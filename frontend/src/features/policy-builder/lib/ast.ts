/**
 * ast.ts — Pure functions for transforming form state into EIAA AST and vice versa.
 *
 * Implements US-02 requirements:
 *  - formToAst: FormState -> Program (EIAA-AST-1.0)
 *  - astToForm: Program -> FormState
 *  - Step sequence guarantees:
 *      1. VerifyAgentIdentity (model_id)
 *      2. CheckDelegationChain (if enabled)
 *      3. EvaluateRisk (if risk threshold enabled)
 *      4. Conditional on RiskScore (if enabled)
 *      5. AuthorizeToolCall + CheckToolPermission per tool row
 *      6. Final Allow(true) / Deny(true)
 */

export interface ToolRow {
  tool_name: string;
  resource_pattern?: string;
  arg_constraints?: Array<{ key: string; value: string }>;
  require_user_confirmation?: boolean;
}

export interface PolicyFormState {
  agent_id: string;
  policy_name: string;
  model_id: string;
  max_delegation_depth: number;
  require_human_delegation: boolean;
  enable_risk_rule: boolean;
  risk_threshold: number; // 0-100
  tools: ToolRow[];
}

export interface AstStep {
  [key: string]: any;
}

export interface AstProgram {
  version: string;
  sequence: AstStep[];
}

/**
 * Validates whether a resource pattern is a valid glob/regex
 */
export function isValidResourcePattern(pattern: string): boolean {
  if (!pattern || pattern === '*') return true;
  try {
    const regexStr = pattern.replace(/\*/g, '.*');
    new RegExp(regexStr);
    return true;
  } catch {
    return false;
  }
}

/**
 * Converts form state into an EIAA-AST-1.0 Program AST.
 */
export function formToAst(form: PolicyFormState): AstProgram {
  const sequence: AstStep[] = [];

  // Step 1: VerifyAgentIdentity
  sequence.push({
    verify_agent_identity: {
      model_id: form.model_id || 'default-agent-model',
    },
  });

  // Step 2: CheckDelegationChain (inserted after VerifyAgentIdentity, before AuthorizeToolCall)
  if (form.require_human_delegation) {
    sequence.push({
      check_delegation_chain: {
        max_depth: form.max_delegation_depth || 3,
        require_human_origin: true,
      },
    });
  }

  // Build the tool authorization sequence
  const toolSteps: AstStep[] = [];

  for (const tool of form.tools) {
    if (!tool.tool_name.trim()) continue;

    let resPattern: string | undefined = undefined;
    if (tool.resource_pattern && tool.resource_pattern.trim() !== '') {
      resPattern = tool.resource_pattern.trim() === '*' ? '.*' : tool.resource_pattern.trim();
    }

    toolSteps.push({
      authorize_tool_call: {
        tool_name: tool.tool_name.trim(),
        resource_pattern: resPattern,
        require_user_confirmation: !!tool.require_user_confirmation,
        arg_constraints: (tool.arg_constraints || []).filter(
          (c) => c.key.trim().length > 0
        ),
      },
    });
  }

  // Terminal tool authorization
  toolSteps.push({ allow: true });

  // Step 3 & 4: Risk Rule (if enabled)
  if (form.enable_risk_rule) {
    sequence.push({
      evaluate_risk: {
        profile: 'agent_default',
      },
    });

    sequence.push({
      if: {
        condition: {
          risk_score: {
            comparator: '>',
            value: Number(form.risk_threshold) || 70,
          },
        },
        then: [{ deny: true }],
        else: toolSteps,
      },
    });
  } else {
    // If no risk rule, toolSteps execute directly
    sequence.push(...toolSteps);
  }

  return {
    version: 'EIAA-AST-1.0',
    sequence,
  };
}

/**
 * Reverses an EIAA-AST-1.0 Program AST into PolicyFormState.
 */
export function astToForm(ast: AstProgram, defaultAgentId = ''): PolicyFormState {
  const form: PolicyFormState = {
    agent_id: defaultAgentId,
    policy_name: '',
    model_id: '',
    max_delegation_depth: 3,
    require_human_delegation: false,
    enable_risk_rule: false,
    risk_threshold: 70,
    tools: [],
  };

  if (!ast || !Array.isArray(ast.sequence)) {
    return form;
  }

  const findTools = (steps: AstStep[]) => {
    for (const step of steps) {
      if (step.authorize_tool_call) {
        const atc = step.authorize_tool_call;
        form.tools.push({
          tool_name: atc.tool_name || '',
          resource_pattern: atc.resource_pattern === '.*' ? '*' : atc.resource_pattern || '',
          arg_constraints: Array.isArray(atc.arg_constraints) ? atc.arg_constraints : [],
          require_user_confirmation: !!atc.require_user_confirmation,
        });
      }
    }
  };

  for (const step of ast.sequence) {
    if (step.verify_agent_identity) {
      form.model_id = step.verify_agent_identity.model_id || '';
    } else if (step.check_delegation_chain) {
      form.require_human_delegation = true;
      form.max_delegation_depth = step.check_delegation_chain.max_depth || 3;
    } else if (step.evaluate_risk) {
      form.enable_risk_rule = true;
    } else if (step.if) {
      const cond = step.if.condition;
      if (cond && cond.risk_score) {
        form.enable_risk_rule = true;
        form.risk_threshold = cond.risk_score.value ?? 70;
      }
      if (Array.isArray(step.if.else)) {
        findTools(step.if.else);
      }
    } else if (step.authorize_tool_call) {
      const atc = step.authorize_tool_call;
      form.tools.push({
        tool_name: atc.tool_name || '',
        resource_pattern: atc.resource_pattern === '.*' ? '*' : atc.resource_pattern || '',
        arg_constraints: Array.isArray(atc.arg_constraints) ? atc.arg_constraints : [],
        require_user_confirmation: !!atc.require_user_confirmation,
      });
    }
  }

  if (form.tools.length === 0) {
    form.tools.push({ tool_name: '', resource_pattern: '*' });
  }

  return form;
}
