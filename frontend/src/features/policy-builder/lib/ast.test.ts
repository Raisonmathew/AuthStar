/**
 * ast.test.ts — Unit tests for formToAst and astToForm
 */

import { describe, it, expect } from 'vitest';
import { formToAst, astToForm, isValidResourcePattern, type PolicyFormState } from './ast';

describe('ast.ts', () => {
  it('validates resource pattern properly', () => {
    expect(isValidResourcePattern('*')).toBe(true);
    expect(isValidResourcePattern('inbox:*')).toBe(true);
    expect(isValidResourcePattern('user/[0-9]+')).toBe(true);
    expect(isValidResourcePattern('(')).toBe(false);
  });

  it('transforms Single Tool template form to AST', () => {
    const form: PolicyFormState = {
      agent_id: 'agent_123',
      policy_name: 'Single Tool Policy',
      model_id: 'claude-3-5-sonnet',
      max_delegation_depth: 3,
      require_human_delegation: false,
      enable_risk_rule: false,
      risk_threshold: 70,
      tools: [{ tool_name: 'send_email', resource_pattern: 'inbox:*' }],
    };

    const ast = formToAst(form);
    expect(ast.version).toBe('EIAA-AST-1.0');
    expect(ast.sequence).toHaveLength(3);
    expect(ast.sequence[0]).toEqual({
      verify_agent_identity: { model_id: 'claude-3-5-sonnet' },
    });
    expect(ast.sequence[1]).toEqual({
      authorize_tool_call: {
        tool_name: 'send_email',
        resource_pattern: 'inbox:*',
        require_user_confirmation: false,
        arg_constraints: [],
      },
    });
    expect(ast.sequence[2]).toEqual({ allow: true });
  });

  it('transforms delegation requirement and risk rules into correct sequence', () => {
    const form: PolicyFormState = {
      agent_id: 'agent_456',
      policy_name: 'Guarded Multi Tool',
      model_id: 'gpt-4o',
      max_delegation_depth: 2,
      require_human_delegation: true,
      enable_risk_rule: true,
      risk_threshold: 80,
      tools: [
        {
          tool_name: 'execute_sql',
          resource_pattern: '*',
          arg_constraints: [{ key: 'db', value: 'analytics' }],
          require_user_confirmation: true,
        },
      ],
    };

    const ast = formToAst(form);
    expect(ast.sequence[0]).toEqual({
      verify_agent_identity: { model_id: 'gpt-4o' },
    });
    expect(ast.sequence[1]).toEqual({
      check_delegation_chain: { max_depth: 2, require_human_origin: true },
    });
    expect(ast.sequence[2]).toEqual({
      evaluate_risk: { profile: 'agent_default' },
    });
    expect(ast.sequence[3].if.condition.risk_score.value).toBe(80);
    expect(ast.sequence[3].if.then).toEqual([{ deny: true }]);
    expect(ast.sequence[3].if.else[0].authorize_tool_call.tool_name).toBe('execute_sql');
    expect(ast.sequence[3].if.else[0].authorize_tool_call.arg_constraints).toEqual([
      { key: 'db', value: 'analytics' },
    ]);
  });

  it('round-trips AST to FormState with astToForm', () => {
    const form: PolicyFormState = {
      agent_id: 'agent_789',
      policy_name: '',
      model_id: 'claude-3-haiku',
      max_delegation_depth: 4,
      require_human_delegation: true,
      enable_risk_rule: true,
      risk_threshold: 65,
      tools: [{ tool_name: 'read_file', resource_pattern: '*', arg_constraints: [], require_user_confirmation: false }],
    };

    const ast = formToAst(form);
    const recovered = astToForm(ast, 'agent_789');

    expect(recovered.agent_id).toBe('agent_789');
    expect(recovered.model_id).toBe('claude-3-haiku');
    expect(recovered.require_human_delegation).toBe(true);
    expect(recovered.max_delegation_depth).toBe(4);
    expect(recovered.enable_risk_rule).toBe(true);
    expect(recovered.risk_threshold).toBe(65);
    expect(recovered.tools[0].tool_name).toBe('read_file');
  });

  it('handles multi-tool forms with argument constraints and custom glob patterns', () => {
    const form: PolicyFormState = {
      agent_id: 'agent_multi',
      policy_name: 'Multi Tool Support',
      model_id: 'gpt-4o',
      max_delegation_depth: 3,
      require_human_delegation: false,
      enable_risk_rule: false,
      risk_threshold: 50,
      tools: [
        {
          tool_name: 'read_inbox',
          resource_pattern: 'inbox/*',
          arg_constraints: [{ key: 'folder', value: 'primary' }],
          require_user_confirmation: false,
        },
        {
          tool_name: 'send_email',
          resource_pattern: 'inbox/sent',
          arg_constraints: [{ key: 'recipient_domain', value: '@authstar.dev' }],
          require_user_confirmation: true,
        },
      ],
    };

    const ast = formToAst(form);
    expect(ast.version).toBe('EIAA-AST-1.0');
    // verify_agent_identity + 2 authorize_tool_call + allow
    expect(ast.sequence).toHaveLength(4);
    expect(ast.sequence[1].authorize_tool_call.tool_name).toBe('read_inbox');
    expect(ast.sequence[1].authorize_tool_call.arg_constraints).toEqual([{ key: 'folder', value: 'primary' }]);
    expect(ast.sequence[2].authorize_tool_call.tool_name).toBe('send_email');
    expect(ast.sequence[2].authorize_tool_call.require_user_confirmation).toBe(true);

    const recovered = astToForm(ast, 'agent_multi');
    expect(recovered.tools).toHaveLength(2);
    expect(recovered.tools[0].tool_name).toBe('read_inbox');
    expect(recovered.tools[0].arg_constraints).toEqual([{ key: 'folder', value: 'primary' }]);
    expect(recovered.tools[1].tool_name).toBe('send_email');
    expect(recovered.tools[1].require_user_confirmation).toBe(true);
  });

  it('handles empty or blank starting template', () => {
    const form: PolicyFormState = {
      agent_id: 'agent_blank',
      policy_name: '',
      model_id: '',
      max_delegation_depth: 3,
      require_human_delegation: false,
      enable_risk_rule: false,
      risk_threshold: 70,
      tools: [{ tool_name: '', resource_pattern: '*' }],
    };

    const ast = formToAst(form);
    expect(ast.version).toBe('EIAA-AST-1.0');
    expect(ast.sequence).toHaveLength(2);
    expect(ast.sequence[0]).toEqual({ verify_agent_identity: { model_id: 'default-agent-model' } });
    expect(ast.sequence[1]).toEqual({ allow: true });
  });
});
