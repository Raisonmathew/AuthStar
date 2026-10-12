/**
 * OpenAI Agents SDK integration
 *
 * Defines an `authstar_authorize` function tool that the OpenAI Agents SDK
 * can call during a run to request AuthStar authorization decisions.
 *
 * Install peer deps:
 *   npm install openai @openai/agents
 *
 * Usage:
 *   import { authorizeTool, handleAuthorizeCall } from './openai-agents.js';
 *   const agent = new Agent({ tools: [authorizeTool], ... });
 */

import OpenAI from "openai";
import { AuthstarClient } from "@authstar/sdk";

// ---------------------------------------------------------------------------
// Tool definition (JSON Schema) for the OpenAI Agents / Assistants API
// ---------------------------------------------------------------------------
export const authorizeTool: OpenAI.Responses.Tool = {
  type: "function",
  name: "authstar_authorize",
  description:
    "Request an authorization decision from AuthStar. " +
    "Call this before performing any sensitive action. " +
    "Returns allowed=true/false plus a signed decision_ref for audit.",
  parameters: {
    type: "object",
    properties: {
      action: {
        type: "string",
        description:
          "The action the agent wants to perform, e.g. 'read:pii' or 'execute:code'.",
      },
      context: {
        type: "object",
        description:
          "Optional key-value context forwarded to the policy engine (resource IDs, environment, etc.).",
        additionalProperties: true,
      },
    },
    required: ["action"],
  },
};

// ---------------------------------------------------------------------------
// Handler — call this when the model emits a tool call for authstar_authorize
// ---------------------------------------------------------------------------
export async function handleAuthorizeCall(
  client: AuthstarClient,
  toolCallArguments: string
): Promise<string> {
  const args = JSON.parse(toolCallArguments) as {
    action: string;
    context?: Record<string, unknown>;
  };

  const decision = await client.authorize(args.action, args.context);
  return JSON.stringify(decision);
}

// ---------------------------------------------------------------------------
// Example: minimal Responses API loop
// ---------------------------------------------------------------------------
async function main() {
  const authstarClient = new AuthstarClient({
    baseUrl: process.env.AUTHSTAR_BASE_URL ?? "http://localhost:8000",
    apiKey: process.env.AUTHSTAR_API_KEY ?? "",
    tenantId: process.env.AUTHSTAR_TENANT_ID,
  });

  const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

  // First turn — ask the model to do something that requires authorization
  let response = await openai.responses.create({
    model: "gpt-4o",
    tools: [authorizeTool],
    input: "Please read the PII records for user 42.",
  });

  // Agentic loop — resolve tool calls until the model stops
  while (response.status === "requires_action") {
    const toolOutputs: OpenAI.Responses.FunctionToolResult[] = [];

    for (const toolCall of response.output) {
      if (
        toolCall.type === "function_call" &&
        toolCall.name === "authstar_authorize"
      ) {
        const output = await handleAuthorizeCall(
          authstarClient,
          toolCall.arguments
        );
        toolOutputs.push({
          type: "function_call_output",
          call_id: toolCall.call_id,
          output,
        });
      }
    }

    response = await openai.responses.create({
      model: "gpt-4o",
      tools: [authorizeTool],
      previous_response_id: response.id,
      input: toolOutputs,
    });
  }

  console.log("Final response:", response.output_text);
}

main().catch(console.error);
