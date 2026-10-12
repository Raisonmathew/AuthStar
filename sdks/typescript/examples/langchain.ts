/**
 * LangChain integration — AuthstarAuthzTool
 *
 * Wraps client.authorize() as a LangChain StructuredTool so an agent can
 * request authorization decisions as part of a tool-use loop.
 *
 * Install peer deps:
 *   npm install langchain @langchain/core zod
 *
 * Usage:
 *   const tool = new AuthstarAuthzTool(client);
 *   const agent = await createToolCallingAgent({ llm, tools: [tool], prompt });
 */

import { z } from "zod";
// LangChain peer dep — not bundled with the SDK
// eslint-disable-next-line import/no-extraneous-dependencies
import { StructuredTool } from "@langchain/core/tools";
import { AuthstarClient } from "@authstar/sdk";

const AuthzSchema = z.object({
  action: z
    .string()
    .describe("The action the agent wants to perform (e.g. 'read:documents')"),
  context: z
    .record(z.unknown())
    .optional()
    .describe("Optional key-value context forwarded to the policy engine"),
});

export class AuthstarAuthzTool extends StructuredTool<typeof AuthzSchema> {
  name = "authstar_authorize";
  description =
    "Check whether the current agent is allowed to perform an action. " +
    "Returns allowed=true/false plus a signed decision reference for audit.";
  schema = AuthzSchema;

  private client: AuthstarClient;

  constructor(client: AuthstarClient) {
    super();
    this.client = client;
  }

  protected async _call(input: z.infer<typeof AuthzSchema>): Promise<string> {
    const decision = await this.client.authorize(
      input.action,
      input.context
    );
    return JSON.stringify(decision);
  }
}

// ---------------------------------------------------------------------------
// Example: wire up the tool in a simple agent
// ---------------------------------------------------------------------------
async function main() {
  const client = new AuthstarClient({
    baseUrl: process.env.AUTHSTAR_BASE_URL ?? "http://localhost:8000",
    apiKey: process.env.AUTHSTAR_API_KEY ?? "",
    tenantId: process.env.AUTHSTAR_TENANT_ID,
  });

  const tool = new AuthstarAuthzTool(client);

  // The tool is now ready to be passed to any LangChain agent, e.g.:
  //   createToolCallingAgent({ llm, tools: [tool], prompt })
  console.log("Tool registered:", tool.name);
  console.log("Schema:", JSON.stringify(tool.schema.shape, null, 2));
}

main().catch(console.error);
