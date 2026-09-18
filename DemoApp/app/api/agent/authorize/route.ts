import { NextRequest, NextResponse } from 'next/server';

const BACKEND = process.env.AUTHSTAR_BASE_URL || 'http://localhost:3000';

/**
 * POST /api/agent/authorize
 *
 * Body: { agentId, toolName, taskId, args? }
 * Forwards the request to the AuthStar backend as the agent bearer token.
 * The Authorization header from the incoming request is forwarded verbatim
 * so the backend can validate the agent JWT.
 *
 * Returns the AgentDecision from the backend.
 */
export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);
  if (!body?.agentId || !body?.toolName) {
    return NextResponse.json({ error: 'agentId and toolName are required' }, { status: 400 });
  }

  const authHeader = req.headers.get('Authorization') || '';

  const upstream = await fetch(
    `${BACKEND}/api/v1/agents/${encodeURIComponent(body.agentId)}/authorize`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: authHeader,
      },
      body: JSON.stringify({
        tool_name: body.toolName,
        task_id: body.taskId,
        tool_args_hash: body.argsHash,
      }),
    },
  );

  const data = await upstream.json().catch(() => ({}));
  return NextResponse.json(data, { status: upstream.status });
}
