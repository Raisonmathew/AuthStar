import { NextRequest, NextResponse } from 'next/server';

const BACKEND = process.env.AUTHSTAR_BASE_URL || 'http://localhost:3000';

/**
 * POST /api/agent/record
 *
 * Body: { agentId, toolName, taskId, allowed, toolArgsHash?, denialReason? }
 * Records a tool execution in the AuthStar audit trail.
 */
export async function POST(req: NextRequest) {
  const body = await req.json().catch(() => null);
  if (!body?.agentId || !body?.toolName || !body?.taskId) {
    return NextResponse.json(
      { error: 'agentId, toolName, and taskId are required' },
      { status: 400 },
    );
  }

  const authHeader = req.headers.get('Authorization') || '';

  const upstream = await fetch(
    `${BACKEND}/api/v1/agents/${encodeURIComponent(body.agentId)}/executions`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: authHeader,
      },
      body: JSON.stringify({
        tool_name: body.toolName,
        task_id: body.taskId,
        allowed: body.allowed ?? true,
        tool_args_hash: body.toolArgsHash,
        denial_reason: body.denialReason,
      }),
    },
  );

  const data = await upstream.json().catch(() => ({}));
  return NextResponse.json(data, { status: upstream.status });
}
