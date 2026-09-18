import { NextRequest, NextResponse } from 'next/server';

const BACKEND = process.env.AUTHSTAR_BASE_URL || 'http://localhost:3000';

/**
 * GET /api/agent/history?type=task&id=<taskId>&cursor=<cursor>
 * GET /api/agent/history?type=agent&id=<agentId>&cursor=<cursor>
 *
 * Fetches cursor-paginated audit chain from the AuthStar backend.
 * type=task  → GET /api/v1/audit/task/:id
 * type=agent → GET /api/v1/audit/agent/:id
 */
export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const type = searchParams.get('type');   // 'task' | 'agent'
  const id = searchParams.get('id');
  const cursor = searchParams.get('cursor');

  if (!type || !id) {
    return NextResponse.json({ error: 'type and id query params are required' }, { status: 400 });
  }
  if (type !== 'task' && type !== 'agent') {
    return NextResponse.json({ error: "type must be 'task' or 'agent'" }, { status: 400 });
  }

  const authHeader = req.headers.get('Authorization') || '';
  const path = type === 'task'
    ? `/api/v1/audit/task/${encodeURIComponent(id)}`
    : `/api/v1/audit/agent/${encodeURIComponent(id)}`;

  const url = new URL(`${BACKEND}${path}`);
  if (cursor) url.searchParams.set('cursor', cursor);

  const upstream = await fetch(url.toString(), {
    headers: { Authorization: authHeader },
  });

  const data = await upstream.json().catch(() => ({}));
  return NextResponse.json(data, { status: upstream.status });
}
