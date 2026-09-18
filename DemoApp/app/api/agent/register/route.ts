/**
 * POST /api/agent/register — proxy to backend agent registration via @idaas/core.
 * Referenced by test 8.5.
 */
import { NextRequest, NextResponse } from 'next/server';

const BACKEND = process.env.AUTHSTAR_BASE_URL || 'http://localhost:3000';

export async function POST(req: NextRequest) {
  const authHeader = req.headers.get('authorization');
  const orgId = req.headers.get('x-organization-id') ?? '';

  if (!authHeader) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: 'Invalid JSON body' }, { status: 400 });
  }

  const upstream = await fetch(`${BACKEND}/api/v1/agents/register`, {
    method: 'POST',
    headers: {
      Authorization: authHeader,
      'X-Organization-Id': orgId,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });

  const data = await upstream.json().catch(() => ({}));
  return NextResponse.json(data, { status: upstream.status });
}
