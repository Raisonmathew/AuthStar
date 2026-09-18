/**
 * GET /api/agent/health — smoke test that @idaas/agent is importable.
 * Referenced by test 8.7.
 */
import { NextResponse } from 'next/server';

export async function GET() {
  try {
    // Dynamic import to verify the SDK module resolves without throwing
    const { AgentAuthzClient } = await import('@idaas/agent');
    const name = (AgentAuthzClient as { name?: string }).name ?? 'AgentAuthzClient';
    return NextResponse.json({ sdk: '@idaas/agent', client: name, ok: true });
  } catch (err) {
    return NextResponse.json(
      { sdk: '@idaas/agent', ok: false, error: String(err) },
      { status: 500 },
    );
  }
}
