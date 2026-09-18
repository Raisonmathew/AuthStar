'use client';

import { useState } from 'react';
import { AgentAuthzClient } from '@idaas/agent';

interface Props {
  jwt: string;
}

/**
 * AgentPanel — demonstrates the @idaas/agent TypeScript SDK running inside
 * the browser (Node.js crypto API is polyfilled by Next.js for browser use
 * but we use a local SHA-256 implementation for the browser path).
 *
 * Playwright tests exercise:
 *   - Registering an agent
 *   - Issuing an agent token
 *   - Authorizing a tool call (authorize button)
 *   - Recording an execution
 *   - Fetching the task chain
 */
export default function AgentPanel({ jwt }: Props) {
  const apiBase = process.env.NEXT_PUBLIC_AUTHSTAR_API_URL!;

  const [agentName, setAgentName] = useState('Demo LangChain Agent');
  const [agentId, setAgentId] = useState('');
  const [taskId] = useState(`task_demo_${Date.now()}`);
  const [toolName, setToolName] = useState('web_search');
  const [decision, setDecision] = useState<{ allowed: boolean; decision_ref: string } | null>(null);
  const [execution, setExecution] = useState<{ execution_id: string; task_id: string } | null>(null);
  const [chainItems, setChainItems] = useState<unknown[]>([]);
  const [status, setStatus] = useState('');
  const [loading, setLoading] = useState(false);

  // ── Register agent ─────────────────────────────────────────────────────────
  async function handleRegister() {
    setLoading(true);
    setStatus('Registering agent…');
    try {
      const csrfRes = await fetch(`${apiBase}/api/csrf-token`, { credentials: 'include' });
      const { csrf_token } = await csrfRes.json();

      const res = await fetch(`${apiBase}/api/v1/agents/register`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
          'X-CSRF-Token': csrf_token,
          Origin: window.location.origin,
        },
        body: JSON.stringify({
          name: agentName,
          model_id: 'claude-3-5-sonnet-20241022',
          allowed_tools: 'web_search send_email',
          max_delegation_depth: 2,
          token_ttl_seconds: 3600,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.message || `Register failed: ${res.status}`);
      setAgentId(data.agent_id);
      setStatus(`✓ Registered: ${data.agent_id}`);
    } catch (e) {
      setStatus(`✗ ${e instanceof Error ? e.message : 'Error'}`);
    } finally {
      setLoading(false);
    }
  }

  // ── Issue agent token and authorize tool call via @idaas/agent SDK ────────
  async function handleAuthorize() {
    if (!agentId) { setStatus('Register an agent first'); return; }
    setLoading(true);
    setStatus('Issuing token and authorizing…');
    try {
      // Issue an agent token (admin JWT used because this demo runs as admin)
      const csrfRes = await fetch(`${apiBase}/api/csrf-token`, { credentials: 'include' });
      const { csrf_token } = await csrfRes.json();

      const tokenRes = await fetch(`${apiBase}/api/v1/agents/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
          'X-CSRF-Token': csrf_token,
          Origin: window.location.origin,
        },
        body: JSON.stringify({ agent_id: agentId, task_id: taskId }),
      });
      if (!tokenRes.ok) throw new Error(`Token issuance failed: ${tokenRes.status}`);
      const { token: agentToken } = await tokenRes.json();

      // Use @idaas/agent SDK to authorize the tool call
      const client = new AgentAuthzClient({
        baseUrl: apiBase,
        tenantId: 'system',
        apiKey: '',
        agentId,
        taskId,
        agentToken,
      });

      const d = await client.authorizeToolCall(toolName, { q: 'test query' });
      setDecision(d);
      setStatus(d.allowed ? `✓ Allowed (${d.decision_ref})` : `✗ Denied: ${d.reason}`);
    } catch (e) {
      setStatus(`✗ ${e instanceof Error ? e.message : 'Error'}`);
    } finally {
      setLoading(false);
    }
  }

  // ── Record execution ───────────────────────────────────────────────────────
  async function handleRecord() {
    if (!agentId || !decision) { setStatus('Authorize a tool call first'); return; }
    setLoading(true);
    setStatus('Recording execution…');
    try {
      // Issue a fresh agent token for the record call
      const csrfRes = await fetch(`${apiBase}/api/csrf-token`, { credentials: 'include' });
      const { csrf_token } = await csrfRes.json();
      const tokenRes = await fetch(`${apiBase}/api/v1/agents/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
          'X-CSRF-Token': csrf_token,
          Origin: window.location.origin,
        },
        body: JSON.stringify({ agent_id: agentId, task_id: taskId }),
      });
      const { token: agentToken } = await tokenRes.json();

      const client = new AgentAuthzClient({
        baseUrl: apiBase, tenantId: 'system', apiKey: '',
        agentId, taskId, agentToken,
      });
      const exec = await client.recordExecution(toolName, {
        allowed: decision.allowed,
        decisionRef: decision.decision_ref,
      });
      setExecution({ execution_id: exec.execution_id, task_id: exec.task_id });
      setStatus(`✓ Recorded execution ${exec.execution_id}`);
    } catch (e) {
      setStatus(`✗ ${e instanceof Error ? e.message : 'Error'}`);
    } finally {
      setLoading(false);
    }
  }

  // ── Fetch task chain ───────────────────────────────────────────────────────
  async function handleFetchChain() {
    if (!agentId) { setStatus('Register an agent first'); return; }
    setLoading(true);
    setStatus('Fetching audit chain…');
    try {
      const csrfRes = await fetch(`${apiBase}/api/csrf-token`, { credentials: 'include' });
      const { csrf_token } = await csrfRes.json();
      const tokenRes = await fetch(`${apiBase}/api/v1/agents/token`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${jwt}`,
          'X-CSRF-Token': csrf_token,
          Origin: window.location.origin,
        },
        body: JSON.stringify({ agent_id: agentId, task_id: taskId }),
      });
      const { token: agentToken } = await tokenRes.json();

      const client = new AgentAuthzClient({
        baseUrl: apiBase, tenantId: 'system', apiKey: '',
        agentId, taskId, agentToken,
      });
      const chain = await client.getTaskChain(taskId);
      setChainItems(chain.items);
      setStatus(`✓ ${chain.items.length} audit record(s) for task`);
    } catch (e) {
      setStatus(`✗ ${e instanceof Error ? e.message : 'Error'}`);
    } finally {
      setLoading(false);
    }
  }

  const btn = (label: string, onClick: () => void, testId: string) => (
    <button
      data-testid={testId}
      onClick={onClick}
      disabled={loading}
      style={{
        padding: '8px 16px', border: '1px solid #d1d5db', borderRadius: 6,
        background: '#fff', fontSize: 13, fontWeight: 500, cursor: loading ? 'not-allowed' : 'pointer',
        opacity: loading ? 0.6 : 1,
      }}
    >
      {label}
    </button>
  );

  return (
    <div
      data-testid="agent-panel"
      style={{ border: '1px solid #e5e7eb', borderRadius: 8, padding: 20, background: '#fafbfc' }}
    >
      {/* Agent name input */}
      <div style={{ marginBottom: 12 }}>
        <label style={{ fontSize: 13, fontWeight: 500, display: 'block', marginBottom: 4 }}>
          Agent name
        </label>
        <input
          data-testid="input-agent-name"
          value={agentName}
          onChange={(e) => setAgentName(e.target.value)}
          style={{ width: '100%', padding: '6px 10px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 13 }}
        />
      </div>

      {/* Tool name input */}
      <div style={{ marginBottom: 16 }}>
        <label style={{ fontSize: 13, fontWeight: 500, display: 'block', marginBottom: 4 }}>
          Tool name
        </label>
        <input
          data-testid="input-tool-name"
          value={toolName}
          onChange={(e) => setToolName(e.target.value)}
          style={{ width: '100%', padding: '6px 10px', border: '1px solid #d1d5db', borderRadius: 6, fontSize: 13 }}
        />
      </div>

      {/* Action buttons */}
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 16 }}>
        {btn('1. Register Agent', handleRegister, 'btn-register-agent')}
        {btn('2. Authorize Tool Call', handleAuthorize, 'btn-authorize')}
        {btn('3. Record Execution', handleRecord, 'btn-record')}
        {btn('4. Fetch Task Chain', handleFetchChain, 'btn-fetch-chain')}
      </div>

      {/* Status output */}
      {status && (
        <p data-testid="agent-status" style={{ fontSize: 13, color: '#57606a', marginBottom: 12 }}>
          {status}
        </p>
      )}

      {/* Agent ID display */}
      {agentId && (
        <p data-testid="agent-id-display" style={{ fontSize: 12, color: '#57606a' }}>
          Agent ID: <code>{agentId}</code>
        </p>
      )}

      {/* Decision display */}
      {decision && (
        <div data-testid="decision-result" style={{ marginTop: 12, fontSize: 12, background: decision.allowed ? '#dcfce7' : '#fee2e2', padding: '8px 12px', borderRadius: 6 }}>
          <strong>Decision:</strong> {decision.allowed ? 'ALLOWED' : 'DENIED'} · ref: {decision.decision_ref}
        </div>
      )}

      {/* Execution display */}
      {execution && (
        <div data-testid="execution-result" style={{ marginTop: 8, fontSize: 12, background: '#eff6ff', padding: '8px 12px', borderRadius: 6 }}>
          <strong>Execution recorded:</strong> {execution.execution_id}
        </div>
      )}

      {/* Audit chain */}
      {chainItems.length > 0 && (
        <div data-testid="chain-items" style={{ marginTop: 8, fontSize: 12 }}>
          <strong>Audit chain ({chainItems.length} records):</strong>
          <ul style={{ paddingLeft: 16, marginTop: 4 }}>
            {chainItems.slice(0, 5).map((item: unknown, i) => {
              const row = item as Record<string, unknown>;
              return (
                <li key={i}>
                  {String(row.tool_name ?? row.action ?? 'unknown')} ·{' '}
                  {String(row.created_at ?? '').substring(0, 19)}
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
}
