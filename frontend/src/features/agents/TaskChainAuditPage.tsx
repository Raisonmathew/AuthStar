import React, { useState, useEffect, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import { toast } from 'sonner';
import { agentsApi, AgentPrincipal, ExecutionRow } from '../../lib/api/agents';

// ─── Types ────────────────────────────────────────────────────────────────────

interface TaskGroup {
  taskId: string;
  agentId: string | null;
  agentName: string | null;
  modelId: string | null;
  items: ExecutionRow[];
  firstSeen: string;
  lastSeen: string;
  allowedCount: number;
  deniedCount: number;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function isAllowed(row: ExecutionRow): boolean {
  return !!(row.decision?.allow ?? row.decision?.allowed);
}

function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function groupByTask(items: ExecutionRow[], agentMap: Record<string, AgentPrincipal>): TaskGroup[] {
  const map = new Map<string, TaskGroup>();
  for (const row of items) {
    const key = row.task_id ?? row.id;
    if (!map.has(key)) {
      const principal = row.agent_id ? agentMap[row.agent_id] : undefined;
      map.set(key, {
        taskId: key,
        agentId: row.agent_id,
        agentName: principal?.name ?? null,
        modelId: row.model_id,
        items: [],
        firstSeen: row.created_at,
        lastSeen: row.created_at,
        allowedCount: 0,
        deniedCount: 0,
      });
    }
    const group = map.get(key)!;
    group.items.push(row);
    if (new Date(row.created_at) < new Date(group.firstSeen)) group.firstSeen = row.created_at;
    if (new Date(row.created_at) > new Date(group.lastSeen)) group.lastSeen = row.created_at;
    if (isAllowed(row)) group.allowedCount++; else group.deniedCount++;
  }
  return Array.from(map.values()).sort(
    (a, b) => new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime(),
  );
}

// ─── Attestation Detail ───────────────────────────────────────────────────────

function AttestationDetail({ row, onClose }: { row: ExecutionRow; onClose: () => void }) {
  const allowed = isAllowed(row);
  const copyText = async (text: string) => {
    try { await navigator.clipboard.writeText(text); toast.success('Copied'); }
    catch { toast.error('Copy failed'); }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-card rounded-2xl border border-border shadow-2xl w-full max-w-lg max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between px-6 py-5 border-b border-border">
          <div>
            <h3 className="font-bold text-foreground font-heading">Attestation Detail</h3>
            <p className="text-xs text-muted-foreground font-mono mt-0.5">{row.decision_ref}</p>
          </div>
          <button onClick={onClose} className="p-2 rounded-xl text-muted-foreground hover:text-foreground hover:bg-accent transition-colors">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        <div className="px-6 py-5 space-y-4 text-sm">
          {/* Decision */}
          <div className="flex items-center gap-3">
            <span className={`px-3 py-1.5 rounded-xl text-xs font-bold ${allowed ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' : 'bg-destructive/10 text-destructive'}`}>
              {allowed ? '✓ ALLOWED' : '✗ DENIED'}
            </span>
            {row.decision?.reason && (
              <span className="text-xs text-muted-foreground italic">"{row.decision.reason}"</span>
            )}
          </div>

          {/* Fields */}
          {[
            { label: 'Action', value: row.action },
            { label: 'Tool Name', value: row.tool_name },
            { label: 'Agent ID', value: row.agent_id },
            { label: 'Model ID', value: row.model_id },
            { label: 'Task ID', value: row.task_id },
            { label: 'Delegation Depth', value: String(row.delegation_depth) },
            { label: 'Principal Type', value: row.principal_type },
            { label: 'Attestation Timestamp', value: formatDateTime(row.attestation_timestamp) },
            { label: 'Created At', value: formatDateTime(row.created_at) },
          ].filter(f => f.value).map(f => (
            <div key={f.label}>
              <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-0.5">{f.label}</p>
              <p className="text-sm font-mono text-foreground break-all">{f.value}</p>
            </div>
          ))}

          {/* Capsule hash */}
          <div>
            <div className="flex items-center justify-between mb-0.5">
              <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Capsule Hash</p>
              <button onClick={() => copyText(row.capsule_hash_b64)} className="text-xs text-primary hover:text-primary/80">Copy</button>
            </div>
            <p className="text-xs font-mono text-foreground break-all bg-muted border border-border rounded-lg px-3 py-2">{row.capsule_hash_b64}</p>
          </div>

          {/* Attestation signature */}
          <div>
            <div className="flex items-center justify-between mb-0.5">
              <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Ed25519 Attestation Signature</p>
              <button onClick={() => copyText(row.attestation_signature_b64)} className="text-xs text-primary hover:text-primary/80">Copy</button>
            </div>
            <p className="text-xs font-mono text-foreground break-all bg-muted border border-border rounded-lg px-3 py-2">{row.attestation_signature_b64}</p>
          </div>

          {row.tool_args_hash && (
            <div>
              <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-0.5">Tool Args Hash (SHA-256)</p>
              <p className="text-xs font-mono text-foreground break-all bg-muted border border-border rounded-lg px-3 py-2">{row.tool_args_hash}</p>
            </div>
          )}
        </div>
        <div className="px-6 pb-6">
          <button onClick={onClose} className="w-full px-4 py-2.5 bg-primary hover:bg-primary/90 text-primary-foreground rounded-xl text-sm font-semibold font-heading transition-colors">
            Close
          </button>
        </div>
      </div>
    </div>
  );
}

// ─── Task Group Row ───────────────────────────────────────────────────────────

function TaskGroupRow({
  group,
  onSelectRow,
}: {
  group: TaskGroup;
  onSelectRow: (row: ExecutionRow) => void;
}) {
  const [expanded, setExpanded] = useState(true);

  return (
    <div className="bg-card rounded-xl border border-border overflow-hidden">
      {/* Task header */}
      <button
        className="w-full flex items-center justify-between px-5 py-4 hover:bg-accent/50 transition-colors text-left"
        onClick={() => setExpanded(v => !v)}
      >
        <div className="flex items-center gap-3 min-w-0">
          <svg
            className={`w-4 h-4 text-muted-foreground flex-shrink-0 transition-transform ${expanded ? 'rotate-90' : ''}`}
            fill="none" stroke="currentColor" viewBox="0 0 24 24"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
          </svg>
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-mono font-semibold text-foreground truncate">{group.taskId}</span>
              {group.agentName && (
                <span className="text-xs text-muted-foreground">· {group.agentName}</span>
              )}
              {group.modelId && (
                <span className="text-xs font-mono text-muted-foreground truncate">{group.modelId}</span>
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">{formatDateTime(group.lastSeen)}</p>
          </div>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0 ml-3">
          <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 font-semibold">
            {group.allowedCount} allowed
          </span>
          {group.deniedCount > 0 && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-destructive/10 text-destructive font-semibold">
              {group.deniedCount} denied
            </span>
          )}
          <span className="text-xs text-muted-foreground">{group.items.length} action{group.items.length !== 1 ? 's' : ''}</span>
        </div>
      </button>

      {/* Execution rows */}
      {expanded && (
        <div className="border-t border-border divide-y divide-border">
          {group.items.map((row, i) => {
            const allowed = isAllowed(row);
            return (
              <button
                key={row.id}
                className="w-full flex items-center gap-3 px-5 py-3 hover:bg-accent/40 transition-colors text-left"
                onClick={() => onSelectRow(row)}
              >
                {/* Step number */}
                <span className="w-6 h-6 rounded-full bg-muted border border-border text-xs font-bold text-muted-foreground flex items-center justify-center flex-shrink-0">
                  {i + 1}
                </span>

                {/* Tool name */}
                <span className="w-36 text-xs font-mono font-semibold text-foreground truncate flex-shrink-0">
                  {row.tool_name ?? row.action}
                </span>

                {/* Decision badge */}
                <span className={`flex-shrink-0 text-xs font-bold px-2.5 py-1 rounded-lg ${allowed ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' : 'bg-destructive/10 text-destructive'}`}>
                  {allowed ? '✓ ALLOWED' : '✗ DENIED'}
                </span>

                {/* Denial reason */}
                {!allowed && row.decision?.reason && (
                  <span className="text-xs text-muted-foreground italic truncate flex-1 min-w-0">
                    "{row.decision.reason}"
                  </span>
                )}

                {/* Depth */}
                {row.delegation_depth > 0 && (
                  <span className="text-xs text-muted-foreground ml-auto flex-shrink-0">
                    depth {row.delegation_depth}
                  </span>
                )}

                {/* Timestamp */}
                <span className="text-xs text-muted-foreground flex-shrink-0 ml-auto">
                  {new Date(row.created_at).toLocaleTimeString()}
                </span>

                {/* Arrow */}
                <svg className="w-4 h-4 text-muted-foreground flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                </svg>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function TaskChainAuditPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [agents, setAgents] = useState<AgentPrincipal[]>([]);
  const [agentMap, setAgentMap] = useState<Record<string, AgentPrincipal>>({});
  const [rows, setRows] = useState<ExecutionRow[]>([]);
  const [groups, setGroups] = useState<TaskGroup[]>([]);
  const [loading, setLoading] = useState(false);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [attestationRow, setAttestationRow] = useState<ExecutionRow | null>(null);

  // Filter state
  const [filterAgent, setFilterAgent] = useState(searchParams.get('agent') ?? '');
  const [filterTaskId, setFilterTaskId] = useState('');
  const [filterDecision, setFilterDecision] = useState<'all' | 'allowed' | 'denied'>('all');

  // Load agent list once for display names
  useEffect(() => {
    agentsApi.list().then(res => {
      setAgents(res.data);
      const map: Record<string, AgentPrincipal> = {};
      for (const a of res.data) map[a.agent_id] = a;
      setAgentMap(map);
    }).catch(() => { /* non-fatal */ });
  }, []);

  const rowsRef = React.useRef<ExecutionRow[]>([]);
  const agentMapRef = React.useRef<Record<string, AgentPrincipal>>({});

  // Keep refs in sync with state so the load callback sees the latest values
  // without being re-created on every state change.
  useEffect(() => { rowsRef.current = rows; }, [rows]);
  useEffect(() => { agentMapRef.current = agentMap; }, [agentMap]);

  const load = useCallback(async (cursor?: string) => {
    if (!filterAgent && !filterTaskId) {
      setRows([]);
      setGroups([]);
      setNextCursor(null);
      return;
    }

    if (!cursor) setLoading(true);
    else setLoadingMore(true);

    try {
      let resp;
      if (filterTaskId) {
        resp = await agentsApi.getTaskChain(filterTaskId, cursor);
      } else {
        resp = await agentsApi.getAgentHistory(filterAgent, cursor);
      }
      const newRows = cursor ? [...rowsRef.current, ...resp.data.items] : resp.data.items;
      setRows(newRows);
      setNextCursor(resp.data.next_cursor);
      setGroups(groupByTask(newRows, agentMapRef.current));
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message;
      toast.error(msg ?? 'Failed to load audit records');
    } finally {
      setLoading(false);
      setLoadingMore(false);
    }
  }, [filterAgent, filterTaskId]);

  // Re-load when filters change
  useEffect(() => { load(); }, [load]);

  // Sync agent filter from URL param
  useEffect(() => {
    const a = searchParams.get('agent');
    if (a) setFilterAgent(a);
  }, [searchParams]);

  const handleAgentChange = (val: string) => {
    setFilterAgent(val);
    setFilterTaskId('');
    setRows([]);
    setNextCursor(null);
    if (val) setSearchParams({ agent: val }); else setSearchParams({});
  };

  const handleTaskSearch = () => {
    if (!filterTaskId.trim()) return;
    setFilterAgent('');
    setSearchParams({});
    load();
  };

  const visibleGroups = filterDecision === 'all'
    ? groups
    : groups.filter(g => filterDecision === 'denied' ? g.deniedCount > 0 : g.allowedCount > 0);

  return (
    <div className="space-y-6 lg:space-y-8">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-foreground font-heading">Agent Task Chain Audit</h2>
        <p className="text-muted-foreground mt-1">
          Browse AI agent tool-call decisions and causal chains with EIAA attestation verification.
        </p>
      </div>

      {/* Filter bar */}
      <div className="bg-card rounded-xl border border-border p-4 flex flex-col sm:flex-row gap-3">
        {/* Agent filter */}
        <select
          value={filterAgent}
          onChange={e => handleAgentChange(e.target.value)}
          className="flex-1 px-3 py-2.5 border border-border rounded-xl bg-muted text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        >
          <option value="">All Agents</option>
          {agents.map(a => (
            <option key={a.agent_id} value={a.agent_id}>{a.name} ({a.agent_id})</option>
          ))}
        </select>

        {/* Task ID search */}
        <div className="flex gap-2 flex-1">
          <input
            type="text"
            value={filterTaskId}
            onChange={e => setFilterTaskId(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleTaskSearch()}
            placeholder="Search by Task ID…"
            className="flex-1 px-3 py-2.5 border border-border rounded-xl bg-muted text-foreground text-sm placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring font-mono"
          />
          <button
            onClick={handleTaskSearch}
            disabled={!filterTaskId.trim()}
            className="px-4 py-2.5 bg-primary text-primary-foreground rounded-xl text-sm font-semibold disabled:opacity-40 hover:bg-primary/90 transition-colors"
          >
            Search
          </button>
        </div>

        {/* Decision filter */}
        <select
          value={filterDecision}
          onChange={e => setFilterDecision(e.target.value as 'all' | 'allowed' | 'denied')}
          className="px-3 py-2.5 border border-border rounded-xl bg-muted text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring"
        >
          <option value="all">All Decisions</option>
          <option value="allowed">Allowed Only</option>
          <option value="denied">Denied Only</option>
        </select>
      </div>

      {/* Results */}
      {!filterAgent && !filterTaskId ? (
        <div className="bg-card rounded-2xl border border-border p-12 text-center">
          <div className="w-16 h-16 rounded-2xl bg-muted flex items-center justify-center mx-auto mb-4 ring-1 ring-border">
            <svg className="w-8 h-8 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
            </svg>
          </div>
          <h3 className="text-lg font-bold text-foreground font-heading mb-2">Select an agent or search by Task ID</h3>
          <p className="text-muted-foreground text-sm">Choose an agent from the dropdown to browse all its task chains, or enter a specific Task ID to inspect a single run.</p>
        </div>
      ) : loading ? (
        <div className="flex items-center justify-center h-48">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
        </div>
      ) : visibleGroups.length === 0 ? (
        <div className="bg-card rounded-2xl border border-border p-10 text-center">
          <p className="text-muted-foreground text-sm">No task chain records found for the selected filters.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {visibleGroups.map(group => (
            <TaskGroupRow key={group.taskId} group={group} onSelectRow={setAttestationRow} />
          ))}

          {nextCursor && (
            <div className="flex justify-center pt-2">
              <button
                onClick={() => load(nextCursor)}
                disabled={loadingMore}
                className="px-6 py-2.5 bg-accent hover:bg-accent/80 text-foreground rounded-xl text-sm font-medium transition-colors disabled:opacity-50"
              >
                {loadingMore ? 'Loading…' : 'Load more'}
              </button>
            </div>
          )}
        </div>
      )}

      {/* Attestation detail modal */}
      {attestationRow && (
        <AttestationDetail
          row={attestationRow}
          onClose={() => setAttestationRow(null)}
        />
      )}
    </div>
  );
}
