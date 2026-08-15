import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'sonner';
import { agentsApi, AgentPrincipal } from '../../lib/api/agents';
import RegisterAgentModal from './RegisterAgentModal';
import IssueTokenModal from './IssueTokenModal';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function PrincipalSourceBadge({ source }: { source: string }) {
  const styles: Record<string, string> = {
    cimd:           'bg-blue-500/10 text-blue-600 dark:text-blue-400 border border-blue-500/20',
    dcr:            'bg-purple-500/10 text-purple-600 dark:text-purple-400 border border-purple-500/20',
    pre_registered: 'bg-muted text-muted-foreground border border-border',
  };
  const labels: Record<string, string> = {
    cimd:           'CIMD',
    dcr:            'DCR',
    pre_registered: 'Registered',
  };
  const cls = styles[source] ?? 'bg-muted text-muted-foreground border border-border';
  const label = labels[source] ?? source;
  return (
    <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${cls}`}>
      {label}
    </span>
  );
}


function formatRelativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  if (diff < 60_000) return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

function formatTtl(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.round(secs / 60)}m`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h`;
  return `${Math.round(secs / 86400)}d`;
}

// ─── Agent Card ───────────────────────────────────────────────────────────────

function AgentCard({
  agent,
  onSelect,
}: {
  agent: AgentPrincipal;
  onSelect: (a: AgentPrincipal) => void;
}) {
  const tools = agent.allowed_tools ? agent.allowed_tools.split(/\s+/).filter(Boolean) : [];

  return (
    <div
      className="bg-card rounded-2xl border border-border hover:border-primary/40 hover:shadow-lg hover:shadow-primary/10 transition-all duration-300 p-5 flex flex-col gap-4 cursor-pointer group"
      onClick={() => onSelect(agent)}
    >
      {/* Header row */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500 to-indigo-600 flex items-center justify-center flex-shrink-0 shadow-md">
            <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104c-.251.023-.501.05-.75.082m.75-.082a24.301 24.301 0 014.5 0m0 0v5.714c0 .597.237 1.17.659 1.591L19.8 15M14.25 3.104c.251.023.501.05.75.082M19.8 15l-3.55-3.553M5 14.5l3.55-3.553M5 14.5l-2.3.768a1.5 1.5 0 00-.76 2.301l1.086 1.627A1.5 1.5 0 004.275 20h15.45a1.5 1.5 0 001.249-.804l1.086-1.627a1.5 1.5 0 00-.76-2.301L19.8 15" />
            </svg>
          </div>
          <div className="min-w-0">
            <h3 className="font-bold text-foreground text-sm font-heading truncate group-hover:text-primary transition-colors">
              {agent.name}
            </h3>
            <p className="text-xs font-mono text-muted-foreground truncate">{agent.agent_id}</p>
          </div>
        </div>
        <div className="flex flex-col items-end gap-1.5 flex-shrink-0">
          <span
            className={`px-2.5 py-1 rounded-full text-[11px] font-semibold ${
              agent.active
                ? 'bg-emerald-500/10 text-emerald-500 border border-emerald-500/20'
                : 'bg-destructive/10 text-destructive border border-destructive/20'
            }`}
          >
            {agent.active ? '● Active' : '✕ Inactive'}
          </span>
          <PrincipalSourceBadge source={agent.principal_source} />
        </div>
      </div>

      {/* Model ID */}
      {agent.model_id && (
        <p className="text-xs text-muted-foreground font-mono truncate">{agent.model_id}</p>
      )}

      {/* Tools */}
      {tools.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {tools.slice(0, 4).map(t => (
            <span key={t} className="px-2 py-0.5 rounded-md bg-primary/10 text-primary text-[11px] font-mono font-medium">
              {t}
            </span>
          ))}
          {tools.length > 4 && (
            <span className="px-2 py-0.5 rounded-md bg-muted text-muted-foreground text-[11px] font-medium">
              +{tools.length - 4} more
            </span>
          )}
        </div>
      )}

      {/* Footer meta */}
      <div className="flex items-center gap-3 text-xs text-muted-foreground pt-1 border-t border-border">
        <span title="Max delegation depth">Depth: {agent.max_delegation_depth}</span>
        <span className="text-border">·</span>
        <span title="Token TTL">TTL: {formatTtl(agent.token_ttl_seconds)}</span>
        <span className="text-border">·</span>
        <span title="Last updated">{formatRelativeTime(agent.updated_at)}</span>
      </div>
    </div>
  );
}

// ─── Slide-over detail panel ──────────────────────────────────────────────────

function AgentDetailPanel({
  agent,
  onEdit,
  onIssueToken,
  onViewAudit,
  onDeactivate,
  onRevoke,
  onClose,
}: {
  agent: AgentPrincipal;
  onEdit: () => void;
  onIssueToken: () => void;
  onViewAudit: () => void;
  onDeactivate: () => void;
  onRevoke: () => void;
  onClose: () => void;
}) {
  const tools = agent.allowed_tools ? agent.allowed_tools.split(/\s+/).filter(Boolean) : [];

  return (
    <div className="fixed inset-0 z-40 flex items-stretch justify-end">
      {/* Overlay */}
      <div className="absolute inset-0 bg-black/40 backdrop-blur-sm" onClick={onClose} />
      {/* Panel */}
      <div className="relative w-full max-w-sm bg-card border-l border-border flex flex-col overflow-y-auto shadow-2xl">
        {/* Header */}
        <div className="flex items-start justify-between px-6 pt-6 pb-4 border-b border-border flex-shrink-0">
          <div>
            <h3 className="font-bold text-foreground font-heading text-base">{agent.name}</h3>
            <div className="flex items-center gap-2 mt-1">
              <code className="text-xs font-mono text-muted-foreground">{agent.agent_id}</code>
              <span
                className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${
                  agent.active
                    ? 'bg-emerald-500/10 text-emerald-500'
                    : 'bg-destructive/10 text-destructive'
                }`}
              >
                {agent.active ? 'Active' : 'Inactive'}
              </span>
              <PrincipalSourceBadge source={agent.principal_source} />
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-xl text-muted-foreground hover:text-foreground hover:bg-accent transition-colors flex-shrink-0"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 px-6 py-5 space-y-5">
          {/* Model */}
          <div>
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">Model ID</p>
            <p className="text-sm font-mono text-foreground">{agent.model_id || '—'}</p>
          </div>

          {/* Tools */}
          <div>
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2">Allowed Tools</p>
            {tools.length > 0 ? (
              <div className="flex flex-wrap gap-1.5">
                {tools.map(t => (
                  <span key={t} className="px-2.5 py-1 rounded-lg bg-primary/10 text-primary text-xs font-mono font-medium">
                    {t}
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">No tools configured</p>
            )}
          </div>

          {/* Config */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">Max Depth</p>
              <p className="text-sm font-semibold text-foreground">{agent.max_delegation_depth}</p>
            </div>
            <div>
              <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">Token TTL</p>
              <p className="text-sm font-semibold text-foreground">{formatTtl(agent.token_ttl_seconds)}</p>
            </div>
          </div>

          {/* CIMD metadata URL — shown for cimd-sourced agents */}
          {agent.cimd_metadata_url && (
            <div>
              <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1">CIMD Metadata URL</p>
              <a
                href={agent.cimd_metadata_url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs font-mono text-blue-600 dark:text-blue-400 hover:underline break-all"
              >
                {agent.cimd_metadata_url}
              </a>
            </div>
          )}

          {/* Timestamps */}
          <div className="grid grid-cols-2 gap-4 text-xs text-muted-foreground">
            <div>
              <p className="font-medium uppercase tracking-wider mb-0.5">Registered</p>
              <p>{new Date(agent.created_at).toLocaleDateString()}</p>
            </div>
            <div>
              <p className="font-medium uppercase tracking-wider mb-0.5">Updated</p>
              <p>{formatRelativeTime(agent.updated_at)}</p>
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="px-6 pb-6 space-y-3 flex-shrink-0">
          <div className="flex gap-2">
            <button
              onClick={onEdit}
              className="flex-1 px-3 py-2.5 bg-accent hover:bg-accent/80 text-foreground rounded-xl transition-colors text-sm font-medium"
            >
              Edit
            </button>
            <button
              onClick={onIssueToken}
              disabled={!agent.active}
              className="flex-1 px-3 py-2.5 bg-primary/10 hover:bg-primary/20 text-primary rounded-xl transition-colors text-sm font-medium border border-primary/20 disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Issue Token
            </button>
            <button
              onClick={onViewAudit}
              className="flex-1 px-3 py-2.5 bg-accent hover:bg-accent/80 text-foreground rounded-xl transition-colors text-sm font-medium"
            >
              Audit
            </button>
          </div>
          <div className="border-t border-border pt-3 flex gap-2">
            {agent.active && (
              <button
                onClick={onDeactivate}
                className="flex-1 px-3 py-2.5 bg-amber-500/10 hover:bg-amber-500/20 text-amber-600 dark:text-amber-400 rounded-xl transition-colors text-sm font-medium border border-amber-500/20"
              >
                Deactivate
              </button>
            )}
            <button
              onClick={onRevoke}
              className="flex-1 px-3 py-2.5 bg-destructive/10 hover:bg-destructive/20 text-destructive rounded-xl transition-colors text-sm font-medium border border-destructive/20"
            >
              Revoke Tokens
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function AgentsPage() {
  const navigate = useNavigate();
  const [agents, setAgents] = useState<AgentPrincipal[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedAgent, setSelectedAgent] = useState<AgentPrincipal | null>(null);
  const [showRegisterModal, setShowRegisterModal] = useState(false);
  const [editingAgent, setEditingAgent] = useState<AgentPrincipal | undefined>(undefined);
  const [showIssueTokenModal, setShowIssueTokenModal] = useState(false);

  const fetchAgents = useCallback(async () => {
    setLoading(true);
    try {
      const res = await agentsApi.list();
      setAgents(res.data);
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message;
      toast.error(msg ?? 'Failed to load agents');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchAgents(); }, [fetchAgents]);

  const handleDeactivate = async (agent: AgentPrincipal) => {
    if (!confirm(`Deactivate "${agent.name}"? No new tokens will be issued for this agent.`)) return;
    try {
      await agentsApi.deactivate(agent.agent_id);
      toast.success(`"${agent.name}" deactivated`);
      setSelectedAgent(null);
      fetchAgents();
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message;
      toast.error(msg ?? 'Failed to deactivate agent');
    }
  };

  const handleRevoke = async (agent: AgentPrincipal) => {
    if (!confirm(`Revoke all active tokens for "${agent.name}"? Any currently running agent tasks will be immediately denied.`)) return;
    try {
      await agentsApi.revoke(agent.agent_id);
      toast.success(`All tokens for "${agent.name}" revoked`);
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message;
      toast.error(msg ?? 'Failed to revoke tokens');
    }
  };

  const handleRegisterSuccess = () => {
    setShowRegisterModal(false);
    setEditingAgent(undefined);
    setSelectedAgent(null);
    fetchAgents();
  };

  return (
    <div className="space-y-6 lg:space-y-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-start gap-4">
        <div>
          <h2 className="text-2xl font-bold text-foreground font-heading">AI Agents</h2>
          <p className="text-muted-foreground mt-1">
            Manage non-human principals (AI models) that call your protected APIs via EIAA capsule authorization.
          </p>
        </div>
        <button
          onClick={() => { setEditingAgent(undefined); setShowRegisterModal(true); }}
          className="inline-flex items-center justify-center gap-2 px-5 py-3 bg-primary text-primary-foreground text-sm font-bold font-heading rounded-xl shadow-lg hover:bg-primary/90 transition-all duration-200 group"
        >
          <svg className="w-5 h-5 group-hover:scale-110 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
          </svg>
          Register Agent
        </button>
      </div>

      {/* Content */}
      {loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
        </div>
      ) : agents.length === 0 ? (
        <div className="bg-card backdrop-blur-sm rounded-2xl border border-border p-12 text-center">
          <div className="w-20 h-20 rounded-3xl bg-muted flex items-center justify-center mx-auto mb-6 shadow-inner ring-1 ring-border">
            <svg className="w-10 h-10 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104c-.251.023-.501.05-.75.082m.75-.082a24.301 24.301 0 014.5 0m0 0v5.714c0 .597.237 1.17.659 1.591L19.8 15M14.25 3.104c.251.023.501.05.75.082M19.8 15l-3.55-3.553M5 14.5l3.55-3.553M5 14.5l-2.3.768a1.5 1.5 0 00-.76 2.301l1.086 1.627A1.5 1.5 0 004.275 20h15.45a1.5 1.5 0 001.249-.804l1.086-1.627a1.5 1.5 0 00-.76-2.301L19.8 15" />
            </svg>
          </div>
          <h3 className="text-xl font-bold text-foreground mb-2 font-heading">No agents registered</h3>
          <p className="text-muted-foreground mb-8 max-w-md mx-auto">
            Register your first AI agent to enable EIAA capsule-based tool-call authorization for Claude, GPT, or any LLM.
          </p>
          <button
            onClick={() => setShowRegisterModal(true)}
            className="inline-flex items-center gap-2 px-6 py-3 bg-primary text-primary-foreground text-sm font-bold font-heading rounded-xl hover:bg-primary/90 transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
            </svg>
            Register First Agent
          </button>
        </div>
      ) : (
        <div className="grid gap-5 md:grid-cols-2 lg:grid-cols-3">
          {agents.map(agent => (
            <AgentCard key={agent.agent_id} agent={agent} onSelect={setSelectedAgent} />
          ))}
        </div>
      )}

      {/* Slide-over panel */}
      {selectedAgent && (
        <AgentDetailPanel
          agent={selectedAgent}
          onEdit={() => {
            setEditingAgent(selectedAgent);
            setShowRegisterModal(true);
          }}
          onIssueToken={() => setShowIssueTokenModal(true)}
          onViewAudit={() => navigate(`/admin/agents/audit?agent=${encodeURIComponent(selectedAgent.agent_id)}`)}
          onDeactivate={() => handleDeactivate(selectedAgent)}
          onRevoke={() => handleRevoke(selectedAgent)}
          onClose={() => setSelectedAgent(null)}
        />
      )}

      {/* Register / Edit modal */}
      {showRegisterModal && (
        <RegisterAgentModal
          agent={editingAgent}
          onClose={() => { setShowRegisterModal(false); setEditingAgent(undefined); }}
          onSuccess={handleRegisterSuccess}
        />
      )}

      {/* Issue Token modal */}
      {showIssueTokenModal && selectedAgent && (
        <IssueTokenModal
          agent={selectedAgent}
          onClose={() => setShowIssueTokenModal(false)}
        />
      )}
    </div>
  );
}
