import { useState } from 'react';
import { toast } from 'sonner';
import { agentsApi, AgentPrincipal, IssueTokenResponse } from '../../lib/api/agents';

interface Props {
  agent: AgentPrincipal;
  onClose: () => void;
}

const PYTHON_SNIPPET = (agentId: string, taskId: string, token: string) => `from idaas.agent import AgentAuthz

authz = AgentAuthz(
    tenant_id="${sessionStorage.getItem('active_org_id') ?? 'your_tenant_id'}",
    agent_id="${agentId}",
    task_id="${taskId}",
    token="${token}",
)
decision = await authz.authorize_tool_call("web_search", args)`;

const TS_SNIPPET = (agentId: string, taskId: string, token: string) => `import { AgentClient } from '@authstar/agent';

const agent = new AgentClient({
  agentId: '${agentId}',
  taskId:  '${taskId}',
  token:   '${token}',
});
const granted = await agent.authorizeToolCall('web_search');`;

export default function IssueTokenModal({ agent, onClose }: Props) {
  const [taskId, setTaskId] = useState('');
  const [toolOverrides, setToolOverrides] = useState<string[]>([]);
  const [delegationChain, setDelegationChain] = useState('');

  const [taskIdError, setTaskIdError] = useState('');
  const [issuing, setIssuing] = useState(false);
  const [issued, setIssued] = useState<IssueTokenResponse | null>(null);
  const [snippet, setSnippet] = useState<'python' | 'ts'>('python');
  const [copied, setCopied] = useState(false);

  const registeredTools = agent.allowed_tools
    ? agent.allowed_tools.split(/\s+/).filter(Boolean)
    : [];

  const handleToggleTool = (tool: string) => {
    setToolOverrides(prev =>
      prev.includes(tool) ? prev.filter(t => t !== tool) : [...prev, tool],
    );
  };

  const handleIssue = async () => {
    const tid = taskId.trim();
    if (!tid) { setTaskIdError('Task ID is required'); return; }
    setTaskIdError('');

    setIssuing(true);
    try {
      const chain = delegationChain.trim()
        ? delegationChain.trim().split(/\s+/)
        : [];
      const res = await agentsApi.issueToken({
        agent_id: agent.agent_id,
        task_id: tid,
        delegation_chain: chain,
        allowed_tools: toolOverrides.length > 0 ? toolOverrides : undefined,
      });
      setIssued(res.data);
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message;
      toast.error(msg ?? 'Failed to issue agent token');
    } finally {
      setIssuing(false);
    }
  };

  const copyToClipboard = async (text: string, label: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      toast.success(`${label} copied to clipboard`);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error('Copy failed — please copy manually');
    }
  };

  const currentSnippet = issued
    ? snippet === 'python'
      ? PYTHON_SNIPPET(issued.agent_id, issued.task_id, issued.token)
      : TS_SNIPPET(issued.agent_id, issued.task_id, issued.token)
    : '';

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-card rounded-2xl border border-border shadow-2xl w-full max-w-lg max-h-[92vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-5 border-b border-border">
          <div>
            <h2 className="text-lg font-bold text-foreground font-heading">Issue Agent Token</h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              {agent.name} · <span className="font-mono">{agent.agent_id}</span>
            </p>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-xl text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {!issued ? (
          /* ── Issue form ── */
          <div className="px-6 py-5 space-y-5">
            {/* Task ID */}
            <div>
              <label className="block text-sm font-medium text-foreground mb-1.5">
                Task ID <span className="text-destructive">*</span>
              </label>
              <input
                type="text"
                value={taskId}
                onChange={e => { setTaskId(e.target.value); setTaskIdError(''); }}
                placeholder="e.g. task_book_flight_20260310"
                autoFocus
                className={`w-full px-3 py-2.5 border rounded-xl bg-muted text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring text-sm font-mono ${taskIdError ? 'border-destructive' : 'border-border'}`}
              />
              {taskIdError
                ? <p className="mt-1 text-xs text-destructive">{taskIdError}</p>
                : <p className="mt-1 text-xs text-muted-foreground">Groups all tool calls in this run for audit chaining</p>
              }
            </div>

            {/* Tool scope override */}
            {registeredTools.length > 0 && (
              <div>
                <label className="block text-sm font-medium text-foreground mb-1.5">
                  Tool Scope Override <span className="text-muted-foreground font-normal">(optional subset)</span>
                </label>
                <div className="flex flex-wrap gap-2">
                  {registeredTools.map(tool => {
                    const selected = toolOverrides.length === 0 || toolOverrides.includes(tool);
                    const toggled = toolOverrides.includes(tool);
                    return (
                      <button
                        key={tool}
                        type="button"
                        onClick={() => handleToggleTool(tool)}
                        className={`px-3 py-1.5 rounded-xl text-xs font-mono font-medium border transition-colors ${
                          toolOverrides.length === 0 || toggled
                            ? 'bg-primary/10 text-primary border-primary/30'
                            : 'bg-muted text-muted-foreground border-border line-through opacity-50'
                        }`}
                        title={selected ? 'Click to exclude' : 'Click to include'}
                      >
                        {tool}
                      </button>
                    );
                  })}
                </div>
                <p className="mt-1.5 text-xs text-muted-foreground">
                  {toolOverrides.length === 0
                    ? 'All registered tools included. Click tools to restrict scope.'
                    : `Restricting to: ${toolOverrides.join(', ')}`}
                </p>
              </div>
            )}

            {/* Delegation chain */}
            <div>
              <label className="block text-sm font-medium text-foreground mb-1.5">
                Delegation Chain <span className="text-muted-foreground font-normal">(optional, space-separated)</span>
              </label>
              <input
                type="text"
                value={delegationChain}
                onChange={e => setDelegationChain(e.target.value)}
                placeholder="e.g. usr_human123 agt_parent456"
                className="w-full px-3 py-2.5 border border-border rounded-xl bg-muted text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring text-sm font-mono"
              />
              <p className="mt-1 text-xs text-muted-foreground">Principal IDs that delegated to this agent (newest first)</p>
            </div>

            <div className="bg-amber-500/10 border border-amber-500/20 rounded-xl px-4 py-3">
              <p className="text-xs text-amber-900 dark:text-amber-300 font-medium">
                ⚠ The issued token will be shown <strong>once</strong>. Store it securely — it cannot be retrieved again.
              </p>
            </div>
          </div>
        ) : (
          /* ── Token reveal ── */
          <div className="px-6 py-5 space-y-5">
            <div className="bg-amber-500/10 border border-amber-500/20 rounded-xl px-4 py-3 flex items-start gap-3">
              <svg className="w-5 h-5 text-amber-500 mt-0.5 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              <div>
                <p className="text-sm font-semibold text-amber-900 dark:text-amber-200">Save this token — it will not be shown again</p>
                <p className="text-xs text-amber-800 dark:text-amber-300 mt-0.5">
                  Expires in {Math.round(issued.expires_in / 60)} {issued.expires_in <= 60 ? 'minute' : issued.expires_in < 3600 ? 'minutes' : 'hour(s)'}
                </p>
              </div>
            </div>

            {/* Token */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-sm font-medium text-foreground">Agent JWT</span>
                <button
                  onClick={() => copyToClipboard(issued.token, 'Token')}
                  className="text-xs text-primary hover:text-primary/80 font-medium transition-colors"
                >
                  {copied ? '✓ Copied' : 'Copy Token'}
                </button>
              </div>
              <div className="bg-muted border border-border rounded-xl p-3 overflow-x-auto">
                <code className="text-xs font-mono text-foreground break-all">
                  {issued.token}
                </code>
              </div>
            </div>

            {/* SDK Snippet */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-foreground">SDK Snippet</span>
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => setSnippet('python')}
                    className={`px-3 py-1 rounded-lg text-xs font-medium transition-colors ${snippet === 'python' ? 'bg-primary text-primary-foreground' : 'bg-accent text-muted-foreground hover:text-foreground'}`}
                  >
                    Python
                  </button>
                  <button
                    onClick={() => setSnippet('ts')}
                    className={`px-3 py-1 rounded-lg text-xs font-medium transition-colors ${snippet === 'ts' ? 'bg-primary text-primary-foreground' : 'bg-accent text-muted-foreground hover:text-foreground'}`}
                  >
                    TypeScript
                  </button>
                </div>
              </div>
              <div className="relative">
                <pre className="bg-muted border border-border rounded-xl p-4 text-xs font-mono text-foreground overflow-x-auto leading-relaxed">
                  {currentSnippet}
                </pre>
                <button
                  onClick={() => copyToClipboard(currentSnippet, 'SDK snippet')}
                  className="absolute top-2 right-2 px-2.5 py-1.5 bg-card border border-border rounded-lg text-xs text-muted-foreground hover:text-foreground transition-colors"
                >
                  Copy
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="flex gap-3 px-6 pb-6">
          {!issued ? (
            <>
              <button
                onClick={onClose}
                className="flex-1 px-4 py-2.5 bg-accent hover:bg-accent/80 text-foreground rounded-xl transition-colors text-sm font-medium"
              >
                Cancel
              </button>
              <button
                onClick={handleIssue}
                disabled={issuing}
                className="flex-1 px-4 py-2.5 bg-primary hover:bg-primary/90 text-primary-foreground rounded-xl transition-colors text-sm font-semibold font-heading disabled:opacity-50"
              >
                {issuing ? 'Issuing…' : 'Issue Token'}
              </button>
            </>
          ) : (
            <button
              onClick={onClose}
              className="w-full px-4 py-2.5 bg-primary hover:bg-primary/90 text-primary-foreground rounded-xl transition-colors text-sm font-semibold font-heading"
            >
              Done
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
