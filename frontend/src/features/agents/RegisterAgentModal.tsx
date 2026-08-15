import { useState, useEffect } from 'react';
import { toast } from 'sonner';
import { agentsApi, AgentPrincipal, RegisterAgentRequest, UpdateAgentRequest } from '../../lib/api/agents';

interface Props {
  agent?: AgentPrincipal;
  onClose: () => void;
  onSuccess: (agentId: string) => void;
}

const TTL_OPTIONS = [
  { label: '1 minute (testing)', value: 60 },
  { label: '15 minutes', value: 900 },
  { label: '1 hour', value: 3600 },
  { label: '4 hours', value: 14400 },
  { label: '8 hours', value: 28800 },
  { label: '24 hours', value: 86400 },
];

export default function RegisterAgentModal({ agent, onClose, onSuccess }: Props) {
  const isEdit = !!agent;

  const [name, setName] = useState(agent?.name ?? '');
  const [modelId, setModelId] = useState(agent?.model_id ?? '');
  const [allowedTools, setAllowedTools] = useState(agent?.allowed_tools ?? '');
  const [maxDepth, setMaxDepth] = useState(agent?.max_delegation_depth ?? 3);
  const [ttl, setTtl] = useState(agent?.token_ttl_seconds ?? 3600);
  const [cimdUrl, setCimdUrl] = useState(agent?.cimd_metadata_url ?? '');
  const [showAdvanced, setShowAdvanced] = useState(false);

  const [nameError, setNameError] = useState('');
  const [toolsError, setToolsError] = useState('');
  const [cimdError, setCimdError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  // Reset errors when inputs change
  useEffect(() => { setNameError(''); }, [name]);
  useEffect(() => { setToolsError(''); }, [allowedTools]);
  useEffect(() => { setCimdError(''); }, [cimdUrl]);

  const validate = (): boolean => {
    let ok = true;
    if (!name.trim()) { setNameError('Agent name is required'); ok = false; }
    if (name.trim().length > 120) { setNameError('Must be 120 characters or fewer'); ok = false; }
    if (allowedTools.trim()) {
      const invalid = allowedTools.trim().split(/\s+/).filter(t => !/^[\w:-]+$/.test(t));
      if (invalid.length > 0) {
        setToolsError(`Invalid tool name(s): ${invalid.join(', ')}. Use alphanumeric, underscores, colons, hyphens only.`);
        ok = false;
      }
    }
    if (cimdUrl && !cimdUrl.startsWith('https://')) {
      setCimdError('CIMD metadata URL must start with https://');
      ok = false;
    }
    return ok;
  };

  const handleSubmit = async () => {
    if (!validate()) return;
    setSubmitting(true);
    try {
      if (isEdit && agent) {
        const req: UpdateAgentRequest = {
          model_id: modelId || undefined,
          allowed_tools: allowedTools || undefined,
          max_delegation_depth: maxDepth,
          token_ttl_seconds: ttl,
        };
        const res = await agentsApi.update(agent.agent_id, req);
        toast.success('Agent updated');
        onSuccess(res.data.agent_id);
      } else {
        const req: RegisterAgentRequest = {
          name: name.trim(),
          model_id: modelId || undefined,
          allowed_tools: allowedTools || undefined,
          max_delegation_depth: maxDepth,
          token_ttl_seconds: ttl,
          cimd_metadata_url: cimdUrl || undefined,
        };
        const res = await agentsApi.register(req);
        toast.success('Agent registered');
        onSuccess(res.data.agent_id);
      }
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message;
      toast.error(msg ?? (isEdit ? 'Failed to update agent' : 'Failed to register agent'));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
      <div className="bg-card rounded-2xl border border-border shadow-2xl w-full max-w-lg max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-5 border-b border-border">
          <div>
            <h2 className="text-lg font-bold text-foreground font-heading">
              {isEdit ? 'Edit Agent' : 'Register AI Agent'}
            </h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              {isEdit ? `agt_id: ${agent?.agent_id}` : 'Register a non-human principal for tool-call authorization'}
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

        {/* Form */}
        <div className="px-6 py-5 space-y-5">
          {/* Name */}
          {!isEdit && (
            <div>
              <label className="block text-sm font-medium text-foreground mb-1.5">
                Agent Name <span className="text-destructive">*</span>
              </label>
              <input
                type="text"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="e.g. Claude Assistant"
                maxLength={120}
                autoFocus
                className={`w-full px-3 py-2.5 border rounded-xl bg-muted text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring text-sm ${nameError ? 'border-destructive' : 'border-border'}`}
              />
              {nameError && <p className="mt-1 text-xs text-destructive">{nameError}</p>}
            </div>
          )}

          {/* Model ID */}
          <div>
            <label className="block text-sm font-medium text-foreground mb-1.5">
              Model Identifier <span className="text-muted-foreground font-normal">(optional)</span>
            </label>
            <input
              type="text"
              value={modelId}
              onChange={e => setModelId(e.target.value)}
              placeholder="e.g. claude-3-5-sonnet-20241022"
              className="w-full px-3 py-2.5 border border-border rounded-xl bg-muted text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring text-sm"
            />
          </div>

          {/* Allowed Tools */}
          <div>
            <label className="block text-sm font-medium text-foreground mb-1.5">
              Allowed Tools <span className="text-muted-foreground font-normal">(space-separated)</span>
            </label>
            <input
              type="text"
              value={allowedTools}
              onChange={e => setAllowedTools(e.target.value)}
              placeholder="e.g. web_search send_email read_file"
              className={`w-full px-3 py-2.5 border rounded-xl bg-muted text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring text-sm font-mono ${toolsError ? 'border-destructive' : 'border-border'}`}
            />
            {toolsError
              ? <p className="mt-1 text-xs text-destructive">{toolsError}</p>
              : <p className="mt-1 text-xs text-muted-foreground">Each tool name maps to an EIAA capsule action string (<code className="font-mono">agent:tool_name</code>)</p>
            }
          </div>

          {/* Depth + TTL row */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-foreground mb-1.5">
                Max Delegation Depth
              </label>
              <select
                value={maxDepth}
                onChange={e => setMaxDepth(Number(e.target.value))}
                className="w-full px-3 py-2.5 border border-border rounded-xl bg-muted text-foreground focus:outline-none focus:ring-2 focus:ring-ring text-sm"
              >
                {[1, 2, 3, 4, 5, 6, 7, 8].map(d => (
                  <option key={d} value={d}>{d}</option>
                ))}
              </select>
              <p className="mt-1 text-xs text-muted-foreground">Chain depth limit (1–8)</p>
            </div>
            <div>
              <label className="block text-sm font-medium text-foreground mb-1.5">
                Token TTL
              </label>
              <select
                value={ttl}
                onChange={e => setTtl(Number(e.target.value))}
                className="w-full px-3 py-2.5 border border-border rounded-xl bg-muted text-foreground focus:outline-none focus:ring-2 focus:ring-ring text-sm"
              >
                {TTL_OPTIONS.map(o => (
                  <option key={o.value} value={o.value}>{o.label}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Advanced section */}
          <div>
            <button
              type="button"
              onClick={() => setShowAdvanced(v => !v)}
              className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
            >
              <svg
                className={`w-4 h-4 transition-transform ${showAdvanced ? 'rotate-90' : ''}`}
                fill="none" stroke="currentColor" viewBox="0 0 24 24"
              >
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
              </svg>
              Advanced (CIMD Metadata URL)
            </button>
            {showAdvanced && (
              <div className="mt-3">
                <input
                  type="url"
                  value={cimdUrl}
                  onChange={e => setCimdUrl(e.target.value)}
                  placeholder="https://your-llm-provider.com/.well-known/agent-metadata"
                  className={`w-full px-3 py-2.5 border rounded-xl bg-muted text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring text-sm ${cimdError ? 'border-destructive' : 'border-border'}`}
                />
                {cimdError
                  ? <p className="mt-1 text-xs text-destructive">{cimdError}</p>
                  : <p className="mt-1 text-xs text-muted-foreground">Optional: CIMD-DCR metadata URL for hybrid pre-registered + dynamic agents</p>
                }
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="flex gap-3 px-6 pb-6">
          <button
            onClick={onClose}
            className="flex-1 px-4 py-2.5 bg-accent hover:bg-accent/80 text-foreground rounded-xl transition-colors text-sm font-medium"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={submitting}
            className="flex-1 px-4 py-2.5 bg-primary hover:bg-primary/90 text-primary-foreground rounded-xl transition-colors text-sm font-semibold font-heading disabled:opacity-50"
          >
            {submitting ? (isEdit ? 'Saving…' : 'Registering…') : (isEdit ? 'Save Changes' : 'Register Agent')}
          </button>
        </div>
      </div>
    </div>
  );
}
