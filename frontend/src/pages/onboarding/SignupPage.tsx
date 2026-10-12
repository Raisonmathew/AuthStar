/**
 * SignupPage — Self-serve tenant provisioning wizard.
 *
 * 5 steps (US-01 → US-05):
 *   Step 1 (org):     Org name + slug
 *   Step 2 (admin):   Admin email + password → calls POST /api/v1/tenants/provision
 *   Step 3 (agent):   Register first agent (US-02)
 *   Step 4 (key):     Show SDK key once with fingerprint + "I've saved it" gate (US-03)
 *   Step 5 (live):    Live first-call polling indicator (US-05)
 */

import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Highlight, themes } from 'prism-react-renderer';
import { api } from '../../lib/api/client';
import { useAuth } from '../../features/auth/AuthContext';
import type { User } from '../../features/auth/types';

// ─── API types ────────────────────────────────────────────────────────────────

interface ProvisionResponse {
  tenant_id: string;
  user_id: string;
  org_name: string;
  org_slug: string;
  sdk_api_key: string;
  sdk_api_key_id: string;
  key_fingerprint: string;
  message: string;
}

interface RegisterAgentResponse {
  agent_id: string;
  name: string;
}

interface OnboardingStatus {
  first_call_received: boolean;
  last_decision: { tool: string; allowed: boolean; audit_id: string } | null;
}

// ─── Utility ─────────────────────────────────────────────────────────────────

function slugify(s: string) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

// ─── Step: Org ────────────────────────────────────────────────────────────────

interface OrgStepProps {
  orgName: string; orgSlug: string;
  onChange: (name: string, slug: string) => void;
  onNext: () => void;
}
function OrgStep({ orgName, orgSlug, onChange, onNext }: OrgStepProps) {
  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-lg font-semibold text-gray-900">Create your workspace</h2>
        <p className="text-sm text-gray-500 mt-1">Your organisation name appears in audit logs.</p>
      </div>
      <div className="space-y-3">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Organisation name</label>
          <input type="text" className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm bg-white text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="Acme Corp" value={orgName}
            onChange={(e) => onChange(e.target.value, slugify(e.target.value))} />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Slug <span className="text-gray-400 font-normal">(auto-generated)</span>
          </label>
          <input type="text" className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm font-mono bg-white text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="acme-corp" value={orgSlug}
            onChange={(e) => onChange(orgName, e.target.value)} />
        </div>
      </div>
      <button onClick={onNext} disabled={!orgName.trim() || !orgSlug.trim()}
        className="w-full rounded-md bg-blue-600 py-2 px-4 text-sm font-medium text-white disabled:opacity-50 hover:bg-blue-700">
        Continue
      </button>
    </div>
  );
}

// ─── Step: Admin account ──────────────────────────────────────────────────────

interface AdminStepProps {
  email: string; password: string; firstName: string; lastName: string;
  loading: boolean; error: string | null;
  onChange: (f: { email?: string; password?: string; firstName?: string; lastName?: string }) => void;
  onSubmit: () => void;
}
function AdminStep({ email, password, firstName, lastName, loading, error, onChange, onSubmit }: AdminStepProps) {
  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-lg font-semibold text-gray-900">Create your admin account</h2>
        <p className="text-sm text-gray-500 mt-1">Full admin access to your workspace.</p>
      </div>
      {error && (
        <div className="rounded-md bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">{error}</div>
      )}
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">First name</label>
          <input type="text" className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm bg-white text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={firstName} onChange={(e) => onChange({ firstName: e.target.value })} />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Last name</label>
          <input type="text" className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm bg-white text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={lastName} onChange={(e) => onChange({ lastName: e.target.value })} />
        </div>
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Email</label>
        <input type="email" className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm bg-white text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
          placeholder="you@example.com" value={email}
          onChange={(e) => onChange({ email: e.target.value })} />
      </div>
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-1">Password</label>
        <input type="password" className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm bg-white text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
          placeholder="Min 8 chars" value={password}
          onChange={(e) => onChange({ password: e.target.value })} />
        <p className="mt-1 text-xs text-gray-400">Min 8 characters · uppercase · lowercase · number · special character</p>
      </div>
      <button onClick={onSubmit} disabled={loading || !email.trim() || !password.trim()}
        className="w-full rounded-md bg-blue-600 py-2 px-4 text-sm font-medium text-white disabled:opacity-50 hover:bg-blue-700">
        {loading ? 'Creating your workspace…' : 'Create workspace'}
      </button>
    </div>
  );
}

// ─── Step: Register agent (US-02) ─────────────────────────────────────────────

const STARTER_TOOLS = ['web_search', 'send_email', 'read_file'];

interface AgentStepProps {
  tenantId: string;
  apiKey: string;
  loading: boolean;
  error: string | null;
  onDone: (agentId: string) => void;
  onSkip: () => void;
}
function AgentStep({ loading, error, onDone, onSkip }: AgentStepProps) {
  const [agentName, setAgentName] = useState('my-first-agent');
  const [modelId, setModelId] = useState('claude-3-5-sonnet-20241022');
  const [selectedTools, setSelectedTools] = useState<string[]>(['web_search']);
  const [customTool, setCustomTool] = useState('');
  const [skipping, setSkipping] = useState(false);

  const tools = customTool.trim() ? [...STARTER_TOOLS, customTool.trim()] : STARTER_TOOLS;

  const toggleTool = (t: string) =>
    setSelectedTools((prev) => prev.includes(t) ? prev.filter((x) => x !== t) : [...prev, t]);

  const handleSkip = () => {
    setSkipping(true);
    onSkip();
  };

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-lg font-semibold text-gray-900">Register your first agent</h2>
        <p className="text-sm text-gray-500 mt-1">
          An agent must be registered before <code className="bg-gray-100 px-1 rounded text-xs">authorize()</code> will work.
        </p>
      </div>
      {error && (
        <div className="rounded-md bg-red-50 border border-red-200 px-4 py-3 text-sm text-red-700">{error}</div>
      )}
      <div className="space-y-3">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Agent name</label>
          <input type="text" className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm bg-white text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={agentName} onChange={(e) => setAgentName(e.target.value)} />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Model ID</label>
          <input type="text" className="w-full border border-gray-300 rounded-md px-3 py-2 text-sm font-mono bg-white text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
            value={modelId} onChange={(e) => setModelId(e.target.value)} />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Allowed tools</label>
          <div className="flex flex-wrap gap-2">
            {tools.map((t) => (
              <button key={t} type="button" onClick={() => toggleTool(t)}
                className={`text-xs rounded-full px-3 py-1 border transition-colors ${
                  selectedTools.includes(t) ? 'bg-blue-600 text-white border-blue-600' : 'bg-white text-gray-600 border-gray-300 hover:bg-gray-50'
                }`}>
                {t}
              </button>
            ))}
          </div>
          <input type="text" className="mt-2 w-full border rounded-md px-3 py-1.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            placeholder="+ Add custom tool name" value={customTool}
            onChange={(e) => setCustomTool(e.target.value)} />
        </div>
      </div>
      <button
        onClick={() => onDone(agentName)}
        disabled={loading || !agentName.trim() || selectedTools.length === 0}
        className="w-full rounded-md bg-blue-600 py-2 px-4 text-sm font-medium text-white disabled:opacity-50 hover:bg-blue-700">
        {loading ? 'Registering…' : 'Register agent'}
      </button>
      <button onClick={handleSkip} disabled={skipping}
        className="w-full text-sm text-gray-500 hover:text-gray-700 underline">
        Skip — I'm only using human authentication
      </button>
    </div>
  );
}

// ─── Step: API key display (US-03) ───────────────────────────────────────────

interface KeyStepProps {
  apiKey: string;
  fingerprint: string;
  agentSkipped?: boolean;
  onNext: () => void;
}
function KeyStep({ apiKey, fingerprint, agentSkipped, onNext }: KeyStepProps) {
  const [copied, setCopied] = useState(false);
  const [saved, setSaved] = useState(false);

  const copyKey = async () => {
    await navigator.clipboard.writeText(apiKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-lg font-semibold text-gray-900">Save your SDK key</h2>
        <p className="text-sm text-gray-500 mt-1">This key is shown once and cannot be retrieved again.</p>
      </div>
      {agentSkipped && (
        <p className="text-xs text-blue-700 bg-blue-50 border border-blue-200 rounded px-3 py-2">
          No agent registered yet — that's fine. You can add one from the <strong>Agents</strong> page after logging in, then start making authorization calls.
        </p>
      )}
      <div className="rounded-md border border-yellow-200 bg-yellow-50 px-4 py-3 space-y-3">
        <p className="text-sm font-medium text-yellow-800">SDK API Key</p>
        <div className="flex items-center gap-2">
          <code className="flex-1 font-mono text-xs bg-white text-gray-900 border rounded px-2 py-1.5 break-all select-all">
            {apiKey}
          </code>
          <button onClick={copyKey} aria-label="Copy code snippet"
            className="text-xs rounded bg-yellow-100 text-yellow-900 border border-yellow-300 px-2 py-1 hover:bg-yellow-200 shrink-0 whitespace-nowrap">
            {copied ? '✓ Copied' : 'Copy'}
          </button>
        </div>
        <p className="text-xs text-yellow-700 font-mono break-all">{fingerprint}</p>
      </div>
      <label className="flex items-start gap-3 cursor-pointer">
        <input type="checkbox" className="mt-0.5 rounded" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
        <span className="text-sm text-gray-700">I've saved my key securely — I understand it won't be shown again</span>
      </label>
      <button onClick={onNext} disabled={!saved}
        className="w-full rounded-md bg-blue-600 py-2 px-4 text-sm font-medium text-white disabled:opacity-50 hover:bg-blue-700">
        Continue →
      </button>
    </div>
  );
}

// ─── Step: Live first-call indicator (US-05) ──────────────────────────────────

const SNIPPETS: Record<string, (key: string, agentId: string) => string> = {
  Python: (key, agentId) => `from authstar import AgentAuthz

authz = AgentAuthz(
    base_url="https://api.authstar.dev",
    api_key="${key}",
    agent_id="${agentId}",
    task_id="task_demo",
)

decision = authz.authorize(tool="web_search", resource="*", args={})
print("allowed:", decision.allowed)
print("audit_id:", decision.audit_id)`,

  TypeScript: (key, agentId) => `import { AgentAuthzClient } from '@idaas/agent';

const authz = new AgentAuthzClient({
  baseUrl: 'https://api.authstar.dev',
  apiKey: '${key}',
  agentId: '${agentId}',
  taskId: 'task_demo',
});

const decision = await authz.authorizeToolCall('web_search', {});
console.log('allowed:', decision.allowed);
console.log('decision_ref:', decision.decision_ref);`,
};

interface LiveStepProps {
  apiKey: string;
  agentId: string;
  tenantId: string;
  sessionToken: string;
  agentSkipped?: boolean;
}
function LiveStep({ apiKey, agentId, tenantId, sessionToken, agentSkipped }: LiveStepProps) {
  const navigate = useNavigate();
  const [lang, setLang] = useState<keyof typeof SNIPPETS>('Python');
  const [copied, setCopied] = useState(false);
  const [status, setStatus] = useState<'waiting' | 'live' | 'timeout'>('waiting');
  const [lastDecision, setLastDecision] = useState<OnboardingStatus['last_decision']>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const deadlineRef = useRef(Date.now() + 10 * 60 * 1000); // 10 min

  useEffect(() => {
    // Don't poll if agent was skipped — there's no agent to make a first call.
    if (agentSkipped || !tenantId || !sessionToken) return;

    timerRef.current = setInterval(async () => {
      if (Date.now() > deadlineRef.current) {
        clearInterval(timerRef.current!);
        setStatus('timeout');
        return;
      }
      try {
        const res = await api.get<OnboardingStatus>('/api/v1/onboarding/status', {
          headers: { Authorization: `Bearer ${sessionToken}`, 'X-Organization-Id': tenantId },
        });
        if (res.data.first_call_received) {
          clearInterval(timerRef.current!);
          setLastDecision(res.data.last_decision);
          setStatus('live');
        }
      } catch {
        // ignore transient errors — keep polling
      }
    }, 3000);

    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [tenantId, sessionToken, agentSkipped]);

  const copySnippet = async () => {
    await navigator.clipboard.writeText(SNIPPETS[lang](apiKey, agentId));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-lg font-semibold text-gray-900">Run your first authorization</h2>
        <p className="text-sm text-gray-500 mt-1">Copy the snippet, run it, and watch it go live here.</p>
      </div>

      {/* Live indicator */}
      {agentSkipped ? (
        <div className="rounded-md border border-gray-200 bg-gray-50 px-4 py-3 text-sm text-gray-700">
          Your workspace is ready. Register an agent from the dashboard to start making authorization calls.
        </div>
      ) : status === 'waiting' && (
        <div className="flex items-center gap-3 rounded-md border border-blue-200 bg-blue-50 px-4 py-3">
          <span className="inline-block h-3 w-3 rounded-full bg-blue-500 animate-pulse shrink-0" />
          <span className="text-sm text-blue-800">Waiting for your first call…</span>
        </div>
      )}
      {status === 'live' && (
        <div className="rounded-md border border-green-200 bg-green-50 px-4 py-3 space-y-1">
          <p className="text-sm font-medium text-green-800">✅ First authorization received — you're live!</p>
          {lastDecision && (
            <p className="text-xs text-green-700 font-mono">
              {lastDecision.tool} → {lastDecision.allowed ? 'ALLOW' : 'DENY'} · audit_id: {lastDecision.audit_id}
            </p>
          )}
        </div>
      )}
      {status === 'timeout' && (
        <div className="rounded-md border border-yellow-200 bg-yellow-50 px-4 py-3 text-sm text-yellow-800">
          No call yet — run the snippet below, or check{' '}
          <code className="text-xs bg-yellow-100 px-1 rounded">authstar doctor</code> for connectivity issues.
        </div>
      )}

      {/* Language selector + code snippet */}
      <div>
        <div className="flex gap-2 mb-2">
          {Object.keys(SNIPPETS).map((l) => (
            <button key={l} onClick={() => setLang(l as keyof typeof SNIPPETS)}
              className={`text-xs rounded px-2 py-1 border ${
                lang === l ? 'bg-gray-900 text-white border-gray-900' : 'bg-white text-gray-600 border-gray-200 hover:bg-gray-50'
              }`}>
              {l}
            </button>
          ))}
          <button onClick={copySnippet} aria-label="Copy code snippet"
            className="ml-auto text-xs rounded px-2 py-1 border bg-white text-gray-600 border-gray-200 hover:bg-gray-50">
            {copied ? '✓ Copied' : 'Copy'}
          </button>
        </div>
        <Highlight
          theme={themes.vsDark}
          code={SNIPPETS[lang](apiKey, agentId)}
          language={lang === 'Python' ? 'python' : 'typescript'}
        >
          {({ className, style, tokens, getLineProps, getTokenProps }) => (
            <pre
              className={`${className} rounded-md p-4 text-xs overflow-x-auto leading-relaxed`}
              style={style}
            >
              {tokens.map((line, i) => (
                <div key={i} {...getLineProps({ line })}>
                  {line.map((token, key) => (
                    <span key={key} {...getTokenProps({ token })} />
                  ))}
                </div>
              ))}
            </pre>
          )}
        </Highlight>
      </div>

      {status === 'live' && lastDecision && (
        <button
          onClick={() => navigate(`/admin/audit?audit_id=${lastDecision.audit_id}`)}
          className="w-full rounded-md border border-blue-300 bg-blue-50 py-2 px-4 text-sm font-medium text-blue-700 hover:bg-blue-100"
        >
          Explore your audit trail →
        </button>
      )}
      <button onClick={() => navigate('/admin/dashboard')}
        className="w-full rounded-md bg-blue-600 py-2 px-4 text-sm font-medium text-white hover:bg-blue-700">
        Go to dashboard →
      </button>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

type Step = 'org' | 'admin' | 'agent' | 'key' | 'live';
const STEP_LABELS: Record<Step, string> = { org: 'Workspace', admin: 'Account', agent: 'Agent', key: 'API Key', live: 'Go live' };
const STEP_ORDER: Step[] = ['org', 'admin', 'agent', 'key', 'live'];

export default function SignupPage() {
  const { setAuth } = useAuth();
  const [step, setStep] = useState<Step>('org');
  const [orgName, setOrgName] = useState('');
  const [orgSlug, setOrgSlug] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [provision, setProvision] = useState<ProvisionResponse | null>(null);
  const [sessionToken, setSessionToken] = useState('');
  const [agentId, setAgentId] = useState('');

  const stepIndex = STEP_ORDER.indexOf(step);

  // ── Step 2: Provision tenant ────────────────────────────────────────────────
  const handleProvision = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.post<ProvisionResponse>('/api/v1/tenants/provision', {
        org_name: orgName,
        org_slug: orgSlug || undefined,
        admin_email: email,
        admin_password: password,
        first_name: firstName || undefined,
        last_name: lastName || undefined,
      });
      setProvision(res.data);
      // Auto-login: establishes the session in AuthContext so "Go to dashboard"
      // lands in the admin shell without bouncing back to the login page.
      try {
        const loginRes = await api.post<{ jwt: string; user: User }>('/api/v1/sign-in', {
          identifier: email,
          password,
          tenantId: res.data.tenant_id,
        });
        setAuth(loginRes.data.jwt, loginRes.data.user);
        setSessionToken(loginRes.data.jwt);
      } catch {
        // Non-fatal: user can still log in manually from the dashboard button
      }
      setStep('agent');
    } catch (err: unknown) {
      // Axios wraps the server response — extract the backend message if present.
      const axiosMsg = (err as any)?.response?.data?.error?.message
        ?? (err as any)?.response?.data?.message;
      setError(axiosMsg ?? (err instanceof Error ? err.message : 'Something went wrong. Please try again.'));
    } finally {
      setLoading(false);
    }
  };

  // ── Step 3: Register agent ──────────────────────────────────────────────────
  const handleRegisterAgent = async (name: string) => {
    if (!provision) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.post<RegisterAgentResponse>(
        '/api/v1/agents/register',
        { name, model_id: 'claude-3-5-sonnet-20241022', allowed_tools: 'web_search send_email read_file' },
        { headers: { Authorization: `Bearer ${sessionToken}`, 'X-Organization-Id': provision.tenant_id } },
      );
      setAgentId(res.data.agent_id);
      setStep('key');
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Agent registration failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="light min-h-screen flex items-center justify-center p-4" style={{ backgroundColor: '#f9fafb' }}>
      <div className="w-full max-w-md">
        {/* Header */}
        <div className="text-center mb-6">
          <h1 className="text-2xl font-bold text-gray-900">AuthStar</h1>
          <p className="text-sm text-gray-500 mt-1">Identity-as-a-Service</p>
        </div>

        {/* Step indicator */}
        <div className="flex items-center mb-8">
          {STEP_ORDER.map((s, i) => (
            <div key={s} className="flex-1 flex items-center">
              <div className="flex flex-col items-center">
                <div className={`w-6 h-6 rounded-full text-xs font-bold flex items-center justify-center ${
                  i < stepIndex ? 'bg-green-500 text-white' : i === stepIndex ? 'bg-blue-600 text-white' : 'bg-gray-200 text-gray-500'
                }`}>
                  {i < stepIndex ? '✓' : i + 1}
                </div>
                <span className="text-xs mt-1 text-gray-500">{STEP_LABELS[s]}</span>
              </div>
              {i < STEP_ORDER.length - 1 && (
                <div className={`flex-1 h-0.5 mx-1 ${i < stepIndex ? 'bg-green-400' : 'bg-gray-200'}`} />
              )}
            </div>
          ))}
        </div>

        {/* Card */}
        <div className="bg-white rounded-xl border border-gray-200 shadow-sm p-6">
          {step === 'org' && (
            <OrgStep orgName={orgName} orgSlug={orgSlug}
              onChange={(name, slug) => { setOrgName(name); setOrgSlug(slug); }}
              onNext={() => setStep('admin')} />
          )}
          {step === 'admin' && (
            <AdminStep email={email} password={password} firstName={firstName} lastName={lastName}
              loading={loading} error={error}
              onChange={({ email: e, password: p, firstName: f, lastName: l }) => {
                if (e !== undefined) setEmail(e);
                if (p !== undefined) setPassword(p);
                if (f !== undefined) setFirstName(f);
                if (l !== undefined) setLastName(l);
              }}
              onSubmit={handleProvision} />
          )}
          {step === 'agent' && provision && (
            <AgentStep
              tenantId={provision.tenant_id}
              apiKey={provision.sdk_api_key}
              loading={loading}
              error={error}
              onDone={handleRegisterAgent}
              onSkip={() => { setAgentId(''); setStep('key'); }} />
          )}
          {step === 'key' && provision && (
            <KeyStep
              apiKey={provision.sdk_api_key}
              fingerprint={provision.key_fingerprint}
              agentSkipped={!agentId}
              onNext={() => setStep('live')} />
          )}
          {step === 'live' && provision && (
            <LiveStep
              apiKey={provision.sdk_api_key}
              agentId={agentId}
              tenantId={provision.tenant_id}
              sessionToken={sessionToken}
              agentSkipped={!agentId} />
          )}
        </div>

        <p className="text-center text-xs text-gray-400 mt-4">
          Already have an account?{' '}
          <a href="/u/default" className="text-blue-600 hover:underline">Sign in</a>
        </p>
      </div>
    </div>
  );
}
