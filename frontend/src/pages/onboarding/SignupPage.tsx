/**
 * SignupPage — Self-serve tenant provisioning wizard.
 *
 * 4 steps:
 *   Step 1 (org):     Org name + slug
 *   Step 2 (admin):   Admin email + password → calls POST /api/v1/tenants/provision
 *   Step 3 (key):     Show SDK key once with fingerprint + "I've saved it" gate
 *   Step 4 (done):    Workspace ready → dashboard
 */

import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
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

// ─── Step: API key display (US-03) ───────────────────────────────────────────

interface KeyStepProps {
  apiKey: string;
  fingerprint: string;
  onNext: () => void;
}
function KeyStep({ apiKey, fingerprint, onNext }: KeyStepProps) {
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

// ─── Step: Done ───────────────────────────────────────────────────────────────

function DoneStep() {
  const navigate = useNavigate();
  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-lg font-semibold text-gray-900">Your workspace is ready</h2>
        <p className="text-sm text-gray-500 mt-1">You can now configure authentication from the dashboard.</p>
      </div>
      <button onClick={() => navigate('/admin/dashboard')}
        className="w-full rounded-md bg-blue-600 py-2 px-4 text-sm font-medium text-white hover:bg-blue-700">
        Go to dashboard →
      </button>
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

type Step = 'org' | 'admin' | 'key' | 'done';
const STEP_LABELS: Record<Step, string> = { org: 'Workspace', admin: 'Account', key: 'API Key', done: 'Done' };
const STEP_ORDER: Step[] = ['org', 'admin', 'key', 'done'];

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
      } catch {
        // Non-fatal: user can still log in manually from the dashboard button
      }
      setStep('key');
    } catch (err: unknown) {
      // Axios wraps the server response — extract the backend message if present.
      const axiosMsg = (err as any)?.response?.data?.error?.message
        ?? (err as any)?.response?.data?.message;
      setError(axiosMsg ?? (err instanceof Error ? err.message : 'Something went wrong. Please try again.'));
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
          {step === 'key' && provision && (
            <KeyStep
              apiKey={provision.sdk_api_key}
              fingerprint={provision.key_fingerprint}
              onNext={() => setStep('done')} />
          )}
          {step === 'done' && <DoneStep />}
        </div>

        <p className="text-center text-xs text-gray-400 mt-4">
          Already have an account?{' '}
          <a href="/u/default" className="text-blue-600 hover:underline">Sign in</a>
        </p>
      </div>
    </div>
  );
}
