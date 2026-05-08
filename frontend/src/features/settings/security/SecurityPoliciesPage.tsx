import { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { api } from '../../../lib/api';
import { Badge, Button, Input, PageHeader } from '../../../components/ui';

interface PasswordPolicy {
  enabled: boolean;
  minLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireDigit: boolean;
  requireSymbol: boolean;
  historyDepth: number;
  maxAgeDays?: number | null;
  forceRotation: boolean;
}

interface LockoutPolicy {
  id?: string;
  tenantId?: string;
  factorKind: string;
  enabled: boolean;
  failureThreshold: number;
  windowSeconds: number;
  lockDurationSeconds: number;
}

interface LockoutState {
  userId: string;
  email?: string | null;
  firstName?: string | null;
  lastName?: string | null;
  accountLocked: boolean;
  accountLockedAt?: string | null;
  last1h: number;
  last24h: number;
  lockedUntil?: string | null;
  lastFailureAt?: string | null;
  lastSuccessAt?: string | null;
}

const factorLabels: Record<string, string> = {
  password: 'Password',
  totp: 'TOTP',
  hotp: 'HOTP',
  webauthn: 'Passkey',
  recovery_code: 'Recovery Code',
  sms: 'SMS',
  email: 'Email',
};

export default function SecurityPoliciesPage() {
  const [passwordPolicy, setPasswordPolicy] = useState<PasswordPolicy | null>(null);
  const [lockoutPolicies, setLockoutPolicies] = useState<LockoutPolicy[]>([]);
  const [selectedFactor, setSelectedFactor] = useState('password');
  const [lockedUsers, setLockedUsers] = useState<LockoutState[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState<'password' | 'lockout' | null>(null);
  const [resettingUserId, setResettingUserId] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    try {
      const [passwordRes, lockoutRes, lockedUsersRes] = await Promise.all([
        api.get<PasswordPolicy>('/api/admin/v1/security/password-policy'),
        api.get<LockoutPolicy[]>('/api/admin/v1/security/lockout-policies'),
        api.get<LockoutState[]>('/api/admin/v1/security/locked-users'),
      ]);
      setPasswordPolicy(passwordRes.data);
      setLockoutPolicies(lockoutRes.data);
      setLockedUsers(lockedUsersRes.data);
    } catch (error) {
      console.error('Failed to load security policies', error);
      toast.error('Failed to load security policies');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const savePasswordPolicy = async () => {
    if (!passwordPolicy) return;
    setSaving('password');
    try {
      const res = await api.put<PasswordPolicy>('/api/admin/v1/security/password-policy', passwordPolicy);
      setPasswordPolicy(res.data);
      toast.success('Password policy saved');
    } catch (error) {
      console.error('Failed to save password policy', error);
      toast.error('Failed to save password policy');
    } finally {
      setSaving(null);
    }
  };

  const saveLockoutPolicy = async () => {
    const lockoutPolicy = lockoutPolicies.find((policy) => policy.factorKind === selectedFactor);
    if (!lockoutPolicy) return;
    setSaving('lockout');
    try {
      const res = await api.put<LockoutPolicy>(`/api/admin/v1/security/lockout-policy/${selectedFactor}`, lockoutPolicy);
      setLockoutPolicies((policies) => policies.map((policy) => policy.factorKind === selectedFactor ? res.data : policy));
      toast.success(`${factorLabels[selectedFactor] || selectedFactor} lockout policy saved`);
    } catch (error) {
      console.error('Failed to save lockout policy', error);
      toast.error('Failed to save lockout policy');
    } finally {
      setSaving(null);
    }
  };

  const updateActiveLockoutPolicy = (patch: Partial<LockoutPolicy>) => {
    setLockoutPolicies((policies) => policies.map((policy) => (
      policy.factorKind === selectedFactor ? { ...policy, ...patch } : policy
    )));
  };

  const resetLockout = async (userId: string) => {
    setResettingUserId(userId);
    try {
      await api.post<LockoutState>(`/api/admin/v1/security/lockout/${userId}/reset`);
      setLockedUsers((users) => users.filter((user) => user.userId !== userId));
      toast.success('User lockout reset');
    } catch (error) {
      console.error('Failed to reset user lockout', error);
      toast.error('Failed to reset user lockout');
    } finally {
      setResettingUserId(null);
    }
  };

  const activeLockoutPolicy = lockoutPolicies.find((policy) => policy.factorKind === selectedFactor) || null;

  if (loading || !passwordPolicy || !activeLockoutPolicy) {
    return <div className="p-8 text-center text-muted-foreground">Loading security policies...</div>;
  }

  return (
    <div className="space-y-6">
      <PageHeader title="Security Policies" description="Configure tenant password rules and credential lockout enforcement." />

      <section className="rounded-xl border border-border bg-card p-4">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div>
            <h3 className="font-semibold text-foreground">Password Policy</h3>
            <p className="text-sm text-muted-foreground">Applies to admin-created users, self-service changes, and forced resets.</p>
          </div>
          <Badge variant={passwordPolicy.enabled ? 'success' : 'muted'}>{passwordPolicy.enabled ? 'Enabled' : 'Disabled'}</Badge>
        </div>

        <div className="mb-4 grid gap-3 text-sm md:grid-cols-3">
          <Metric label="Current expiry" value={passwordPolicy.maxAgeDays ? `${passwordPolicy.maxAgeDays} days` : 'Never'} />
          <Metric label="History depth" value={`${passwordPolicy.historyDepth} previous`} />
          <Metric label="Rotation" value={passwordPolicy.forceRotation ? 'Forced for all users' : 'Policy age based'} />
        </div>

        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <NumberInput label="Minimum Length" value={passwordPolicy.minLength} onChange={(minLength) => setPasswordPolicy({ ...passwordPolicy, minLength: typeof minLength === 'number' ? minLength : 0 })} />
          <NumberInput label="History Depth" value={passwordPolicy.historyDepth} onChange={(historyDepth) => setPasswordPolicy({ ...passwordPolicy, historyDepth: typeof historyDepth === 'number' ? historyDepth : 0 })} />
          <NumberInput
            label="Max Age Days"
            value={passwordPolicy.maxAgeDays ?? ''}
            placeholder="Never"
            onChange={(maxAgeDays) => setPasswordPolicy({ ...passwordPolicy, maxAgeDays: maxAgeDays === '' || maxAgeDays === 0 ? null : Number(maxAgeDays) })}
          />
        </div>

        <div className="mt-4 flex flex-wrap gap-4 text-sm text-foreground">
          <Checkbox label="Enabled" checked={passwordPolicy.enabled} onChange={(enabled) => setPasswordPolicy({ ...passwordPolicy, enabled })} />
          <Checkbox label="Uppercase" checked={passwordPolicy.requireUppercase} onChange={(requireUppercase) => setPasswordPolicy({ ...passwordPolicy, requireUppercase })} />
          <Checkbox label="Lowercase" checked={passwordPolicy.requireLowercase} onChange={(requireLowercase) => setPasswordPolicy({ ...passwordPolicy, requireLowercase })} />
          <Checkbox label="Digit" checked={passwordPolicy.requireDigit} onChange={(requireDigit) => setPasswordPolicy({ ...passwordPolicy, requireDigit })} />
          <Checkbox label="Symbol" checked={passwordPolicy.requireSymbol} onChange={(requireSymbol) => setPasswordPolicy({ ...passwordPolicy, requireSymbol })} />
          <Checkbox label="Force Rotation" checked={passwordPolicy.forceRotation} onChange={(forceRotation) => setPasswordPolicy({ ...passwordPolicy, forceRotation })} />
        </div>

        <div className="mt-4">
          <Button loading={saving === 'password'} onClick={savePasswordPolicy}>Save Password Policy</Button>
        </div>
      </section>

      <section className="rounded-xl border border-border bg-card p-4">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div>
            <h3 className="font-semibold text-foreground">Credential Lockout</h3>
            <p className="text-sm text-muted-foreground">Blocks password verification after repeated failed attempts.</p>
          </div>
          <Badge variant={activeLockoutPolicy.enabled ? 'success' : 'muted'}>{activeLockoutPolicy.enabled ? 'Enabled' : 'Disabled'}</Badge>
        </div>

        <div className="mb-4 flex flex-wrap gap-2">
          {lockoutPolicies.map((policy) => (
            <button
              key={policy.factorKind}
              type="button"
              onClick={() => setSelectedFactor(policy.factorKind)}
              className={`rounded-lg border px-3 py-1.5 text-sm font-semibold transition-colors ${selectedFactor === policy.factorKind ? 'border-primary bg-primary text-primary-foreground' : 'border-border bg-background text-muted-foreground hover:text-foreground'}`}
            >
              {factorLabels[policy.factorKind] || policy.factorKind}
            </button>
          ))}
        </div>

        <div className="grid gap-4 md:grid-cols-3">
          <NumberInput label="Failure Threshold" value={activeLockoutPolicy.failureThreshold} onChange={(failureThreshold) => updateActiveLockoutPolicy({ failureThreshold: typeof failureThreshold === 'number' ? failureThreshold : 0 })} />
          <NumberInput label="Window Seconds" value={activeLockoutPolicy.windowSeconds} onChange={(windowSeconds) => updateActiveLockoutPolicy({ windowSeconds: typeof windowSeconds === 'number' ? windowSeconds : 0 })} />
          <NumberInput label="Lock Duration Seconds" value={activeLockoutPolicy.lockDurationSeconds} onChange={(lockDurationSeconds) => updateActiveLockoutPolicy({ lockDurationSeconds: typeof lockDurationSeconds === 'number' ? lockDurationSeconds : 0 })} />
        </div>

        <div className="mt-4 flex flex-wrap items-center gap-4">
          <Checkbox label="Enabled" checked={activeLockoutPolicy.enabled} onChange={(enabled) => updateActiveLockoutPolicy({ enabled })} />
          <Button loading={saving === 'lockout'} onClick={saveLockoutPolicy}>Save Lockout Policy</Button>
        </div>
      </section>

      <section className="rounded-xl border border-border bg-card p-4">
        <div className="mb-4 flex items-center justify-between gap-3">
          <div>
            <h3 className="font-semibold text-foreground">Locked Users</h3>
            <p className="text-sm text-muted-foreground">Accounts or password credentials currently blocked by lockout enforcement.</p>
          </div>
          <Button variant="outline" size="sm" onClick={load}>Refresh</Button>
        </div>

        <div className="overflow-hidden rounded-lg border border-border">
          <table className="min-w-full divide-y divide-border">
            <thead className="bg-muted/30">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-muted-foreground">User</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-muted-foreground">Failures</th>
                <th className="px-4 py-3 text-left text-xs font-semibold uppercase text-muted-foreground">Locked Until</th>
                <th className="px-4 py-3 text-right text-xs font-semibold uppercase text-muted-foreground">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {lockedUsers.length === 0 && (
                <tr>
                  <td colSpan={4} className="px-4 py-8 text-center text-sm text-muted-foreground">No locked users.</td>
                </tr>
              )}
              {lockedUsers.map((user) => (
                <tr key={user.userId}>
                  <td className="px-4 py-3">
                    <div className="font-medium text-foreground">{displayUser(user)}</div>
                    <div className="text-xs text-muted-foreground">{user.email || user.userId}</div>
                    {user.accountLocked && <Badge variant="danger">Account locked</Badge>}
                  </td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">
                    <div>{user.last1h} in 1h</div>
                    <div>{user.last24h} in 24h</div>
                  </td>
                  <td className="px-4 py-3 text-sm text-muted-foreground">
                    {user.lockedUntil ? formatDate(user.lockedUntil) : (user.accountLockedAt ? formatDate(user.accountLockedAt) : 'Manual lock')}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <Button size="sm" variant="outline" loading={resettingUserId === user.userId} onClick={() => resetLockout(user.userId)}>Reset</Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-border bg-background p-3">
      <div className="text-xs font-semibold uppercase text-muted-foreground">{label}</div>
      <div className="mt-1 text-sm font-medium text-foreground">{value}</div>
    </div>
  );
}

function NumberInput({ label, value, onChange, placeholder }: { label: string; value: number | ''; onChange: (value: number | '') => void; placeholder?: string }) {
  return (
    <Input
      label={label}
      type="number"
      placeholder={placeholder}
      value={value === '' ? '' : (Number.isFinite(value) ? value : 0)}
      onChange={(event) => {
        const raw = event.target.value;
        onChange(raw === '' ? '' : Number(raw));
      }}
    />
  );
}

function Checkbox({ label, checked, onChange }: { label: string; checked: boolean; onChange: (checked: boolean) => void }) {
  return (
    <label className="flex items-center gap-2">
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      {label}
    </label>
  );
}

function displayUser(user: LockoutState) {
  return [user.firstName, user.lastName].filter(Boolean).join(' ') || user.email || user.userId;
}

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(value));
}