/**
 * SimulatePanel — test a policy against a synthetic context.
 * Shows a form on the left, result trace on the right.
 */

import { useState } from 'react';
import { clsx } from 'clsx';
import type { TestContext, SimulateResponse } from '../types';
import * as pbApi from '../api';

interface SimulatePanelProps {
  configId: string;
}

// Quick scenario presets
const PRESETS: { label: string; context: TestContext }[] = [
  {
    label: 'Normal User',
    context: {
      risk_score: 15,
      country_code: 'US',
      is_new_device: false,
      email_verified: true,
      vpn_detected: false,
      tor_detected: false,
      aal_level: 2,
      current_hour: 14,
    },
  },
  {
    label: 'High Risk',
    context: {
      risk_score: 85,
      country_code: 'US',
      is_new_device: false,
      email_verified: true,
      vpn_detected: false,
      tor_detected: false,
      aal_level: 1,
      current_hour: 14,
    },
  },
  {
    label: 'New Device',
    context: {
      risk_score: 30,
      country_code: 'US',
      is_new_device: true,
      email_verified: true,
      vpn_detected: false,
      tor_detected: false,
      aal_level: 1,
      current_hour: 10,
    },
  },
  {
    label: 'Blocked Country',
    context: {
      risk_score: 20,
      country_code: 'KP',
      is_new_device: false,
      email_verified: true,
      vpn_detected: false,
      tor_detected: false,
      aal_level: 2,
      current_hour: 12,
    },
  },
  {
    label: 'VPN User',
    context: {
      risk_score: 40,
      country_code: 'DE',
      is_new_device: false,
      email_verified: true,
      vpn_detected: true,
      tor_detected: false,
      aal_level: 1,
      current_hour: 9,
    },
  },
];

const DEFAULT_CONTEXT: TestContext = {
  risk_score: 20,
  country_code: 'US',
  is_new_device: false,
  email_verified: true,
  vpn_detected: false,
  tor_detected: false,
  aal_level: 1,
  current_hour: 12,
  impossible_travel: false,
  user_roles: [],
  ip_address: '',
  custom_claims: {},
};

export function SimulatePanel({ configId }: SimulatePanelProps) {
  const [context, setContext] = useState<TestContext>(DEFAULT_CONTEXT);
  const [result, setResult] = useState<SimulateResponse | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [roleInput, setRoleInput] = useState('');
  const [claimKey, setClaimKey] = useState('');
  const [claimVal, setClaimVal] = useState('');

  const set = <K extends keyof TestContext>(key: K, value: TestContext[K]) => {
    setContext((c) => ({ ...c, [key]: value }));
  };

  const applyPreset = (preset: typeof PRESETS[0]) => {
    setContext({ ...DEFAULT_CONTEXT, ...preset.context });
    setResult(null);
    setError(null);
  };

  const handleRun = async () => {
    setRunning(true);
    setError(null);
    setResult(null);
    try {
      const res = await pbApi.simulateConfig(configId, { context });
      setResult(res);
    } catch (err: any) {
      setError(err?.response?.data?.error ?? err?.message ?? 'Simulation failed');
    } finally {
      setRunning(false);
    }
  };

  const addRole = () => {
    const r = roleInput.trim();
    if (r && !(context.user_roles ?? []).includes(r)) {
      set('user_roles', [...(context.user_roles ?? []), r]);
    }
    setRoleInput('');
  };

  const removeRole = (role: string) => {
    set('user_roles', (context.user_roles ?? []).filter((r) => r !== role));
  };

  const addClaim = () => {
    if (claimKey.trim()) {
      set('custom_claims', { ...(context.custom_claims ?? {}), [claimKey.trim()]: claimVal.trim() });
      setClaimKey('');
      setClaimVal('');
    }
  };

  const removeClaim = (key: string) => {
    const claims = { ...(context.custom_claims ?? {}) };
    delete claims[key];
    set('custom_claims', claims);
  };

  return (
    <div className="space-y-6">
      <div>
        <h3 className="text-base font-semibold text-white">Simulate Policy</h3>
        <p className="text-sm text-slate-400 mt-1">
          Test your policy against a hypothetical user context. No real users are affected.
        </p>
      </div>

      {/* Presets */}
      <div className="flex flex-wrap gap-2">
        <span className="text-xs text-slate-500 self-center">Presets:</span>
        {PRESETS.map((p) => (
          <button
            key={p.label}
            type="button"
            onClick={() => applyPreset(p)}
            className="px-3 py-1 text-xs bg-slate-800 border border-slate-700 rounded-full text-slate-300 hover:border-indigo-500 hover:text-indigo-300 transition-colors"
          >
            {p.label}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Left: Context form */}
        <div className="space-y-4 bg-slate-900 border border-slate-800 rounded-2xl p-5">
          <h4 className="text-sm font-semibold text-slate-200">Test Context</h4>

          {/* Risk score */}
          <div className="space-y-1">
            <div className="flex justify-between">
              <label className="text-xs font-medium text-slate-300">Risk Score</label>
              <span className="text-xs text-slate-400 font-mono">{context.risk_score ?? 0}</span>
            </div>
            <input
              type="range"
              min={0}
              max={100}
              value={context.risk_score ?? 0}
              onChange={(e) => set('risk_score', Number(e.target.value))}
              className="w-full h-1.5 bg-slate-700 rounded-full appearance-none cursor-pointer accent-indigo-500"
            />
            <div className="flex justify-between text-[10px] text-slate-600">
              <span>0 (low)</span>
              <span>100 (high)</span>
            </div>
          </div>

          {/* Country code */}
          <div className="space-y-1">
            <label className="text-xs font-medium text-slate-300">Country Code</label>
            <input
              type="text"
              value={context.country_code ?? ''}
              onChange={(e) => set('country_code', e.target.value.toUpperCase().slice(0, 2))}
              placeholder="US"
              maxLength={2}
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 font-mono uppercase"
            />
          </div>

          {/* AAL level */}
          <div className="space-y-1">
            <label className="text-xs font-medium text-slate-300">AAL Level</label>
            <div className="flex gap-2">
              {[1, 2, 3].map((level) => (
                <button
                  key={level}
                  type="button"
                  onClick={() => set('aal_level', level)}
                  className={clsx(
                    'flex-1 py-1.5 rounded-lg text-xs font-medium border transition-colors',
                    context.aal_level === level
                      ? 'bg-indigo-500/20 border-indigo-500/40 text-indigo-300'
                      : 'bg-slate-800 border-slate-700 text-slate-400 hover:border-slate-500'
                  )}
                >
                  AAL{level}
                </button>
              ))}
            </div>
          </div>

          {/* Current hour */}
          <div className="space-y-1">
            <div className="flex justify-between">
              <label className="text-xs font-medium text-slate-300">Current Hour (0–23)</label>
              <span className="text-xs text-slate-400 font-mono">{context.current_hour ?? 0}:00</span>
            </div>
            <input
              type="range"
              min={0}
              max={23}
              value={context.current_hour ?? 0}
              onChange={(e) => set('current_hour', Number(e.target.value))}
              className="w-full h-1.5 bg-slate-700 rounded-full appearance-none cursor-pointer accent-indigo-500"
            />
          </div>

          {/* IP address */}
          <div className="space-y-1">
            <label className="text-xs font-medium text-slate-300">IP Address (optional)</label>
            <input
              type="text"
              value={context.ip_address ?? ''}
              onChange={(e) => set('ip_address', e.target.value)}
              placeholder="192.168.1.1"
              className="w-full bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 font-mono"
            />
          </div>

          {/* Boolean flags */}
          <div className="space-y-2">
            {(
              [
                ['is_new_device', 'New Device'],
                ['email_verified', 'Email Verified'],
                ['vpn_detected', 'VPN Detected'],
                ['tor_detected', 'Tor Detected'],
                ['impossible_travel', 'Impossible Travel'],
              ] as [keyof TestContext, string][]
            ).map(([key, label]) => (
              <div key={key} className="flex items-center justify-between">
                <label className="text-xs text-slate-300">{label}</label>
                <button
                  type="button"
                  role="switch"
                  aria-checked={!!context[key]}
                  onClick={() => set(key, !context[key] as any)}
                  className={clsx(
                    'relative inline-flex h-5 w-9 items-center rounded-full transition-colors focus:outline-none',
                    context[key] ? 'bg-indigo-600' : 'bg-slate-700'
                  )}
                >
                  <span
                    className={clsx(
                      'inline-block h-3.5 w-3.5 transform rounded-full bg-white transition-transform',
                      context[key] ? 'translate-x-4' : 'translate-x-1'
                    )}
                  />
                </button>
              </div>
            ))}
          </div>

          {/* User roles */}
          <div className="space-y-1">
            <label className="text-xs font-medium text-slate-300">User Roles</label>
            <div className="flex flex-wrap gap-1.5 p-2 bg-slate-800 border border-slate-700 rounded-lg min-h-[36px]">
              {(context.user_roles ?? []).map((role) => (
                <span
                  key={role}
                  className="inline-flex items-center gap-1 px-2 py-0.5 bg-indigo-500/20 text-indigo-300 rounded text-xs"
                >
                  {role}
                  <button type="button" onClick={() => removeRole(role)} className="text-indigo-400 hover:text-white">×</button>
                </span>
              ))}
              <input
                type="text"
                value={roleInput}
                onChange={(e) => setRoleInput(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addRole(); } }}
                onBlur={addRole}
                placeholder="add role..."
                className="flex-1 min-w-[80px] bg-transparent text-xs text-slate-100 placeholder-slate-500 focus:outline-none"
              />
            </div>
          </div>

          {/* Custom claims */}
          <div className="space-y-1">
            <label className="text-xs font-medium text-slate-300">Custom Claims (optional)</label>
            <div className="space-y-1">
              {Object.entries(context.custom_claims ?? {}).map(([k, v]) => (
                <div key={k} className="flex items-center gap-2 text-xs">
                  <span className="font-mono text-slate-300 bg-slate-800 px-2 py-0.5 rounded">{k}</span>
                  <span className="text-slate-500">=</span>
                  <span className="font-mono text-slate-300 bg-slate-800 px-2 py-0.5 rounded flex-1 truncate">{v}</span>
                  <button type="button" onClick={() => removeClaim(k)} className="text-slate-500 hover:text-red-400">×</button>
                </div>
              ))}
              <div className="flex gap-1.5">
                <input
                  type="text"
                  value={claimKey}
                  onChange={(e) => setClaimKey(e.target.value)}
                  placeholder="key"
                  className="flex-1 bg-slate-800 border border-slate-700 rounded px-2 py-1 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 font-mono"
                />
                <span className="text-slate-500 self-center text-xs">=</span>
                <input
                  type="text"
                  value={claimVal}
                  onChange={(e) => setClaimVal(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addClaim(); } }}
                  placeholder="value"
                  className="flex-1 bg-slate-800 border border-slate-700 rounded px-2 py-1 text-xs text-slate-100 placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-indigo-500 font-mono"
                />
                <button
                  type="button"
                  onClick={addClaim}
                  className="px-2 py-1 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded text-xs transition-colors"
                >
                  Add
                </button>
              </div>
            </div>
          </div>

          {/* Run button */}
          <button
            type="button"
            onClick={handleRun}
            disabled={running}
            className="w-full flex items-center justify-center gap-2 py-2.5 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white rounded-xl text-sm font-medium transition-colors"
          >
            {running ? (
              <>
                <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Running...
              </>
            ) : (
              <>
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                Run Simulation
              </>
            )}
          </button>
        </div>

        {/* Right: Result */}
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-5">
          <h4 className="text-sm font-semibold text-slate-200 mb-4">Result</h4>

          {error && (
            <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-xl text-sm text-red-400">
              {error}
            </div>
          )}

          {!result && !error && (
            <div className="flex flex-col items-center justify-center h-48 text-center">
              <svg className="w-10 h-10 text-slate-700 mb-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
              </svg>
              <p className="text-slate-500 text-sm">Run a simulation to see results here</p>
            </div>
          )}

          {result && <SimulationResult result={result} />}
        </div>
      </div>
    </div>
  );
}

function SimulationResult({ result }: { result: SimulateResponse }) {
  const decisionConfig = {
    allow: {
      icon: '✅',
      label: 'ALLOW',
      bg: 'bg-emerald-500/10 border-emerald-500/30',
      text: 'text-emerald-400',
      desc: 'This user would be allowed to proceed.',
    },
    deny: {
      icon: '❌',
      label: 'DENY',
      bg: 'bg-red-500/10 border-red-500/30',
      text: 'text-red-400',
      desc: 'This user would be blocked.',
    },
    stepup: {
      icon: '🔐',
      label: 'STEP-UP',
      bg: 'bg-amber-500/10 border-amber-500/30',
      text: 'text-amber-400',
      desc: 'This user would be required to complete additional verification.',
    },
  };

  const dc = decisionConfig[result.decision] ?? decisionConfig.deny;

  return (
    <div className="space-y-4">
      {/* Decision banner */}
      <div className={clsx('p-4 rounded-xl border', dc.bg)}>
        <div className="flex items-center gap-3">
          <span className="text-2xl">{dc.icon}</span>
          <div>
            <p className={clsx('text-lg font-bold', dc.text)}>{dc.label}</p>
            <p className="text-sm text-slate-400">{dc.desc}</p>
          </div>
        </div>
      </div>

      {/* Human explanation */}
      {result.human_explanation.length > 0 && (
        <div className="space-y-1">
          <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Why?</p>
          <ul className="space-y-1">
            {result.human_explanation.map((line, i) => (
              <li key={i} className="text-sm text-slate-300 flex items-start gap-2">
                <span className="text-slate-600 mt-0.5">•</span>
                {line}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Group trace */}
      <div className="space-y-2">
        <p className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Group Trace</p>
        {result.groups_evaluated.map((group) => (
          <div
            key={group.group_id}
            className={clsx(
              'rounded-xl border p-3 space-y-2',
              group.matched
                ? 'border-indigo-500/30 bg-indigo-500/5'
                : 'border-slate-700 bg-slate-800/30'
            )}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className={group.matched ? 'text-indigo-400' : 'text-slate-500'}>
                  {group.matched ? '✓' : '—'}
                </span>
                <span className="text-sm font-medium text-slate-200">{group.display_name}</span>
              </div>
              <span
                className={clsx(
                  'text-xs font-semibold px-2 py-0.5 rounded-full',
                  group.matched
                    ? 'bg-indigo-500/20 text-indigo-300'
                    : 'bg-slate-700 text-slate-400'
                )}
              >
                {group.matched ? `MATCHED → ${group.outcome.toUpperCase()}` : 'NOT MATCHED'}
              </span>
            </div>

            {/* Rule results */}
            <div className="pl-4 space-y-1">
              {group.rules.map((rule) => (
                <div key={rule.rule_id} className="flex items-center gap-2 text-xs">
                  <span className={rule.matched ? 'text-emerald-400' : 'text-slate-600'}>
                    {rule.matched ? '✓' : '✗'}
                  </span>
                  <span className={rule.matched ? 'text-slate-300' : 'text-slate-500'}>
                    {rule.display_name}
                  </span>
                  <span className={clsx('ml-auto', rule.matched ? 'text-emerald-500' : 'text-slate-600')}>
                    {rule.matched ? 'matched' : 'not matched'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}