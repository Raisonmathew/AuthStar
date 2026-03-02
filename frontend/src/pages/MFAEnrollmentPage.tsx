import { useState, useEffect, useCallback } from 'react';
import { api } from '../lib/api/client';
import { useAuth } from '../features/auth/AuthContext';
import { toast } from 'sonner';

// ─── Types ────────────────────────────────────────────────────────────────────

interface MfaStatus {
    totpEnabled: boolean;
    backupCodesEnabled: boolean;
    backupCodesRemaining: number;
}

interface MfaSetupResponse {
    secret: string;
    qrCodeUri: string;
    manualEntryKey: string;
}

interface BackupCodesResponse {
    codes: string[];
    count: number;
    remainingCodes: number;
}

interface Passkey {
    id: string;
    name?: string;
    created_at: string;
    last_used_at?: string;
    aaguid?: string;
}

// ─── WebAuthn Helpers ─────────────────────────────────────────────────────────

function base64urlToUint8Array(base64url: string): ArrayBuffer {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64.padEnd(base64.length + (4 - (base64.length % 4)) % 4, '=');
    const binary = atob(padded);
    const arr = new Uint8Array([...binary].map(c => c.charCodeAt(0)));
    return arr.buffer as ArrayBuffer;
}

function uint8ArrayToBase64url(arr: Uint8Array): string {
    return btoa(String.fromCharCode(...arr))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

// ─── Section Components ───────────────────────────────────────────────────────

// ── TOTP Section ──────────────────────────────────────────────────────────────

interface TotpSectionProps {
    status: MfaStatus;
    onStatusChange: () => void;
}

function TotpSection({ status, onStatusChange }: TotpSectionProps) {
    const [step, setStep] = useState<'idle' | 'setup' | 'verify'>('idle');
    const [setupData, setSetupData] = useState<MfaSetupResponse | null>(null);
    const [code, setCode] = useState('');
    const [loading, setLoading] = useState(false);

    const startSetup = async () => {
        setLoading(true);
        try {
            // MFA routes are mounted at /api/mfa (no /v1/ segment) per router.rs
            const res = await api.post<MfaSetupResponse>('/api/mfa/totp/setup');
            setSetupData(res.data);
            setStep('setup');
        } catch (err: any) {
            toast.error(err.response?.data?.message || 'Failed to start TOTP setup');
        } finally {
            setLoading(false);
        }
    };

    const verifyAndEnable = async () => {
        if (!code.trim() || code.length !== 6) {
            toast.error('Enter the 6-digit code from your authenticator app');
            return;
        }
        setLoading(true);
        try {
            await api.post('/api/mfa/totp/verify', { code });
            toast.success('Authenticator app enabled!');
            setStep('idle');
            setCode('');
            setSetupData(null);
            onStatusChange();
        } catch (err: any) {
            toast.error(err.response?.data?.message || 'Invalid code — try again');
        } finally {
            setLoading(false);
        }
    };

    const disableTotp = async () => {
        if (!confirm('Disable authenticator app? You will need to re-enroll to use TOTP again.')) return;
        setLoading(true);
        try {
            await api.post('/api/mfa/disable');
            toast.success('Authenticator app disabled');
            onStatusChange();
        } catch (err: any) {
            toast.error(err.response?.data?.message || 'Failed to disable TOTP');
        } finally {
            setLoading(false);
        }
    };

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text).then(() => toast.success('Copied!'));
    };

    return (
        <div className="bg-slate-800/50 rounded-2xl border border-slate-700/50 p-6">
            <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                    <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${status.totpEnabled ? 'bg-emerald-500/20' : 'bg-slate-700/50'}`}>
                        <svg className={`w-5 h-5 ${status.totpEnabled ? 'text-emerald-400' : 'text-slate-400'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 18h.01M8 21h8a2 2 0 002-2V5a2 2 0 00-2-2H8a2 2 0 00-2 2v14a2 2 0 002 2z" />
                        </svg>
                    </div>
                    <div>
                        <h3 className="text-base font-bold text-white">Authenticator App (TOTP)</h3>
                        <p className="text-sm text-slate-400">Google Authenticator, Authy, 1Password, etc.</p>
                    </div>
                </div>
                <span className={`text-xs font-medium px-2.5 py-1 rounded-full border ${
                    status.totpEnabled
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                        : 'bg-slate-700/50 text-slate-400 border-slate-600/50'
                }`}>
                    {status.totpEnabled ? 'Enabled' : 'Disabled'}
                </span>
            </div>

            {step === 'idle' && (
                <div className="flex gap-3 mt-4">
                    {status.totpEnabled ? (
                        <button
                            onClick={disableTotp}
                            disabled={loading}
                            className="px-4 py-2 text-sm font-medium text-red-400 bg-red-500/10 hover:bg-red-500/20 border border-red-500/20 rounded-xl transition-colors disabled:opacity-50"
                        >
                            Disable TOTP
                        </button>
                    ) : (
                        <button
                            onClick={startSetup}
                            disabled={loading}
                            className="px-4 py-2 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-500 rounded-xl transition-colors disabled:opacity-50 flex items-center gap-2"
                        >
                            {loading && <div className="animate-spin rounded-full h-3.5 w-3.5 border-b-2 border-white" />}
                            Set up authenticator
                        </button>
                    )}
                </div>
            )}

            {step === 'setup' && setupData && (
                <div className="mt-4 space-y-4">
                    <p className="text-sm text-slate-300">
                        Scan this QR code with your authenticator app, then enter the 6-digit code to confirm.
                    </p>
                    {/* QR Code — backend returns a URI, render as text for now since qrCodeUri is an otpauth:// URI */}
                    <div className="bg-slate-900/50 rounded-xl p-4 border border-slate-700/50">
                        <p className="text-xs text-slate-400 mb-2 font-medium uppercase tracking-wider">Manual entry key</p>
                        <div className="flex items-center gap-2">
                            <code className="flex-1 text-sm font-mono text-indigo-300 break-all">{setupData.manualEntryKey || setupData.secret}</code>
                            <button
                                onClick={() => copyToClipboard(setupData.manualEntryKey || setupData.secret)}
                                className="p-2 text-slate-400 hover:text-white hover:bg-slate-700/50 rounded-lg transition-colors flex-shrink-0"
                                title="Copy"
                            >
                                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                </svg>
                            </button>
                        </div>
                        {setupData.qrCodeUri && (
                            <div className="mt-3">
                                <a
                                    href={setupData.qrCodeUri}
                                    className="text-xs text-indigo-400 hover:text-indigo-300 underline break-all"
                                    title="Open in authenticator app"
                                >
                                    Open in authenticator app →
                                </a>
                            </div>
                        )}
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-slate-300 mb-2">
                            Verification code
                        </label>
                        <input
                            type="text"
                            inputMode="numeric"
                            value={code}
                            onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                            placeholder="000000"
                            maxLength={6}
                            className="w-full px-4 py-3 bg-slate-900/50 border border-slate-700/50 rounded-xl text-white text-center text-2xl tracking-[0.5em] font-mono focus:outline-none focus:ring-2 focus:ring-indigo-500/50 focus:border-indigo-500/50"
                        />
                    </div>

                    <div className="flex gap-3">
                        <button
                            onClick={verifyAndEnable}
                            disabled={loading || code.length !== 6}
                            className="flex-1 py-2.5 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium rounded-xl transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
                        >
                            {loading && <div className="animate-spin rounded-full h-3.5 w-3.5 border-b-2 border-white" />}
                            Verify & Enable
                        </button>
                        <button
                            onClick={() => { setStep('idle'); setSetupData(null); setCode(''); }}
                            className="px-4 py-2.5 text-slate-400 hover:text-white bg-slate-700/50 hover:bg-slate-700 rounded-xl text-sm font-medium transition-colors"
                        >
                            Cancel
                        </button>
                    </div>
                </div>
            )}
        </div>
    );
}

// ── Backup Codes Section ──────────────────────────────────────────────────────

interface BackupCodesSectionProps {
    status: MfaStatus;
}

function BackupCodesSection({ status }: BackupCodesSectionProps) {
    const [codes, setCodes] = useState<string[]>([]);
    const [loading, setLoading] = useState(false);
    const [regenerating, setRegenerating] = useState(false);
    const [showCodes, setShowCodes] = useState(false);

    const fetchCodes = async () => {
        setLoading(true);
        try {
            // POST /api/mfa/backup-codes — returns existing codes
            const res = await api.post<BackupCodesResponse>('/api/mfa/backup-codes');
            setCodes(res.data.codes);
            setShowCodes(true);
        } catch (err: any) {
            toast.error(err.response?.data?.message || 'Failed to load backup codes');
        } finally {
            setLoading(false);
        }
    };

    const regenerateCodes = async () => {
        if (!confirm('Regenerate backup codes? Your existing codes will be invalidated immediately.')) return;
        setRegenerating(true);
        try {
            const res = await api.post<BackupCodesResponse>('/api/mfa/backup-codes');
            setCodes(res.data.codes);
            setShowCodes(true);
            toast.success('New backup codes generated — save them now!');
        } catch (err: any) {
            toast.error(err.response?.data?.message || 'Failed to regenerate backup codes');
        } finally {
            setRegenerating(false);
        }
    };

    const copyAll = () => {
        navigator.clipboard.writeText(codes.join('\n')).then(() => toast.success('All codes copied!'));
    };

    const downloadCodes = () => {
        const blob = new Blob([codes.join('\n')], { type: 'text/plain' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'authstar-backup-codes.txt';
        a.click();
        URL.revokeObjectURL(url);
    };

    return (
        <div className="bg-slate-800/50 rounded-2xl border border-slate-700/50 p-6">
            <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                    <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${status.backupCodesEnabled ? 'bg-amber-500/20' : 'bg-slate-700/50'}`}>
                        <svg className={`w-5 h-5 ${status.backupCodesEnabled ? 'text-amber-400' : 'text-slate-400'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                        </svg>
                    </div>
                    <div>
                        <h3 className="text-base font-bold text-white">Backup Codes</h3>
                        <p className="text-sm text-slate-400">
                            {status.backupCodesEnabled
                                ? `${status.backupCodesRemaining} code${status.backupCodesRemaining !== 1 ? 's' : ''} remaining`
                                : 'One-time codes for account recovery'}
                        </p>
                    </div>
                </div>
                <span className={`text-xs font-medium px-2.5 py-1 rounded-full border ${
                    status.backupCodesEnabled
                        ? 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                        : 'bg-slate-700/50 text-slate-400 border-slate-600/50'
                }`}>
                    {status.backupCodesEnabled ? `${status.backupCodesRemaining} left` : 'None'}
                </span>
            </div>

            {/* Warning if codes are running low */}
            {status.backupCodesEnabled && status.backupCodesRemaining <= 2 && (
                <div className="mb-4 flex items-start gap-2 p-3 bg-amber-500/10 border border-amber-500/20 rounded-xl">
                    <svg className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                    <p className="text-xs text-amber-300">
                        You're running low on backup codes. Regenerate them to ensure account recovery access.
                    </p>
                </div>
            )}

            {showCodes && codes.length > 0 ? (
                <div className="mt-4 space-y-4">
                    <div className="p-4 bg-amber-500/5 border border-amber-500/20 rounded-xl">
                        <p className="text-xs text-amber-300 font-medium mb-3">
                            ⚠ Save these codes now — they won't be shown again
                        </p>
                        <div className="grid grid-cols-2 gap-2">
                            {codes.map((code, i) => (
                                <code key={i} className="px-3 py-2 bg-slate-900/50 border border-slate-700/50 rounded-lg text-sm font-mono text-slate-200 text-center">
                                    {code}
                                </code>
                            ))}
                        </div>
                    </div>
                    <div className="flex gap-2">
                        <button
                            onClick={copyAll}
                            className="flex-1 py-2 text-sm font-medium text-white bg-slate-700/50 hover:bg-slate-700 rounded-xl border border-slate-600/50 transition-colors flex items-center justify-center gap-2"
                        >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                            </svg>
                            Copy all
                        </button>
                        <button
                            onClick={downloadCodes}
                            className="flex-1 py-2 text-sm font-medium text-white bg-slate-700/50 hover:bg-slate-700 rounded-xl border border-slate-600/50 transition-colors flex items-center justify-center gap-2"
                        >
                            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                            </svg>
                            Download
                        </button>
                        <button
                            onClick={() => setShowCodes(false)}
                            className="px-3 py-2 text-slate-400 hover:text-white bg-slate-700/50 hover:bg-slate-700 rounded-xl text-sm transition-colors"
                        >
                            Hide
                        </button>
                    </div>
                </div>
            ) : (
                <div className="flex gap-3 mt-4">
                    <button
                        onClick={fetchCodes}
                        disabled={loading}
                        className="px-4 py-2 text-sm font-medium text-white bg-indigo-600 hover:bg-indigo-500 rounded-xl transition-colors disabled:opacity-50 flex items-center gap-2"
                    >
                        {loading && <div className="animate-spin rounded-full h-3.5 w-3.5 border-b-2 border-white" />}
                        {status.backupCodesEnabled ? 'View codes' : 'Generate codes'}
                    </button>
                    {status.backupCodesEnabled && (
                        <button
                            onClick={regenerateCodes}
                            disabled={regenerating}
                            className="px-4 py-2 text-sm font-medium text-amber-400 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/20 rounded-xl transition-colors disabled:opacity-50 flex items-center gap-2"
                        >
                            {regenerating && <div className="animate-spin rounded-full h-3.5 w-3.5 border-b-2 border-amber-400" />}
                            Regenerate
                        </button>
                    )}
                </div>
            )}
        </div>
    );
}

// ── Passkeys Section ──────────────────────────────────────────────────────────

interface PasskeysSectionProps {
    userEmail: string;
}

function PasskeysSection({ userEmail }: PasskeysSectionProps) {
    const [passkeys, setPasskeys] = useState<Passkey[]>([]);
    const [loading, setLoading] = useState(true);
    const [registering, setRegistering] = useState(false);
    const [deletingId, setDeletingId] = useState<string | null>(null);
    const [newKeyName, setNewKeyName] = useState('');
    const [showNameInput, setShowNameInput] = useState(false);

    const loadPasskeys = useCallback(async () => {
        try {
            // Passkeys management routes are at /api/passkeys (no /v1/) per router.rs
            const res = await api.get<Passkey[]>('/api/passkeys/');
            setPasskeys(res.data);
        } catch (err: any) {
            if (err?.response?.status !== 404) {
                toast.error('Failed to load passkeys');
            }
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        loadPasskeys();
    }, [loadPasskeys]);

    const registerPasskey = async () => {
        if (!window.PublicKeyCredential) {
            toast.error('Your browser does not support passkeys');
            return;
        }

        setRegistering(true);
        try {
            // Step 1: Get registration challenge from server
            const startRes = await api.post<{
                session_id: string;
                options: PublicKeyCredentialCreationOptions;
            }>('/api/passkeys/register/start', { email: userEmail });

            const { session_id, options } = startRes.data;

            // Decode base64url fields for WebAuthn API
            const publicKeyOptions: PublicKeyCredentialCreationOptions = {
                ...options,
                challenge: base64urlToUint8Array(options.challenge as unknown as string),
                user: {
                    ...options.user,
                    id: base64urlToUint8Array(options.user.id as unknown as string),
                },
                excludeCredentials: options.excludeCredentials?.map(c => ({
                    ...c,
                    id: base64urlToUint8Array(c.id as unknown as string),
                })),
            };

            // Step 2: Invoke browser WebAuthn API
            const credential = await navigator.credentials.create({ publicKey: publicKeyOptions }) as PublicKeyCredential;
            if (!credential) throw new Error('No credential returned');

            const response = credential.response as AuthenticatorAttestationResponse;

            // Step 3: Send attestation to server
            await api.post('/api/passkeys/register/finish', {
                session_id,
                name: newKeyName.trim() || undefined,
                response: {
                    id: credential.id,
                    rawId: uint8ArrayToBase64url(new Uint8Array(credential.rawId)),
                    type: credential.type,
                    response: {
                        clientDataJSON: uint8ArrayToBase64url(new Uint8Array(response.clientDataJSON)),
                        attestationObject: uint8ArrayToBase64url(new Uint8Array(response.attestationObject)),
                    },
                },
            });

            toast.success('Passkey registered successfully!');
            setShowNameInput(false);
            setNewKeyName('');
            loadPasskeys();
        } catch (err: any) {
            if (err?.name === 'NotAllowedError') {
                toast.error('Passkey registration was cancelled');
            } else if (err?.name === 'InvalidStateError') {
                toast.error('A passkey for this device is already registered');
            } else {
                toast.error(err?.response?.data?.message || err?.message || 'Failed to register passkey');
            }
        } finally {
            setRegistering(false);
        }
    };

    const deletePasskey = async (id: string) => {
        if (!confirm('Remove this passkey? You will no longer be able to sign in with it.')) return;
        setDeletingId(id);
        try {
            await api.delete(`/api/passkeys/${id}`);
            toast.success('Passkey removed');
            setPasskeys(prev => prev.filter(p => p.id !== id));
        } catch (err: any) {
            toast.error(err?.response?.data?.message || 'Failed to remove passkey');
        } finally {
            setDeletingId(null);
        }
    };

    const formatDate = (iso: string) => new Date(iso).toLocaleDateString(undefined, {
        month: 'short', day: 'numeric', year: 'numeric',
    });

    return (
        <div className="bg-slate-800/50 rounded-2xl border border-slate-700/50 p-6">
            <div className="flex items-start justify-between mb-4">
                <div className="flex items-center gap-3">
                    <div className={`w-10 h-10 rounded-xl flex items-center justify-center ${passkeys.length > 0 ? 'bg-indigo-500/20' : 'bg-slate-700/50'}`}>
                        <svg className={`w-5 h-5 ${passkeys.length > 0 ? 'text-indigo-400' : 'text-slate-400'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 11c0 3.517-1.009 6.799-2.753 9.571m-3.44-2.04l.054-.09A13.916 13.916 0 008 11a4 4 0 118 0c0 1.017-.07 2.019-.203 3m-2.118 6.844A21.88 21.88 0 0015.171 17m3.839 1.132c.645-2.266.99-4.659.99-7.132A8 8 0 008 4.07M3 15.364c.64-1.319 1-2.8 1-4.364 0-1.457.39-2.823 1.07-4" />
                        </svg>
                    </div>
                    <div>
                        <h3 className="text-base font-bold text-white">Passkeys</h3>
                        <p className="text-sm text-slate-400">
                            {passkeys.length > 0
                                ? `${passkeys.length} passkey${passkeys.length !== 1 ? 's' : ''} registered`
                                : 'Sign in with Face ID, Touch ID, or hardware key'}
                        </p>
                    </div>
                </div>
                <span className={`text-xs font-medium px-2.5 py-1 rounded-full border ${
                    passkeys.length > 0
                        ? 'bg-indigo-500/10 text-indigo-400 border-indigo-500/20'
                        : 'bg-slate-700/50 text-slate-400 border-slate-600/50'
                }`}>
                    {passkeys.length} registered
                </span>
            </div>

            {/* Passkey list */}
            {loading ? (
                <div className="space-y-3 mt-4">
                    {[...Array(2)].map((_, i) => (
                        <div key={i} className="h-14 bg-slate-700/30 rounded-xl animate-pulse" />
                    ))}
                </div>
            ) : passkeys.length > 0 ? (
                <div className="mt-4 space-y-2">
                    {passkeys.map((pk) => (
                        <div key={pk.id} className="flex items-center justify-between p-3 bg-slate-900/30 rounded-xl border border-slate-700/30 group">
                            <div className="flex items-center gap-3">
                                <div className="w-8 h-8 rounded-lg bg-indigo-500/10 flex items-center justify-center">
                                    <svg className="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                                    </svg>
                                </div>
                                <div>
                                    <p className="text-sm font-medium text-white">{pk.name || 'Passkey'}</p>
                                    <p className="text-xs text-slate-500">
                                        Added {formatDate(pk.created_at)}
                                        {pk.last_used_at && ` · Last used ${formatDate(pk.last_used_at)}`}
                                    </p>
                                </div>
                            </div>
                            <button
                                onClick={() => deletePasskey(pk.id)}
                                disabled={deletingId === pk.id}
                                className="p-1.5 text-slate-500 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors opacity-0 group-hover:opacity-100 disabled:opacity-50"
                                title="Remove passkey"
                            >
                                {deletingId === pk.id ? (
                                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-red-400" />
                                ) : (
                                    <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                    </svg>
                                )}
                            </button>
                        </div>
                    ))}
                </div>
            ) : null}

            {/* Add passkey */}
            <div className="mt-4">
                {showNameInput ? (
                    <div className="flex gap-2">
                        <input
                            type="text"
                            value={newKeyName}
                            onChange={(e) => setNewKeyName(e.target.value)}
                            placeholder="Name this passkey (optional)"
                            className="flex-1 px-3 py-2 bg-slate-900/50 border border-slate-700/50 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
                            onKeyDown={(e) => e.key === 'Enter' && registerPasskey()}
                            autoFocus
                        />
                        <button
                            onClick={registerPasskey}
                            disabled={registering}
                            className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium rounded-xl transition-colors disabled:opacity-50 flex items-center gap-2"
                        >
                            {registering && <div className="animate-spin rounded-full h-3.5 w-3.5 border-b-2 border-white" />}
                            Register
                        </button>
                        <button
                            onClick={() => { setShowNameInput(false); setNewKeyName(''); }}
                            className="px-3 py-2 text-slate-400 hover:text-white bg-slate-700/50 rounded-xl text-sm transition-colors"
                        >
                            Cancel
                        </button>
                    </div>
                ) : (
                    <button
                        onClick={() => setShowNameInput(true)}
                        className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-indigo-300 bg-indigo-500/10 hover:bg-indigo-500/20 border border-indigo-500/20 rounded-xl transition-colors"
                    >
                        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                        </svg>
                        Add passkey
                    </button>
                )}
            </div>
        </div>
    );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function MFAEnrollmentPage() {
    const { user } = useAuth();
    const [status, setStatus] = useState<MfaStatus | null>(null);
    const [loading, setLoading] = useState(true);

    const loadStatus = useCallback(async () => {
        try {
            // GET /api/mfa/status — returns totpEnabled, backupCodesEnabled, backupCodesRemaining
            const res = await api.get<MfaStatus>('/api/mfa/status');
            setStatus(res.data);
        } catch (err: any) {
            // Fallback: try to infer from /api/v1/user
            try {
                const userRes = await api.get<{ mfaEnabled?: boolean }>('/api/v1/user');
                setStatus({
                    totpEnabled: userRes.data.mfaEnabled ?? false,
                    backupCodesEnabled: false,
                    backupCodesRemaining: 0,
                });
            } catch {
                toast.error('Failed to load security status');
            }
        } finally {
            setLoading(false);
        }
    }, []);

    useEffect(() => {
        loadStatus();
    }, [loadStatus]);

    if (loading) {
        return (
            <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 flex items-center justify-center">
                <div className="animate-spin rounded-full h-10 w-10 border-b-2 border-indigo-500" />
            </div>
        );
    }

    const defaultStatus: MfaStatus = {
        totpEnabled: false,
        backupCodesEnabled: false,
        backupCodesRemaining: 0,
    };
    const mfaStatus = status ?? defaultStatus;

    // Overall security score
    const securityScore = [
        mfaStatus.totpEnabled,
        mfaStatus.backupCodesEnabled,
    ].filter(Boolean).length;

    return (
        <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 py-8">
            <div className="max-w-2xl mx-auto px-4 sm:px-6">

                {/* Header */}
                <div className="mb-8">
                    <div className="flex items-center gap-3 mb-2">
                        <div className="w-10 h-10 rounded-xl bg-indigo-500/20 flex items-center justify-center">
                            <svg className="w-5 h-5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                            </svg>
                        </div>
                        <div>
                            <h1 className="text-2xl font-bold text-white">Security Settings</h1>
                            <p className="text-slate-400 text-sm">Manage your authentication methods</p>
                        </div>
                    </div>

                    {/* Security score bar */}
                    <div className="mt-4 p-4 bg-slate-800/50 rounded-2xl border border-slate-700/50">
                        <div className="flex items-center justify-between mb-2">
                            <span className="text-sm font-medium text-slate-300">Security level</span>
                            <span className={`text-sm font-bold ${
                                securityScore === 2 ? 'text-emerald-400' :
                                securityScore === 1 ? 'text-amber-400' : 'text-red-400'
                            }`}>
                                {securityScore === 2 ? 'Strong' : securityScore === 1 ? 'Moderate' : 'Basic'}
                            </span>
                        </div>
                        <div className="h-2 bg-slate-700/50 rounded-full overflow-hidden">
                            <div
                                className={`h-full rounded-full transition-all duration-500 ${
                                    securityScore === 2 ? 'bg-emerald-500 w-full' :
                                    securityScore === 1 ? 'bg-amber-500 w-1/2' : 'bg-red-500 w-1/4'
                                }`}
                            />
                        </div>
                        <p className="text-xs text-slate-500 mt-2">
                            {securityScore === 2
                                ? 'Your account is well protected with multiple authentication factors.'
                                : securityScore === 1
                                ? 'Add backup codes or a passkey to further secure your account.'
                                : 'Enable an authenticator app or passkey to protect your account.'}
                        </p>
                    </div>
                </div>

                {/* Security sections */}
                <div className="space-y-4">
                    <TotpSection status={mfaStatus} onStatusChange={loadStatus} />
                    <BackupCodesSection status={mfaStatus} />
                    <PasskeysSection userEmail={user?.email ?? ''} />
                </div>
            </div>
        </div>
    );
}
