
// Step-up authentication modal.
//
// Supports four factor types that the step-up route can verify:
//   passkey    — WebAuthn ceremony (no code input)
//   totp       — 6-digit TOTP code from authenticator app
//   email_otp  — 6-digit code sent to user's verified email
//   sms_otp    — 6-digit code sent via SMS (same verification path as email_otp)
//
// For email_otp / sms_otp the flow is two-step:
//   1. "Send code" button → POST /api/v1/auth/step-up/send-otp
//   2. Code input + Verify → POST /api/v1/auth/step-up
//
// Users with NO enrolled factors (no passkey, no TOTP) are shown the email OTP
// option automatically — every user has a verified email in the identities table.

import React, { useState, useEffect } from 'react';
import { startAuthentication } from '@simplewebauthn/browser';
import { toast } from 'sonner';
import { api, getApiError } from '../../lib/api';
import { setInMemoryToken } from '../../lib/auth-storage';
import { Requirement } from '../../lib/types';
import {
    AUTH_STEP_UP_REQUIRED,
    dispatchStepUpComplete,
    dispatchStepUpCancelled,
    StepUpRequiredEvent,
} from '../../lib/events';

type FactorType = 'totp' | 'passkey' | 'email_otp' | 'sms_otp';

interface UserFactor {
    id: string;
    factor_type: FactorType;
    status: string;
}

// Sentinel ID used when we offer email OTP to a user with no enrolled factors.
const EMAIL_OTP_FALLBACK_ID = '__email_otp_fallback__';

function factorLabel(factor_type: FactorType): string {
    switch (factor_type) {
        case 'passkey':   return '🔑 Passkey (phishing-resistant)';
        case 'totp':      return '📱 Authenticator App (TOTP)';
        case 'email_otp': return '📧 Email OTP';
        case 'sms_otp':   return '💬 SMS Code';
    }
}

export default function StepUpModal() {
    const [isOpen, setIsOpen] = useState(false);
    const [factors, setFactors] = useState<UserFactor[]>([]);
    const [selectedFactorId, setSelectedFactorId] = useState<string>('');
    const [code, setCode] = useState('');
    const [loading, setLoading] = useState(false);
    const [verifying, setVerifying] = useState(false);
    const [sending, setSending] = useState(false);
    const [codeSent, setCodeSent] = useState(false);
    const [requirement, setRequirement] = useState<Requirement | undefined>(undefined);

    const selectedFactor = factors.find(f => f.id === selectedFactorId);
    const isPasskey   = selectedFactor?.factor_type === 'passkey';
    const isEmailOtp  = selectedFactor?.factor_type === 'email_otp'
                     || selectedFactor?.factor_type === 'sms_otp';
    const isFallback  = selectedFactorId === EMAIL_OTP_FALLBACK_ID;

    // Reset per-factor state whenever the user switches factor selection.
    useEffect(() => {
        setCode('');
        setCodeSent(false);
    }, [selectedFactorId]);

    useEffect(() => {
        let inFlight = false;

        const handleStepUpRequired = async (e: Event) => {
            if (inFlight) return;
            inFlight = true;
            const event = e as StepUpRequiredEvent;
            setIsOpen(true);
            setLoading(true);
            setCodeSent(false);
            setCode('');
            const req = event.detail.requirement;
            setRequirement(req);

            try {
                const { data } = await api.get<UserFactor[]>('/api/v1/user/factors');
                let available: UserFactor[] = data.filter((f: UserFactor) => f.status === 'active');

                // Phishing-resistant requirement: only passkeys
                if (req?.require_phishing_resistant) {
                    available = available.filter(f => f.factor_type === 'passkey');
                }

                // If no enrolled factors at all, inject the email OTP fallback.
                // Every user has a verified email — they can always step up this way.
                if (available.length === 0 && !req?.require_phishing_resistant) {
                    available = [{
                        id: EMAIL_OTP_FALLBACK_ID,
                        factor_type: 'email_otp',
                        status: 'active',
                    }];
                }

                setFactors(available);
                if (available.length > 0) {
                    setSelectedFactorId(available[0].id);
                }
            } catch (err) {
                console.error('Failed to load factors', err);
                toast.error('Failed to load authentication factors.', {
                    id: 'stepup-load-factors',
                });
            } finally {
                setLoading(false);
                inFlight = false;
            }
        };

        window.addEventListener(AUTH_STEP_UP_REQUIRED, handleStepUpRequired);
        return () => window.removeEventListener(AUTH_STEP_UP_REQUIRED, handleStepUpRequired);
    }, []);

    // ── Send OTP (email_otp / sms_otp) ──────────────────────────────────────
    const handleSendOtp = async () => {
        setSending(true);
        try {
            await api.post('/api/v1/auth/step-up/send-otp', {
                factor_type: 'email_otp',
            });
            setCodeSent(true);
            toast.success('Verification code sent to your email.');
        } catch (err: any) {
            toast.error(getApiError(err, 'Failed to send verification code.'));
        } finally {
            setSending(false);
        }
    };

    // ── TOTP / email OTP code verification ───────────────────────────────────
    const handleCodeVerify = async (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        if (!code) return;

        setVerifying(true);
        try {
            const resp = await api.post<{ token?: string }>('/api/v1/auth/step-up', {
                // For the email OTP fallback there is no real factor_id enrolled,
                // so we send a sentinel that the backend ignores for email_otp path.
                factor_id: isFallback ? '' : selectedFactorId,
                code,
            });
            if (resp?.data?.token) {
                setInMemoryToken(resp.data.token);
            }
            toast.success('Identity verified');
            setIsOpen(false);
            setCode('');
            setCodeSent(false);
            dispatchStepUpComplete();
        } catch (err: any) {
            toast.error(getApiError(err, 'Verification failed'));
        } finally {
            setVerifying(false);
        }
    };

    // ── Passkey WebAuthn ceremony ─────────────────────────────────────────────
    const handlePasskeyVerify = async () => {
        if (!selectedFactorId) return;

        setVerifying(true);
        try {
            const { data: challengeData } = await api.get(
                `/api/v1/auth/step-up/passkey-challenge?factor_id=${encodeURIComponent(selectedFactorId)}`
            );

            const passkeySessionId = (challengeData as any).session_id;
            const challengeOptions =
                (challengeData as any).publicKey?.publicKey ??
                (challengeData as any).publicKey;

            const assertion = await startAuthentication({
                optionsJSON: challengeOptions as Parameters<typeof startAuthentication>[0]['optionsJSON'],
            });

            await api.post('/api/v1/auth/step-up', {
                factor_id: selectedFactorId,
                assertion: { ...assertion, session_id: passkeySessionId },
            });

            toast.success('Passkey verified');
            setIsOpen(false);
            dispatchStepUpComplete();
        } catch (err: any) {
            if (err?.name === 'NotAllowedError') {
                toast.error('Passkey verification was cancelled.');
            } else {
                toast.error(getApiError(err, 'Passkey verification failed'));
            }
        } finally {
            setVerifying(false);
        }
    };

    const handleCancel = () => {
        setIsOpen(false);
        setCode('');
        setCodeSent(false);
        dispatchStepUpCancelled();
        toast.info('Verification cancelled');
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
            <div className="w-full max-w-md bg-card border border-border rounded-xl shadow-2xl p-6">
                {/* Header */}
                <div className="mb-6">
                    <h2 className="text-xl font-bold text-foreground mb-2">
                        Security Verification Required
                    </h2>
                    <p className="text-sm text-muted-foreground">
                        {requirement?.require_phishing_resistant
                            ? 'This action requires a phishing-resistant authentication method (Passkey).'
                            : requirement?.required_assurance
                                ? `This action requires ${requirement.required_assurance} assurance.`
                                : 'This action requires additional authentication. Please verify your identity to continue.'}
                    </p>
                </div>

                {loading ? (
                    <div className="flex justify-center p-8">
                        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
                    </div>
                ) : factors.length === 0 ? (
                    // No factors and phishing-resistant required — nothing we can offer
                    <div className="text-center py-4">
                        <p className="text-yellow-400 mb-4">No authentication factors found.</p>
                        <p className="text-sm text-muted-foreground mb-4">
                            This action requires a passkey or authentication factor. Please enroll a factor to continue.
                        </p>
                        <div className="flex justify-end gap-3">
                            <button
                                onClick={handleCancel}
                                className="px-4 py-2 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
                            >
                                Cancel
                            </button>
                            <a
                                href="/security"
                                className="px-4 py-2 text-sm font-medium bg-primary hover:bg-primary/90 text-primary-foreground rounded-lg transition-colors"
                            >
                                Enroll Passkey
                            </a>
                        </div>
                    </div>
                ) : (
                    <div className="space-y-4">
                        {/* Factor selector — only when multiple options */}
                        {factors.length > 1 && (
                            <div>
                                <label className="block text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1.5">
                                    Select Method
                                </label>
                                <select
                                    value={selectedFactorId}
                                    onChange={(e: React.ChangeEvent<HTMLSelectElement>) => {
                                        setSelectedFactorId(e.target.value);
                                    }}
                                    className="w-full bg-muted border border-border rounded-lg px-3 py-2 text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                                >
                                    {factors.map(f => (
                                        <option key={f.id} value={f.id}>
                                            {factorLabel(f.factor_type)}
                                        </option>
                                    ))}
                                </select>
                            </div>
                        )}

                        {isPasskey ? (
                            // ── Passkey branch ────────────────────────────────
                            <div className="text-center py-4">
                                <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-primary/20 border border-primary/40">
                                    <svg className="h-8 w-8 text-primary" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor">
                                        <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
                                    </svg>
                                </div>
                                <p className="text-sm text-foreground mb-2 font-medium">Use your passkey to verify</p>
                                <p className="text-xs text-muted-foreground mb-6">
                                    Your browser will prompt you to authenticate using your device's biometrics or security key.
                                </p>
                                <div className="flex justify-end gap-3">
                                    <button type="button" onClick={handleCancel} className="px-4 py-2 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">
                                        Cancel
                                    </button>
                                    <button
                                        type="button"
                                        onClick={handlePasskeyVerify}
                                        disabled={verifying}
                                        className="px-4 py-2 text-sm font-medium bg-primary hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed text-primary-foreground rounded-lg transition-colors flex items-center gap-2"
                                    >
                                        {verifying
                                            ? <><div className="animate-spin h-4 w-4 border-2 border-primary-foreground/20 border-t-primary-foreground rounded-full" /> Verifying…</>
                                            : '🔑 Use Passkey'}
                                    </button>
                                </div>
                            </div>
                        ) : isEmailOtp ? (
                            // ── Email / SMS OTP branch ────────────────────────
                            !codeSent ? (
                                <div className="text-center py-4">
                                    <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-primary/20 border border-primary/40">
                                        <svg className="h-8 w-8 text-primary" fill="none" viewBox="0 0 24 24" strokeWidth="1.5" stroke="currentColor">
                                            <path strokeLinecap="round" strokeLinejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75" />
                                        </svg>
                                    </div>
                                    <p className="text-sm text-foreground mb-2 font-medium">Verify via email</p>
                                    <p className="text-xs text-muted-foreground mb-6">
                                        We'll send a 6-digit verification code to your registered email address.
                                    </p>
                                    <div className="flex justify-end gap-3">
                                        <button type="button" onClick={handleCancel} className="px-4 py-2 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">
                                            Cancel
                                        </button>
                                        <button
                                            type="button"
                                            onClick={handleSendOtp}
                                            disabled={sending}
                                            className="px-4 py-2 text-sm font-medium bg-primary hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed text-primary-foreground rounded-lg transition-colors flex items-center gap-2"
                                        >
                                            {sending
                                                ? <><div className="animate-spin h-4 w-4 border-2 border-primary-foreground/20 border-t-primary-foreground rounded-full" /> Sending…</>
                                                : '📧 Send code to email'}
                                        </button>
                                    </div>
                                </div>
                            ) : (
                                <form onSubmit={handleCodeVerify}>
                                    <div className="mb-6">
                                        <label className="block text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1.5">
                                            Verification Code
                                        </label>
                                        <input
                                            type="text"
                                            inputMode="numeric"
                                            value={code}
                                            onChange={e => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                            placeholder="000000"
                                            className="w-full bg-muted border border-border rounded-lg px-3 py-2 text-foreground font-mono tracking-widest text-center text-lg focus:outline-none focus:ring-2 focus:ring-ring"
                                            autoFocus
                                            autoComplete="one-time-code"
                                        />
                                        <p className="mt-1.5 text-xs text-muted-foreground">
                                            Enter the 6-digit code sent to your email.{' '}
                                            <button
                                                type="button"
                                                onClick={() => { setCodeSent(false); setCode(''); }}
                                                className="text-primary hover:underline"
                                            >
                                                Resend
                                            </button>
                                        </p>
                                    </div>
                                    <div className="flex justify-end gap-3">
                                        <button type="button" onClick={handleCancel} className="px-4 py-2 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">
                                            Cancel
                                        </button>
                                        <button
                                            type="submit"
                                            disabled={verifying || code.length !== 6}
                                            className="px-4 py-2 text-sm font-medium bg-primary hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed text-primary-foreground rounded-lg transition-colors flex items-center gap-2"
                                        >
                                            {verifying && <div className="animate-spin h-4 w-4 border-2 border-primary-foreground/20 border-t-primary-foreground rounded-full" />}
                                            Verify
                                        </button>
                                    </div>
                                </form>
                            )
                        ) : (
                            // ── TOTP branch ───────────────────────────────────
                            <form onSubmit={handleCodeVerify}>
                                <div className="mb-6">
                                    <label className="block text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1.5">
                                        Verification Code
                                    </label>
                                    <input
                                        type="text"
                                        inputMode="numeric"
                                        value={code}
                                        onChange={e => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                                        placeholder="000000"
                                        className="w-full bg-muted border border-border rounded-lg px-3 py-2 text-foreground font-mono tracking-widest text-center text-lg focus:outline-none focus:ring-2 focus:ring-ring"
                                        autoFocus
                                        autoComplete="one-time-code"
                                    />
                                    <p className="mt-1.5 text-xs text-muted-foreground">
                                        Enter the 6-digit code from your authenticator app.
                                    </p>
                                </div>
                                <div className="flex justify-end gap-3">
                                    <button type="button" onClick={handleCancel} className="px-4 py-2 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors">
                                        Cancel
                                    </button>
                                    <button
                                        type="submit"
                                        disabled={verifying || code.length !== 6}
                                        className="px-4 py-2 text-sm font-medium bg-primary hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed text-primary-foreground rounded-lg transition-colors flex items-center gap-2"
                                    >
                                        {verifying && <div className="animate-spin h-4 w-4 border-2 border-primary-foreground/20 border-t-primary-foreground rounded-full" />}
                                        Verify
                                    </button>
                                </div>
                            </form>
                        )}
                    </div>
                )}
            </div>
        </div>
    );
}
