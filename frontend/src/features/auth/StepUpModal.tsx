
// STRUCT-3 FIX: Implement proper passkey (WebAuthn) ceremony for step-up auth.
//
// Previously, the modal showed a TOTP code input for ALL factor types, including
// passkeys. Passkeys cannot be verified by typing a code — they require a full
// WebAuthn authentication ceremony:
//   1. GET /api/v1/auth/step-up/passkey-challenge  → server returns PublicKeyCredentialRequestOptions
//   2. navigator.credentials.get(options)          → browser prompts user for biometric/PIN
//   3. POST /api/v1/auth/step-up                   → send the assertion (not a code)
//
// The old handleVerify guard `if (!code) return` also blocked passkeys entirely.
//
// Fix:
//   - Derive `selectedFactor` from `selectedFactorId` to know the type
//   - For 'passkey': show a "Use Passkey" button that triggers the WebAuthn ceremony
//   - For 'totp': keep the existing 6-digit code input
//   - handleVerify is split: TOTP submits via form, passkey uses handlePasskeyVerify
//   - Uses @simplewebauthn/browser (already in package.json) for the ceremony

import React, { useState, useEffect } from 'react';
import { startAuthentication } from '@simplewebauthn/browser';
import { toast } from 'sonner';
import { api } from '../../lib/api';
import { setInMemoryToken } from '../../lib/auth-storage';
import { Requirement } from '../../lib/types';
import { AUTH_STEP_UP_REQUIRED, dispatchStepUpComplete, dispatchStepUpCancelled, StepUpRequiredEvent } from '../../lib/events';
// Note: AUTH_STEP_UP_COMPLETE and AUTH_STEP_UP_CANCELLED are not imported here —
// we use the dispatch helpers (dispatchStepUpComplete / dispatchStepUpCancelled) instead.

interface UserFactor {
    id: string;
    factor_type: 'totp' | 'passkey';
    status: string;
}

export default function StepUpModal() {
    const [isOpen, setIsOpen] = useState(false);
    const [factors, setFactors] = useState<UserFactor[]>([]);
    const [selectedFactorId, setSelectedFactorId] = useState<string>('');
    const [code, setCode] = useState('');
    const [loading, setLoading] = useState(false);
    const [verifying, setVerifying] = useState(false);
    const [requirement, setRequirement] = useState<Requirement | undefined>(undefined);

    // Derive the currently selected factor object so we can branch on factor_type
    const selectedFactor = factors.find(f => f.id === selectedFactorId);
    const isPasskey = selectedFactor?.factor_type === 'passkey';

    useEffect(() => {
        const handleStepUpRequired = async (e: Event) => {
            const event = e as StepUpRequiredEvent;
            setIsOpen(true);
            setLoading(true);
            const req = event.detail.requirement;
            setRequirement(req);

            try {
                // /api/v1/user/factors is intentionally allowed at AAL1 so the user
                // can select which factor to use for the step-up ceremony.
                const { data } = await api.get<UserFactor[]>('/api/v1/user/factors');

                let availableFactors: UserFactor[] = data.filter((f: UserFactor) => f.status === 'active');

                // If the requirement demands phishing-resistant auth, only show passkeys.
                if (req?.require_phishing_resistant) {
                    availableFactors = availableFactors.filter((f: UserFactor) => f.factor_type === 'passkey');
                }

                setFactors(availableFactors);
                if (availableFactors.length > 0) {
                    setSelectedFactorId(availableFactors[0].id);
                }
            } catch (err) {
                console.error("Failed to load factors", err);
                toast.error("Failed to load authentication factors.");
            } finally {
                setLoading(false);
            }
        };

        window.addEventListener(AUTH_STEP_UP_REQUIRED, handleStepUpRequired);
        return () => window.removeEventListener(AUTH_STEP_UP_REQUIRED, handleStepUpRequired);
    }, []);

    // -------------------------------------------------------------------------
    // TOTP verification — submits the 6-digit code via form POST
    // -------------------------------------------------------------------------
    const handleTotpVerify = async (e: React.FormEvent<HTMLFormElement>) => {
        e.preventDefault();
        if (!selectedFactorId || !code) return;

        setVerifying(true);
        try {
            // Backend returns { token, aal_level, provisional } on success;
            // swap the in-memory JWT so subsequent requests carry the
            // non-provisional token bound to the upgraded session.
            const resp = await api.post<{ token?: string }>('/api/v1/auth/step-up', {
                factor_id: selectedFactorId,
                code,
            });
            if (resp?.data?.token) {
                setInMemoryToken(resp.data.token);
            }

            toast.success("Identity verified");
            setIsOpen(false);
            setCode('');
            dispatchStepUpComplete();
        } catch (err: any) {
            console.error("TOTP verification failed", err);
            toast.error(err.response?.data?.message ?? err.response?.data ?? "Verification failed");
        } finally {
            setVerifying(false);
        }
    };

    // -------------------------------------------------------------------------
    // Passkey verification — full WebAuthn authentication ceremony
    //
    // Flow:
    //   1. GET /api/v1/auth/step-up/passkey-challenge?factor_id=<id>
    //      → server creates a challenge, stores it in Redis, returns
    //        PublicKeyCredentialRequestOptionsJSON
    //   2. startAuthentication(options) — @simplewebauthn/browser
    //      → browser invokes the platform authenticator (Touch ID, Face ID, etc.)
    //      → returns AuthenticationResponseJSON
    //   3. POST /api/v1/auth/step-up  { factor_id, assertion: <response> }
    //      → server verifies the assertion against the stored challenge
    //      → on success, upgrades the session AAL to AAL2
    // -------------------------------------------------------------------------
    const handlePasskeyVerify = async () => {
        if (!selectedFactorId) return;

        setVerifying(true);
        try {
            // Step 1: Fetch the WebAuthn challenge from the server.
            // Server returns { session_id, publicKey: PublicKeyCredentialRequestOptionsJSON }
            const { data: challengeData } = await api.get(
                `/api/v1/auth/step-up/passkey-challenge?factor_id=${encodeURIComponent(selectedFactorId)}`
            );

            const passkeySessionId = (challengeData as any).session_id;
            const challengeOptions = (challengeData as any).publicKey?.publicKey ?? (challengeData as any).publicKey;

            // Step 2: Run the WebAuthn ceremony in the browser.
            // @simplewebauthn/browser v13: startAuthentication takes { optionsJSON }.
            // The server wraps options in a `publicKey` field (webauthn-rs convention).
            const assertion = await startAuthentication({
                optionsJSON: challengeOptions as Parameters<typeof startAuthentication>[0]['optionsJSON'],
            });

            // Step 3: Send the assertion to the server for verification.
            // Include the passkey session_id so the backend can retrieve the
            // stored challenge from Redis.
            await api.post('/api/v1/auth/step-up', {
                factor_id: selectedFactorId,
                assertion: { ...assertion, session_id: passkeySessionId },
            });

            toast.success("Passkey verified");
            setIsOpen(false);
            dispatchStepUpComplete();
        } catch (err: any) {
            // NotAllowedError = user cancelled the browser prompt
            if (err?.name === 'NotAllowedError') {
                toast.error("Passkey verification was cancelled.");
            } else {
                console.error("Passkey verification failed", err);
                toast.error(err.response?.data?.message ?? err.message ?? "Passkey verification failed");
            }
        } finally {
            setVerifying(false);
        }
    };

    const handleCancel = () => {
        setIsOpen(false);
        setCode('');
        dispatchStepUpCancelled();
        toast.info("Verification cancelled");
    };

    if (!isOpen) return null;

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
            <div className="w-full max-w-md bg-card border border-border rounded-xl shadow-2xl p-6">
                <div className="mb-6">
                    <h2 className="text-xl font-bold text-foreground mb-2">Security Verification Required</h2>
                    <p className="text-sm text-muted-foreground">
                        {requirement?.required_assurance
                            ? `This action requires ${requirement.required_assurance} assurance.`
                            : requirement?.require_phishing_resistant
                                ? "This action requires a phishing-resistant authentication method (e.g. Passkey)."
                                : "This action requires additional authentication. Please verify your identity to continue."
                        }
                    </p>
                </div>

                {loading ? (
                    <div className="flex justify-center p-8">
                        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
                    </div>
                ) : factors.length === 0 ? (
                    <div className="text-center py-4">
                        <p className="text-yellow-400 mb-4">No authentication factors found.</p>
                        <p className="text-sm text-muted-foreground mb-4">You need to enroll in MFA to perform this action.</p>
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
                                Enroll MFA
                            </a>
                        </div>
                    </div>
                ) : (
                    <div className="space-y-4">
                        {/* Factor selector — only shown when multiple factors are available */}
                        {factors.length > 1 && (
                            <div>
                                <label className="block text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1.5">
                                    Select Method
                                </label>
                                <select
                                    value={selectedFactorId}
                                    onChange={(e: React.ChangeEvent<HTMLSelectElement>) => { setSelectedFactorId(e.target.value); setCode(''); }}
                                    className="w-full bg-muted border border-border rounded-lg px-3 py-2 text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                                >
                                    {factors.map((f: UserFactor) => (
                                        <option key={f.id} value={f.id}>
                                            {f.factor_type === 'passkey' ? '🔑 Passkey (phishing-resistant)' : '📱 Authenticator App (TOTP)'}
                                        </option>
                                    ))}
                                </select>
                            </div>
                        )}

                        {isPasskey ? (
                            // -------------------------------------------------------
                            // PASSKEY BRANCH: WebAuthn ceremony — no code input needed
                            // -------------------------------------------------------
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
                                    <button
                                        type="button"
                                        onClick={handleCancel}
                                        className="px-4 py-2 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
                                    >
                                        Cancel
                                    </button>
                                    <button
                                        type="button"
                                        onClick={handlePasskeyVerify}
                                        disabled={verifying}
                                        className="px-4 py-2 text-sm font-medium bg-primary hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed text-primary-foreground rounded-lg transition-colors flex items-center gap-2"
                                    >
                                        {verifying
                                            ? <><div className="animate-spin h-4 w-4 border-2 border-primary-foreground/20 border-t-primary-foreground rounded-full"></div> Verifying...</>
                                            : '🔑 Use Passkey'
                                        }
                                    </button>
                                </div>
                            </div>
                        ) : (
                            // -------------------------------------------------------
                            // TOTP BRANCH: 6-digit code input
                            // -------------------------------------------------------
                            <form onSubmit={handleTotpVerify}>
                                <div className="mb-6">
                                    <label className="block text-xs font-medium text-muted-foreground uppercase tracking-wider mb-1.5">
                                        Verification Code
                                    </label>
                                    <input
                                        type="text"
                                        inputMode="numeric"
                                        value={code}
                                        onChange={(e) => setCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
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
                                    <button
                                        type="button"
                                        onClick={handleCancel}
                                        className="px-4 py-2 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
                                    >
                                        Cancel
                                    </button>
                                    <button
                                        type="submit"
                                        disabled={verifying || code.length !== 6}
                                        className="px-4 py-2 text-sm font-medium bg-primary hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed text-primary-foreground rounded-lg transition-colors flex items-center gap-2"
                                    >
                                        {verifying && <div className="animate-spin h-4 w-4 border-2 border-primary-foreground/20 border-t-primary-foreground rounded-full"></div>}
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
