/**
 * OAuth 2.0 Consent Page
 *
 * Shown to the user after authenticating via EIAA when an OAuth flow is active.
 * For first-party apps, consent is auto-granted (transparent to user).
 * For third-party apps, user must explicitly approve scope access.
 *
 * Flow:
 * 1. /oauth/authorize stores context in Redis, redirects here via login
 * 2. User completes EIAA auth flow (login page)
 * 3. AuthFlowPage detects oauth_flow_id, redirects to this page
 * 4. This page checks consent status and either auto-redirects or shows prompt
 * 5. On grant/deny, backend issues authorization code and returns redirect URL
 */

import { useEffect, useState, useCallback } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { api } from '../lib/api/client';

interface ConsentInfo {
    consent_required: boolean;
    client_name: string;
    scopes: string[];
    redirect_uri: string;
}

const SCOPE_LABELS: Record<string, { label: string; description: string }> = {
    openid: {
        label: 'OpenID Connect',
        description: 'Verify your identity',
    },
    profile: {
        label: 'Profile',
        description: 'Access your name and profile picture',
    },
    email: {
        label: 'Email',
        description: 'Access your email address',
    },
    offline_access: {
        label: 'Offline Access',
        description: 'Maintain access when you are not present',
    },
};

export default function OAuthConsentPage() {
    const [searchParams] = useSearchParams();
    const navigate = useNavigate();
    const oauthFlowId = searchParams.get('oauth_flow_id');

    const [consentInfo, setConsentInfo] = useState<ConsentInfo | null>(null);
    const [loading, setLoading] = useState(true);
    const [submitting, setSubmitting] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Check consent status
    useEffect(() => {
        if (!oauthFlowId) {
            setError('Missing OAuth flow ID');
            setLoading(false);
            return;
        }

        const checkConsent = async () => {
            try {
                const res = await api.get<ConsentInfo>('/oauth/consent', {
                    params: { oauth_flow_id: oauthFlowId },
                });
                const info: ConsentInfo = res.data;
                setConsentInfo(info);

                // First-party or already consented → auto-grant
                if (!info.consent_required) {
                    await handleGrant(true);
                }
            } catch (err: any) {
                const msg = err?.response?.data?.error_description
                    || err?.response?.data?.message
                    || 'Failed to load consent information';
                setError(msg);
            } finally {
                setLoading(false);
            }
        };

        checkConsent();
    }, [oauthFlowId]); // eslint-disable-line react-hooks/exhaustive-deps

    const handleGrant = useCallback(async (grant: boolean) => {
        if (!oauthFlowId) return;
        setSubmitting(true);
        try {
            const res = await api.post<{ redirect_uri: string }>('/oauth/consent', {
                oauth_flow_id: oauthFlowId,
                grant,
            });

            // Backend returns redirect_uri with code (or error)
            const redirectUri = res.data.redirect_uri;
            if (redirectUri) {
                window.location.href = redirectUri;
            }
        } catch (err: any) {
            setError(err?.response?.data?.message || 'Failed to process consent');
            setSubmitting(false);
        }
    }, [oauthFlowId]);

    // Loading state
    if (loading) {
        return (
            <div className="min-h-screen bg-gray-950 flex items-center justify-center">
                <div className="flex flex-col items-center gap-4">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-500" />
                    <p className="text-gray-400 text-sm">Checking authorization...</p>
                </div>
            </div>
        );
    }

    // Error state
    if (error) {
        return (
            <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4">
                <div className="max-w-md w-full bg-gray-900 rounded-xl p-8 border border-red-800 text-center">
                    <div className="text-red-400 text-4xl mb-4">⚠</div>
                    <h1 className="text-xl font-bold text-white mb-2">Authorization Error</h1>
                    <p className="text-gray-400 text-sm mb-6">{error}</p>
                    <button
                        onClick={() => navigate('/')}
                        className="bg-gray-800 hover:bg-gray-700 text-white px-6 py-2 rounded-lg text-sm font-medium"
                    >
                        Return Home
                    </button>
                </div>
            </div>
        );
    }

    // Consent prompt (only shown for third-party apps)
    if (!consentInfo) return null;

    return (
        <div className="min-h-screen bg-gray-950 flex items-center justify-center p-4">
            <div className="max-w-md w-full bg-gray-900 rounded-xl border border-gray-800 overflow-hidden">
                {/* Header */}
                <div className="px-8 pt-8 pb-4 text-center">
                    <div className="inline-flex items-center justify-center w-16 h-16 bg-indigo-600/20 rounded-2xl mb-4">
                        <svg className="w-8 h-8 text-indigo-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5}
                                d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                        </svg>
                    </div>
                    <h1 className="text-xl font-bold text-white mb-1">Authorize Application</h1>
                    <p className="text-gray-400 text-sm">
                        <span className="text-white font-semibold">{consentInfo.client_name}</span>{' '}
                        wants to access your account
                    </p>
                </div>

                {/* Scope list */}
                <div className="px-8 py-4">
                    <p className="text-gray-500 text-xs uppercase tracking-wider font-medium mb-3">
                        This will allow the application to:
                    </p>
                    <ul className="space-y-3">
                        {consentInfo.scopes.map((scope) => {
                            const info = SCOPE_LABELS[scope] || {
                                label: scope,
                                description: `Access "${scope}" data`,
                            };
                            return (
                                <li key={scope} className="flex items-start gap-3">
                                    <div className="w-5 h-5 mt-0.5 rounded-full bg-green-500/20 flex items-center justify-center flex-shrink-0">
                                        <svg className="w-3 h-3 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={3} d="M5 13l4 4L19 7" />
                                        </svg>
                                    </div>
                                    <div>
                                        <p className="text-white text-sm font-medium">{info.label}</p>
                                        <p className="text-gray-500 text-xs">{info.description}</p>
                                    </div>
                                </li>
                            );
                        })}
                    </ul>
                </div>

                {/* Redirect URI info */}
                <div className="px-8 py-3 bg-gray-800/50">
                    <p className="text-gray-500 text-xs">
                        Authorizing will redirect you to{' '}
                        <span className="text-gray-400 font-mono text-xs">
                            {(() => { try { return new URL(consentInfo.redirect_uri).origin; } catch { return consentInfo.redirect_uri; } })()}
                        </span>
                    </p>
                </div>

                {/* Actions */}
                <div className="px-8 py-6 flex gap-3">
                    <button
                        onClick={() => handleGrant(false)}
                        disabled={submitting}
                        className="flex-1 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 text-white px-4 py-2.5 rounded-lg text-sm font-medium transition-colors"
                    >
                        Deny
                    </button>
                    <button
                        onClick={() => handleGrant(true)}
                        disabled={submitting}
                        className="flex-1 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white px-4 py-2.5 rounded-lg text-sm font-medium transition-colors"
                    >
                        {submitting ? 'Authorizing...' : 'Authorize'}
                    </button>
                </div>
            </div>
        </div>
    );
}
