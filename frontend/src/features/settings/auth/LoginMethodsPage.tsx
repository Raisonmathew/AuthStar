/**
 * Login Methods Configuration Page
 *
 * Admin Console page for configuring organization authentication methods.
 * Changes here trigger policy compilation via PolicyCompiler.
 */

import { useState, useEffect } from 'react';
import { toast } from 'sonner';
import AuthFlowPreview from '../../auth/AuthFlowPreview';
// FIX BUG-6: Use the shared api client (attaches in-memory JWT automatically)
// instead of raw fetch() with localStorage.getItem('admin_token') which is
// always null after the CRITICAL-10+11 fix.
import { api } from '../../../lib/api';

interface MfaConfig {
    required: boolean;
    methods: string[];
}

interface LoginMethodsConfig {
    email_password: boolean;
    passkey: boolean;
    sso: boolean;
    mfa: MfaConfig;
    require_email_verification: boolean;
}

const defaultConfig: LoginMethodsConfig = {
    email_password: true,
    passkey: false,
    sso: false,
    mfa: {
        required: false,
        methods: ['totp'],
    },
    require_email_verification: true,
};

export default function LoginMethodsPage() {
    const [config, setConfig] = useState<LoginMethodsConfig>(defaultConfig);
    const [loading, setLoading] = useState(false);
    const [saving, setSaving] = useState(false);

    // Fetch current config
    useEffect(() => {
        const fetchConfig = async () => {
            setLoading(true);
            try {
                // FIX BUG-6: Use api client (in-memory JWT) instead of fetch + localStorage token
                const res = await api.get<LoginMethodsConfig>('/api/org-config/login-methods');
                setConfig(res.data);
            } catch (error) {
                console.error('Failed to fetch config:', error);
            } finally {
                setLoading(false);
            }
        };
        fetchConfig();
    }, []);

    const handleSave = async () => {
        setSaving(true);
        try {
            // FIX BUG-6: Use api client (in-memory JWT) instead of fetch + localStorage token
            await api.patch('/api/org-config/login-methods', config);
            toast.success('Login methods updated! Policies recompiled.');
        } catch (error: any) {
            toast.error(error?.response?.data?.message || 'Failed to save');
        } finally {
            setSaving(false);
        }
    };

    const toggleMfaMethod = (method: string) => {
        setConfig(prev => ({
            ...prev,
            mfa: {
                ...prev.mfa,
                methods: prev.mfa.methods.includes(method)
                    ? prev.mfa.methods.filter(m => m !== method)
                    : [...prev.mfa.methods, method],
            },
        }));
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary" />
            </div>
        );
    }

    return (
        <div className="max-w-3xl mx-auto p-6">
            <div className="mb-8">
                <h1 className="text-2xl font-bold text-foreground font-heading">
                    Login Methods
                </h1>
                <p className="text-muted-foreground mt-2">
                    Configure how users authenticate to your organization.
                    Changes automatically update the authentication policy.
                </p>
            </div>

            {/* Primary Authentication */}
            <div className="bg-card rounded-xl border border-border p-6 mb-6">
                <h2 className="text-lg font-semibold text-foreground font-heading mb-4">
                    Primary Authentication
                </h2>

                <div className="space-y-4">
                    <div className="flex items-center justify-between p-4 bg-muted/50 rounded-xl min-h-[56px]">
                        <div>
                            <span className="font-medium text-foreground">
                                Email & Password
                            </span>
                            <p className="text-sm text-muted-foreground">
                                Traditional username/password login
                            </p>
                        </div>
                        <button
                            type="button"
                            role="switch"
                            aria-checked={config.email_password}
                            onClick={() => setConfig({ ...config, email_password: !config.email_password })}
                            className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 focus-visible:ring-offset-background ${config.email_password ? 'bg-primary' : 'bg-muted-foreground/30'}`}
                        >
                            <span className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow-lg ring-0 transition-transform duration-200 ease-in-out ${config.email_password ? 'translate-x-5' : 'translate-x-0'}`} />
                        </button>
                    </div>

                    <div className="flex items-center justify-between p-4 bg-muted/50 rounded-xl min-h-[56px]">
                        <div>
                            <span className="font-medium text-foreground">
                                Passkey (WebAuthn)
                            </span>
                            <p className="text-sm text-muted-foreground">
                                Phishing-resistant passwordless authentication
                            </p>
                        </div>
                        <button
                            type="button"
                            role="switch"
                            aria-checked={config.passkey}
                            onClick={() => setConfig({ ...config, passkey: !config.passkey })}
                            className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 focus-visible:ring-offset-background ${config.passkey ? 'bg-primary' : 'bg-muted-foreground/30'}`}
                        >
                            <span className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow-lg ring-0 transition-transform duration-200 ease-in-out ${config.passkey ? 'translate-x-5' : 'translate-x-0'}`} />
                        </button>
                    </div>

                    <div className="flex items-center justify-between p-4 bg-muted/50 rounded-xl min-h-[56px]">
                        <div>
                            <span className="font-medium text-foreground">
                                SSO (Enterprise)
                            </span>
                            <p className="text-sm text-muted-foreground">
                                SAML 2.0 and OIDC federation
                            </p>
                        </div>
                        <button
                            type="button"
                            role="switch"
                            aria-checked={config.sso}
                            onClick={() => setConfig({ ...config, sso: !config.sso })}
                            className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 focus-visible:ring-offset-background ${config.sso ? 'bg-primary' : 'bg-muted-foreground/30'}`}
                        >
                            <span className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow-lg ring-0 transition-transform duration-200 ease-in-out ${config.sso ? 'translate-x-5' : 'translate-x-0'}`} />
                        </button>
                    </div>
                </div>

                {!config.email_password && !config.passkey && !config.sso && (
                    <p className="mt-4 text-sm text-destructive">
                        ⚠️ At least one authentication method must be enabled
                    </p>
                )}
            </div>

            {/* MFA Configuration */}
            <div className="bg-card rounded-xl border border-border p-6 mb-6">
                <h2 className="text-lg font-semibold text-foreground font-heading mb-4">
                    Multi-Factor Authentication (MFA)
                </h2>

                <div className="flex items-center justify-between p-4 bg-muted/50 rounded-xl mb-4 min-h-[56px]">
                    <div>
                        <span className="font-medium text-foreground">
                            Require MFA
                        </span>
                        <p className="text-sm text-muted-foreground">
                            Enforce second factor for all users
                        </p>
                    </div>
                    <button
                        type="button"
                        role="switch"
                        aria-checked={config.mfa.required}
                        onClick={() => setConfig({
                            ...config,
                            mfa: { ...config.mfa, required: !config.mfa.required }
                        })}
                        className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 focus-visible:ring-offset-background ${config.mfa.required ? 'bg-primary' : 'bg-muted-foreground/30'}`}
                    >
                        <span className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow-lg ring-0 transition-transform duration-200 ease-in-out ${config.mfa.required ? 'translate-x-5' : 'translate-x-0'}`} />
                    </button>
                </div>

                {config.mfa.required && (
                    <div className="mt-4">
                        <p className="text-sm font-medium text-foreground mb-3">
                            Allowed MFA Methods:
                        </p>
                        <div className="flex gap-3">
                            <button
                                onClick={() => toggleMfaMethod('totp')}
                                className={`px-4 py-2 rounded-xl border text-sm font-medium transition-colors ${config.mfa.methods.includes('totp')
                                    ? 'bg-primary/10 border-primary text-primary'
                                    : 'bg-muted border-border text-muted-foreground'
                                    }`}
                            >
                                📱 Authenticator App (TOTP)
                            </button>
                            <button
                                onClick={() => toggleMfaMethod('passkey')}
                                className={`px-4 py-2 rounded-xl border text-sm font-medium transition-colors ${config.mfa.methods.includes('passkey')
                                    ? 'bg-primary/10 border-primary text-primary'
                                    : 'bg-muted border-border text-muted-foreground'
                                    }`}
                            >
                                🔑 Security Key
                            </button>
                        </div>
                    </div>
                )}
            </div>

            {/* Signup Configuration */}
            <div className="bg-card rounded-xl border border-border p-6 mb-6">
                <h2 className="text-lg font-semibold text-foreground font-heading mb-4">
                    Signup Settings
                </h2>

                <div className="flex items-center justify-between p-4 bg-muted/50 rounded-xl min-h-[56px]">
                    <div>
                        <span className="font-medium text-foreground">
                            Require Email Verification
                        </span>
                        <p className="text-sm text-muted-foreground">
                            Users must verify email before account is active
                        </p>
                    </div>
                    <button
                        type="button"
                        role="switch"
                        aria-checked={config.require_email_verification}
                        onClick={() => setConfig({ ...config, require_email_verification: !config.require_email_verification })}
                        className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 focus-visible:ring-offset-background ${config.require_email_verification ? 'bg-primary' : 'bg-muted-foreground/30'}`}
                    >
                        <span className={`pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow-lg ring-0 transition-transform duration-200 ease-in-out ${config.require_email_verification ? 'translate-x-5' : 'translate-x-0'}`} />
                    </button>
                </div>
            </div>

            {/* Flow Preview */}
            <div className="mb-6">
                <AuthFlowPreview config={config} flowType="login" />
            </div>
            <div className="mb-6">
                <AuthFlowPreview config={config} flowType="signup" />
            </div>

            {/* EIAA Policy Info */}
            <div className="bg-primary/5 border border-primary/20 rounded-xl p-6 mb-6">
                <h3 className="text-sm font-semibold text-primary mb-2">
                    🔒 EIAA Policy Compilation
                </h3>
                <p className="text-sm text-primary/80">
                    When you save, these settings are compiled into an immutable policy AST.
                    The authentication flow engine executes only this compiled policy,
                    ensuring a single source of truth and full auditability.
                </p>
            </div>

            {/* Save Button */}
            <div className="flex justify-end">
                <button
                    onClick={handleSave}
                    disabled={saving || (!config.email_password && !config.passkey && !config.sso)}
                    className="px-6 py-3 bg-primary text-primary-foreground font-semibold font-heading rounded-xl hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                    {saving ? 'Saving & Compiling Policy...' : 'Save & Compile Policy'}
                </button>
            </div>
        </div>
    );
}
