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
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
            </div>
        );
    }

    return (
        <div className="max-w-3xl mx-auto p-6">
            <div className="mb-8">
                <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                    Login Methods
                </h1>
                <p className="text-gray-600 dark:text-gray-400 mt-2">
                    Configure how users authenticate to your organization.
                    Changes automatically update the authentication policy.
                </p>
            </div>

            {/* Primary Authentication */}
            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6 mb-6">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                    Primary Authentication
                </h2>

                <div className="space-y-4">
                    <label className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                        <div>
                            <span className="font-medium text-gray-900 dark:text-white">
                                Email & Password
                            </span>
                            <p className="text-sm text-gray-500 dark:text-gray-400">
                                Traditional username/password login
                            </p>
                        </div>
                        <input
                            type="checkbox"
                            checked={config.email_password}
                            onChange={(e) => setConfig({ ...config, email_password: e.target.checked })}
                            className="w-5 h-5 text-blue-600 rounded"
                        />
                    </label>

                    <label className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                        <div>
                            <span className="font-medium text-gray-900 dark:text-white">
                                Passkey (WebAuthn)
                            </span>
                            <p className="text-sm text-gray-500 dark:text-gray-400">
                                Phishing-resistant passwordless authentication
                            </p>
                        </div>
                        <input
                            type="checkbox"
                            checked={config.passkey}
                            onChange={(e) => setConfig({ ...config, passkey: e.target.checked })}
                            className="w-5 h-5 text-blue-600 rounded"
                        />
                    </label>

                    <label className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                        <div>
                            <span className="font-medium text-gray-900 dark:text-white">
                                SSO (Enterprise)
                            </span>
                            <p className="text-sm text-gray-500 dark:text-gray-400">
                                SAML 2.0 and OIDC federation
                            </p>
                        </div>
                        <input
                            type="checkbox"
                            checked={config.sso}
                            onChange={(e) => setConfig({ ...config, sso: e.target.checked })}
                            className="w-5 h-5 text-blue-600 rounded"
                        />
                    </label>
                </div>

                {!config.email_password && !config.passkey && !config.sso && (
                    <p className="mt-4 text-sm text-red-600">
                        ⚠️ At least one authentication method must be enabled
                    </p>
                )}
            </div>

            {/* MFA Configuration */}
            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6 mb-6">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                    Multi-Factor Authentication (MFA)
                </h2>

                <label className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700 rounded-lg mb-4">
                    <div>
                        <span className="font-medium text-gray-900 dark:text-white">
                            Require MFA
                        </span>
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                            Enforce second factor for all users
                        </p>
                    </div>
                    <input
                        type="checkbox"
                        checked={config.mfa.required}
                        onChange={(e) => setConfig({
                            ...config,
                            mfa: { ...config.mfa, required: e.target.checked }
                        })}
                        className="w-5 h-5 text-blue-600 rounded"
                    />
                </label>

                {config.mfa.required && (
                    <div className="mt-4">
                        <p className="text-sm font-medium text-gray-700 dark:text-gray-300 mb-3">
                            Allowed MFA Methods:
                        </p>
                        <div className="flex gap-3">
                            <button
                                onClick={() => toggleMfaMethod('totp')}
                                className={`px-4 py-2 rounded-lg border ${config.mfa.methods.includes('totp')
                                    ? 'bg-blue-100 border-blue-500 text-blue-700'
                                    : 'bg-gray-100 border-gray-300 text-gray-600'
                                    }`}
                            >
                                📱 Authenticator App (TOTP)
                            </button>
                            <button
                                onClick={() => toggleMfaMethod('passkey')}
                                className={`px-4 py-2 rounded-lg border ${config.mfa.methods.includes('passkey')
                                    ? 'bg-blue-100 border-blue-500 text-blue-700'
                                    : 'bg-gray-100 border-gray-300 text-gray-600'
                                    }`}
                            >
                                🔑 Security Key
                            </button>
                        </div>
                    </div>
                )}
            </div>

            {/* Signup Configuration */}
            <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-6 mb-6">
                <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
                    Signup Settings
                </h2>

                <label className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                    <div>
                        <span className="font-medium text-gray-900 dark:text-white">
                            Require Email Verification
                        </span>
                        <p className="text-sm text-gray-500 dark:text-gray-400">
                            Users must verify email before account is active
                        </p>
                    </div>
                    <input
                        type="checkbox"
                        checked={config.require_email_verification}
                        onChange={(e) => setConfig({ ...config, require_email_verification: e.target.checked })}
                        className="w-5 h-5 text-blue-600 rounded"
                    />
                </label>
            </div>

            {/* Flow Preview */}
            <div className="mb-6">
                <AuthFlowPreview config={config} flowType="login" />
            </div>
            <div className="mb-6">
                <AuthFlowPreview config={config} flowType="signup" />
            </div>

            {/* EIAA Policy Info */}
            <div className="bg-blue-50 dark:bg-blue-900/20 rounded-xl p-6 mb-6">
                <h3 className="text-sm font-semibold text-blue-800 dark:text-blue-300 mb-2">
                    🔒 EIAA Policy Compilation
                </h3>
                <p className="text-sm text-blue-700 dark:text-blue-400">
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
                    className="px-6 py-3 bg-blue-600 text-white font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                >
                    {saving ? 'Saving & Compiling Policy...' : 'Save & Compile Policy'}
                </button>
            </div>
        </div>
    );
}
