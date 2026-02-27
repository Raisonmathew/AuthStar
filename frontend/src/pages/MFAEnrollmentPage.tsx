import { useState, useEffect } from 'react';
import { api } from '../lib/api/client';
import { toast } from 'sonner';

interface UserMfaStatus {
    mfaEnabled: boolean;
}

interface MfaSetupResponse {
    qrCodeBase64: string;
    secret: string;
    backupCodes: string[];
}

export default function MFAEnrollmentPage() {
    const [step, setStep] = useState<'setup' | 'verify' | 'complete'>('setup');
    const [qrCode, setQrCode] = useState('');
    const [secret, setSecret] = useState('');
    const [backupCodes, setBackupCodes] = useState<string[]>([]);
    const [verificationCode, setVerificationCode] = useState('');
    const [mfaEnabled, setMfaEnabled] = useState(false);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        checkMfaStatus();
    }, []);

    const checkMfaStatus = async () => {
        try {
            const response = await api.get<UserMfaStatus>('/v1/user');
            setMfaEnabled(response.data.mfaEnabled);
        } catch (error) {
            console.error('Failed to check MFA status:', error);
        } finally {
            setLoading(false);
        }
    };

    const setupMfa = async () => {
        try {
            const response = await api.post<MfaSetupResponse>('/v1/mfa/totp/setup');
            setQrCode(response.data.qrCodeBase64);
            setSecret(response.data.secret);
            setBackupCodes(response.data.backupCodes);
            setStep('verify');
        } catch (error: any) {
            toast.error(error.response?.data?.message || 'Failed to setup MFA');
        }
    };

    const verifyAndEnable = async () => {
        if (!verificationCode.trim()) return;

        try {
            await api.post('/v1/mfa/totp/verify', { code: verificationCode });
            toast.success('MFA enabled successfully!');
            setStep('complete');
            setMfaEnabled(true);
        } catch (error: any) {
            toast.error(error.response?.data?.message || 'Invalid code');
        }
    };

    const disableMfa = async () => {
        if (!confirm('Are you sure you want to disable MFA?')) return;

        try {
            await api.post('/v1/mfa/disable');
            toast.success('MFA disabled');
            setMfaEnabled(false);
            setStep('setup');
        } catch (error: any) {
            toast.error(error.response?.data?.message || 'Failed to disable MFA');
        }
    };

    const copyToClipboard = (text: string) => {
        navigator.clipboard.writeText(text);
        toast.success('Copied to clipboard');
    };

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gradient-to-br from-green-50 to-blue-100 dark:from-gray-900 dark:to-gray-800 py-8">
            <div className="max-w-2xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl overflow-hidden">
                    <div className="p-6 bg-gradient-to-r from-green-500 to-blue-600">
                        <h1 className="text-2xl font-bold text-white">Security Settings</h1>
                        <p className="text-green-100 mt-1">Multi-Factor Authentication (MFA)</p>
                    </div>

                    <div className="p-6">
                        {mfaEnabled && step !== 'setup' ? (
                            <div className="text-center py-8">
                                <div className="w-20 h-20 bg-green-100 dark:bg-green-900/30 rounded-full flex items-center justify-center mx-auto mb-4">
                                    <svg className="w-12 h-12 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                                    </svg>
                                </div>
                                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
                                    MFA is Enabled
                                </h2>
                                <p className="text-gray-600 dark:text-gray-400 mb-6">
                                    Your account is protected with two-factor authentication
                                </p>
                                <button
                                    onClick={disableMfa}
                                    className="px-6 py-2 bg-red-600 hover:bg-red-700 text-white font-medium rounded-lg transition-colors"
                                >
                                    Disable MFA
                                </button>
                            </div>
                        ) : step === 'setup' ? (
                            <div className="text-center py-8">
                                <div className="w-20 h-20 bg-blue-100 dark:bg-blue-900/30 rounded-full flex items-center justify-center mx-auto mb-4">
                                    <svg className="w-12 h-12 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                                    </svg>
                                </div>
                                <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
                                    Enhance Your Security
                                </h2>
                                <p className="text-gray-600 dark:text-gray-400 mb-6">
                                    Add an extra layer of protection to your account with MFA
                                </p>
                                <button
                                    onClick={setupMfa}
                                    className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-colors"
                                >
                                    Enable MFA
                                </button>
                            </div>
                        ) : step === 'verify' ? (
                            <div>
                                <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">
                                    Setup Authenticator App
                                </h2>

                                <div className="mb-6">
                                    <p className="text-gray-600 dark:text-gray-400 mb-4">
                                        Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)
                                    </p>
                                    <div className="bg-white p-4 rounded-lg inline-block">
                                        <img src={`data:image/png;base64,${qrCode}`} alt="QR Code" className="w-64 h-64" />
                                    </div>
                                </div>

                                <div className="mb-6">
                                    <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                                        Or enter this code manually:
                                    </p>
                                    <div className="flex items-center space-x-2">
                                        <code className="flex-1 px-4 py-2 bg-gray-100 dark:bg-gray-700 rounded-lg font-mono text-sm">
                                            {secret}
                                        </code>
                                        <button
                                            onClick={() => copyToClipboard(secret)}
                                            className="p-2 text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded-lg transition-colors"
                                        >
                                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                                            </svg>
                                        </button>
                                    </div>
                                </div>

                                <div className="mb-6">
                                    <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                        Enter the 6-digit code from your app
                                    </label>
                                    <input
                                        type="text"
                                        value={verificationCode}
                                        onChange={(e) => setVerificationCode(e.target.value)}
                                        placeholder="000000"
                                        maxLength={6}
                                        className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:text-white text-center text-2xl tracking-widest"
                                    />
                                </div>

                                <button
                                    onClick={verifyAndEnable}
                                    className="w-full py-3 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-colors"
                                >
                                    Verify and Enable
                                </button>
                            </div>
                        ) : (
                            <div>
                                <div className="text-center mb-6">
                                    <div className="w-20 h-20 bg-green-100 dark:bg-green-900/30 rounded-full flex items-center justify-center mx-auto mb-4">
                                        <svg className="w-12 h-12 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                        </svg>
                                    </div>
                                    <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
                                        MFA Enabled Successfully!
                                    </h2>
                                </div>

                                <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4 mb-6">
                                    <p className="text-sm font-medium text-yellow-800 dark:text-yellow-200 mb-2">
                                        Save your backup codes
                                    </p>
                                    <p className="text-xs text-yellow-700 dark:text-yellow-300 mb-4">
                                        Use these codes if you lose access to your authenticator app. Keep them safe!
                                    </p>
                                    <div className="grid grid-cols-2 gap-2">
                                        {backupCodes.map((code, i) => (
                                            <code key={i} className="px-3 py-2 bg-white dark:bg-gray-800 rounded border border-yellow-300 dark:border-yellow-700 text-sm font-mono">
                                                {code}
                                            </code>
                                        ))}
                                    </div>
                                    <button
                                        onClick={() => copyToClipboard(backupCodes.join('\n'))}
                                        className="mt-4 w-full py-2 bg-yellow-600 hover:bg-yellow-700 text-white font-medium rounded-lg transition-colors"
                                    >
                                        Copy All Codes
                                    </button>
                                </div>
                            </div>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}
