import React, { useState } from 'react';
import IDaaSClient from '@idaas/client';
import { useIDaaS } from './IDaaSProvider';

export interface SignUpProps {
    apiUrl?: string; // Optional - uses IDaaSProvider if not specified
    onSuccess?: (data: any) => void;
    onError?: (error: Error) => void;
    className?: string;
    theme?: 'light' | 'dark';
    requireEmailVerification?: boolean;
}

export function SignUp({
    apiUrl: propApiUrl,
    onSuccess,
    onError,
    className = '',
    theme = 'light',
    requireEmailVerification = true,
}: SignUpProps) {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [firstName, setFirstName] = useState('');
    const [lastName, setLastName] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [step, setStep] = useState<'form' | 'verify'>('form');
    const [ticketId, setTicketId] = useState('');
    const [verificationCode, setVerificationCode] = useState('');

    // Use context if apiUrl not provided
    const context = propApiUrl ? null : useIDaaS();
    const apiUrl = propApiUrl || context?.config.apiUrl || 'http://localhost:3000';

    const client = new IDaaSClient({ apiUrl });

    const handleSignUp = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        try {
            const response = await client.signUp({ email, password, firstName, lastName });

            if (requireEmailVerification && response.requiresVerification) {
                setTicketId(response.ticketId);
                setStep('verify');
            } else if (onSuccess) {
                onSuccess(response);
            }
        } catch (err: any) {
            const message = err.response?.data?.message || 'Sign up failed';
            setError(message);
            if (onError) {
                onError(new Error(message));
            }
        } finally {
            setLoading(false);
        }
    };

    const handleVerify = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        try {
            await client.verifyEmail({ ticketId, code: verificationCode });
            if (onSuccess) {
                onSuccess({ verified: true });
            }
        } catch (err: any) {
            const message = err.response?.data?.message || 'Verification failed';
            setError(message);
            if (onError) {
                onError(new Error(message));
            }
        } finally {
            setLoading(false);
        }
    };

    const isDark = theme === 'dark';
    const bgColor = isDark ? 'bg-gray-900' : 'bg-gradient-to-br from-purple-50 to-pink-100';
    const cardBg = isDark ? 'bg-gray-800' : 'bg-white';
    const textColor = isDark ? 'text-white' : 'text-gray-900';
    const textSecondary = isDark ? 'text-gray-400' : 'text-gray-600';
    const inputBg = isDark ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-300';
    const inputText = isDark ? 'text-white' : 'text-gray-900';

    return (
        <div className={`min-h-screen flex items-center justify-center ${bgColor} ${className}`}>
            <div className={`w-full max-w-md p-8 ${cardBg} rounded-lg shadow-xl`}>
                <div className="text-center mb-8">
                    <h1 className={`text-3xl font-bold ${textColor}`}>
                        {step === 'form' ? 'Create Account' : 'Verify Email'}
                    </h1>
                    <p className={`${textSecondary} mt-2`}>
                        {step === 'form' ? 'Get started with IDaaS' : 'Enter the code sent to your email'}
                    </p>
                </div>

                {step === 'form' ? (
                    <form onSubmit={handleSignUp} className="space-y-4">
                        <div className="grid grid-cols-2 gap-4">
                            <div>
                                <label className={`block text-sm font-medium ${textSecondary} mb-2`}>
                                    First Name
                                </label>
                                <input
                                    type="text"
                                    value={firstName}
                                    onChange={(e) => setFirstName(e.target.value)}
                                    className={`w-full px-4 py-2 border ${inputBg} ${inputText} rounded-lg focus:ring-2 focus:ring-purple-500`}
                                    placeholder="John"
                                />
                            </div>
                            <div>
                                <label className={`block text-sm font-medium ${textSecondary} mb-2`}>
                                    Last Name
                                </label>
                                <input
                                    type="text"
                                    value={lastName}
                                    onChange={(e) => setLastName(e.target.value)}
                                    className={`w-full px-4 py-2 border ${inputBg} ${inputText} rounded-lg focus:ring-2 focus:ring-purple-500`}
                                    placeholder="Doe"
                                />
                            </div>
                        </div>

                        <div>
                            <label className={`block text-sm font-medium ${textSecondary} mb-2`}>
                                Email
                            </label>
                            <input
                                type="email"
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                className={`w-full px-4 py-2 border ${inputBg} ${inputText} rounded-lg focus:ring-2 focus:ring-purple-500`}
                                placeholder="you@example.com"
                                required
                            />
                        </div>

                        <div>
                            <label className={`block text-sm font-medium ${textSecondary} mb-2`}>
                                Password
                            </label>
                            <input
                                type="password"
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                className={`w-full px-4 py-2 border ${inputBg} ${inputText} rounded-lg focus:ring-2 focus:ring-purple-500`}
                                placeholder="••••••••"
                                required
                            />
                        </div>

                        {error && (
                            <div className="p-3 bg-red-50 border border-red-200 text-red-600 text-sm rounded-lg">
                                {error}
                            </div>
                        )}

                        <button
                            type="submit"
                            disabled={loading}
                            className="w-full py-2 px-4 bg-purple-600 hover:bg-purple-700 text-white font-medium rounded-lg transition-colors disabled:opacity-50"
                        >
                            {loading ? 'Creating account...' : 'Sign Up'}
                        </button>
                    </form>
                ) : (
                    <form onSubmit={handleVerify} className="space-y-6">
                        <div>
                            <label className={`block text-sm font-medium ${textSecondary} mb-2`}>
                                Verification Code
                            </label>
                            <input
                                type="text"
                                value={verificationCode}
                                onChange={(e) => setVerificationCode(e.target.value)}
                                className={`w-full px-4 py-2 border ${inputBg} ${inputText} rounded-lg focus:ring-2 focus:ring-purple-500 text-center text-2xl tracking-widest`}
                                placeholder="000000"
                                maxLength={6}
                                required
                            />
                        </div>

                        {error && (
                            <div className="p-3 bg-red-50 border border-red-200 text-red-600 text-sm rounded-lg">
                                {error}
                            </div>
                        )}

                        <button
                            type="submit"
                            disabled={loading}
                            className="w-full py-2 px-4 bg-purple-600 hover:bg-purple-700 text-white font-medium rounded-lg transition-colors disabled:opacity-50"
                        >
                            {loading ? 'Verifying...' : 'Verify Email'}
                        </button>
                    </form>
                )}
            </div>
        </div>
    );
}
