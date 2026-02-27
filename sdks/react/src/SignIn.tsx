```typescript
import React, { useState } from 'react';
import IDaaSClient from '@idaas/client';
import { useIDaaS } from './IDaaSProvider';

export interface SignInProps {
    apiUrl?: string; // Optional - uses IDaaSProvider if not specified
    onSuccess?: (user: any, jwt: string) => void;
    onError?: (error: Error) => void;
    redirectUrl?: string;
    className?: string;
    theme?: 'light' | 'dark';
}

export function SignIn({
    apiUrl: propApiUrl,
    onSuccess,
    onError,
    redirectUrl,
    className = '',
    theme = 'light',
}: SignInProps) {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    // Use context if apiUrl not provided
    const context = propApiUrl ? null : useIDaaS();
    const apiUrl = propApiUrl || context?.config.apiUrl || 'http://localhost:3000';

    const client = new IDaaSClient({ apiUrl });

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        try {
            const response = await client.signIn({ identifier: email, password });

            // Store JWT
            sessionStorage.setItem('jwt', response.jwt);

            if (onSuccess) {
                onSuccess(response.user, response.jwt);
            }

            if (redirectUrl) {
                window.location.href = redirectUrl;
            }
        } catch (err: any) {
            const message = err.response?.data?.message || 'Sign in failed';
            setError(message);
            if (onError) {
                onError(new Error(message));
            }
        } finally {
            setLoading(false);
        }
    };

    const isDark = theme === 'dark';
    const bgColor = isDark ? 'bg-gray-900' : 'bg-gradient-to-br from-blue-50 to-indigo-100';
    const cardBg = isDark ? 'bg-gray-800' : 'bg-white';
    const textColor = isDark ? 'text-white' : 'text-gray-900';
    const textSecondary = isDark ? 'text-gray-400' : 'text-gray-600';
    const inputBg = isDark ? 'bg-gray-700 border-gray-600' : 'bg-white border-gray-300';
    const inputText = isDark ? 'text-white' : 'text-gray-900';

    return (
        <div className={`min - h - screen flex items - center justify - center ${ bgColor } ${ className } `}>
            <div className={`w - full max - w - md p - 8 ${ cardBg } rounded - lg shadow - xl`}>
                <div className="text-center mb-8">
                    <h1 className={`text - 3xl font - bold ${ textColor } `}>
                        Welcome Back
                    </h1>
                    <p className={`${ textSecondary } mt - 2`}>
                        Sign in to your account
                    </p>
                </div>

                <form onSubmit={handleSubmit} className="space-y-6">
                    <div>
                        <label className={`block text - sm font - medium ${ textSecondary } mb - 2`}>
                            Email
                        </label>
                        <input
                            type="email"
                            value={email}
                            onChange={(e) => setEmail(e.target.value)}
                            className={`w - full px - 4 py - 2 border ${ inputBg } ${ inputText } rounded - lg focus: ring - 2 focus: ring - blue - 500 focus: border - transparent`}
                            placeholder="you@example.com"
                            required
                            disabled={loading}
                        />
                    </div>

                    <div>
                        <label className={`block text - sm font - medium ${ textSecondary } mb - 2`}>
                            Password
                        </label>
                        <input
                            type="password"
                            value={password}
                            onChange={(e) => setPassword(e.target.value)}
                            className={`w - full px - 4 py - 2 border ${ inputBg } ${ inputText } rounded - lg focus: ring - 2 focus: ring - blue - 500 focus: border - transparent`}
                            placeholder="••••••••"
                            required
                            disabled={loading}
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
                        className="w-full py-2 px-4 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                        {loading ? 'Signing in...' : 'Sign In'}
                    </button>
                </form>
            </div>
        </div>
    );
}
