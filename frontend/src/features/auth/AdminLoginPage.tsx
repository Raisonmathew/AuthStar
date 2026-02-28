import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../../lib/api';
import { LoginResponse } from './types';
import { toast } from 'sonner';
import { getDeviceSignals } from '../../lib/device';
// CRITICAL-10+11 FIX: Use AuthContext instead of sessionStorage/localStorage
import { useAuth } from './AuthContext';

export default function AdminLoginPage() {
    const navigate = useNavigate();
    const { setAuth } = useAuth();
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [loading, setLoading] = useState(false);

    const handleLogin = async (e: React.FormEvent) => {
        e.preventDefault();
        setLoading(true);

        try {
            // Collect device signals for risk analysis
            const deviceSignals = await getDeviceSignals();

            const res = await api.post<LoginResponse>('/admin/v1/auth/login', {
                email,
                password,
                deviceSignals
            });

            const { token, user } = res.data;

            // CRITICAL-10+11 FIX: Store token in memory via AuthContext.
            // NEVER write to localStorage or sessionStorage.
            // The backend sets an HttpOnly refresh cookie automatically.
            setAuth(token, user);

            toast.success('Welcome back, Admin!');
            navigate('/admin/dashboard');

        } catch (err: unknown) {
            console.error(err);
            const apiError = err as { response?: { data?: { error?: string } } };
            const message = apiError.response?.data?.error || 'Login failed';
            toast.error(message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-900 px-4">
            <div className="max-w-md w-full space-y-8">
                <div>
                    <h2 className="mt-6 text-center text-3xl font-extrabold text-white">
                        Admin Console
                    </h2>
                    <p className="mt-2 text-center text-sm text-gray-400">
                        Sign in to manage your IDaaS platform
                    </p>
                </div>
                <form className="mt-8 space-y-6" onSubmit={handleLogin}>
                    <div className="rounded-md shadow-sm -space-y-px">
                        <div>
                            <input
                                type="email"
                                required
                                className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-700 placeholder-gray-500 text-white bg-gray-800 rounded-t-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                                placeholder="Admin Email"
                                value={email}
                                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setEmail(e.target.value)}
                            />
                        </div>
                        <div>
                            <input
                                type="password"
                                required
                                className="appearance-none rounded-none relative block w-full px-3 py-2 border border-gray-700 placeholder-gray-500 text-white bg-gray-800 rounded-b-md focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 focus:z-10 sm:text-sm"
                                placeholder="Password"
                                value={password}
                                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setPassword(e.target.value)}
                            />
                        </div>
                    </div>

                    <div className="flex items-center justify-between">
                        <div className="text-sm">
                            <a
                                href="/u/admin/reset-password"
                                className="font-medium text-indigo-400 hover:text-indigo-300 transition-colors"
                            >
                                Forgot your password?
                            </a>
                        </div>
                    </div>

                    <div>
                        <button
                            type="submit"
                            disabled={loading}
                            className={`group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white ${loading ? 'bg-indigo-800' : 'bg-indigo-600 hover:bg-indigo-700'
                                } focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500`}
                        >
                            {loading ? 'Signing in...' : 'Sign in'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}
