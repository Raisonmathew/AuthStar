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
        <div className="relative min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-purple-100 dark:from-[#0a0a1a] dark:via-[#0d1033] dark:to-[#1a0a2e] px-4 overflow-hidden">
            {/* Dark mode decorative gradient orbs */}
            <div className="hidden dark:block absolute top-[-20%] left-[-10%] w-[500px] h-[500px] rounded-full bg-blue-600/20 blur-[120px] pointer-events-none" />
            <div className="hidden dark:block absolute bottom-[-15%] right-[-10%] w-[400px] h-[400px] rounded-full bg-purple-600/20 blur-[120px] pointer-events-none" />
            <div className="hidden dark:block absolute top-[30%] right-[5%] w-[250px] h-[250px] rounded-full bg-indigo-500/10 blur-[80px] pointer-events-none" />

            <div className="relative z-10 max-w-md w-full space-y-8 p-6 sm:p-8 bg-white dark:bg-white/[0.05] dark:backdrop-blur-xl rounded-2xl shadow-xl dark:shadow-2xl dark:shadow-blue-500/5 border border-transparent dark:border-white/[0.08]">
                <div>
                    <h2 className="mt-6 text-center text-3xl font-extrabold text-foreground font-heading">
                        Admin Console
                    </h2>
                    <p className="mt-2 text-center text-sm text-muted-foreground">
                        Sign in to manage your IDaaS platform
                    </p>
                </div>
                <form className="mt-8 space-y-6" onSubmit={handleLogin}>
                    <div className="rounded-xl shadow-sm space-y-3">
                        <div>
                            <input
                                type="email"
                                required
                                className="appearance-none relative block w-full px-4 py-3 border border-border dark:border-white/[0.12] placeholder-muted-foreground text-foreground bg-card dark:bg-white/[0.06] rounded-xl focus:outline-none focus:ring-2 focus:ring-ring focus:border-primary sm:text-sm transition-colors"
                                placeholder="Admin Email"
                                value={email}
                                onChange={(e: React.ChangeEvent<HTMLInputElement>) => setEmail(e.target.value)}
                            />
                        </div>
                        <div>
                            <input
                                type="password"
                                required
                                className="appearance-none relative block w-full px-4 py-3 border border-border dark:border-white/[0.12] placeholder-muted-foreground text-foreground bg-card dark:bg-white/[0.06] rounded-xl focus:outline-none focus:ring-2 focus:ring-ring focus:border-primary sm:text-sm transition-colors"
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
                                className="font-medium text-primary hover:text-primary/80 transition-colors"
                            >
                                Forgot your password?
                            </a>
                        </div>
                    </div>

                    <div>
                        <button
                            type="submit"
                            disabled={loading}
                            className={`group relative w-full flex justify-center py-3 px-4 border border-transparent text-sm font-semibold font-heading rounded-xl text-primary-foreground ${loading ? 'bg-primary/60' : 'bg-primary hover:bg-primary/90'
                                } focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-ring transition-colors`}
                        >
                            {loading ? 'Signing in...' : 'Sign in'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}
