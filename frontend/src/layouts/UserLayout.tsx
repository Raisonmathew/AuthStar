import { useEffect, useState } from 'react';
import { useNavigate, Outlet, useLocation, useOutletContext } from 'react-router-dom';
import { useAuth } from '../features/auth/AuthContext';

export default function UserLayout() {
    const navigate = useNavigate();
    const location = useLocation();
    const { user, isLoading, logout } = useAuth();
    const [showUserMenu, setShowUserMenu] = useState(false);

    const handleSignOut = async () => {
        await logout();
    };

    const isActive = (path: string) => location.pathname === path;

    // Redirect unauthenticated users to the user login portal so the URL
    // does not silently linger on a blank /account/* page. This matches the
    // AdminLayout's behavior for /admin/* routes.
    useEffect(() => {
        if (!isLoading && !user) {
            navigate('/u/default', { replace: true });
        }
    }, [isLoading, user, navigate]);

    if (isLoading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-background">
                <div className="text-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto"></div>
                    <p className="mt-4 text-muted-foreground">Loading...</p>
                </div>
            </div>
        );
    }

    if (!user) return null;

    return (
        <div className="min-h-screen bg-background">
            <nav className="bg-card shadow-sm border-b border-border">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex justify-between items-center h-16">
                        <div className="flex items-center space-x-8">
                            <h1 className="text-xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-purple-600">
                                My Account
                            </h1>

                            <div className="hidden md:flex space-x-1">
                                <button
                                    onClick={() => navigate('/account/profile')}
                                    className={`px-3 py-2 text-sm font-medium rounded-lg transition-colors ${isActive('/account/profile')
                                        ? 'bg-primary/10 text-primary'
                                        : 'text-muted-foreground hover:bg-accent'
                                        }`}
                                >
                                    Profile
                                </button>
                                <button
                                    onClick={() => navigate('/account/security')}
                                    className={`px-3 py-2 text-sm font-medium rounded-lg transition-colors ${isActive('/account/security')
                                        ? 'bg-primary/10 text-primary'
                                        : 'text-muted-foreground hover:bg-accent'
                                        }`}
                                >
                                    Security
                                </button>
                                <button
                                    onClick={() => navigate('/account/delegations')}
                                    className={`px-3 py-2 text-sm font-medium rounded-lg transition-colors ${isActive('/account/delegations')
                                        ? 'bg-primary/10 text-primary'
                                        : 'text-muted-foreground hover:bg-accent'
                                        }`}
                                >
                                    Delegations
                                </button>
                            </div>
                        </div>

                        <div className="flex items-center space-x-4">
                            <div className="relative">
                                <button
                                    onClick={() => setShowUserMenu(!showUserMenu)}
                                    className="flex items-center space-x-3 px-3 py-2 rounded-lg hover:bg-accent transition-colors"
                                >
                                    <div className="w-8 h-8 bg-gradient-to-br from-green-400 to-blue-500 rounded-full flex items-center justify-center text-white font-bold">
                                        {user?.email?.charAt(0).toUpperCase() || 'U'}
                                    </div>
                                    <div className="hidden md:block text-left">
                                        <div className="text-sm font-medium text-foreground">
                                            {user?.first_name && user?.last_name
                                                ? `${user.first_name} ${user.last_name}`
                                                : user?.email?.split('@')[0] || 'User'}
                                        </div>
                                        <div className="text-xs text-muted-foreground">
                                            {user?.email}
                                        </div>
                                    </div>
                                    <svg className="w-4 h-4 text-muted-foreground" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                    </svg>
                                </button>

                                {showUserMenu && (
                                    <div className="absolute right-0 mt-2 w-64 bg-card border border-border rounded-xl shadow-xl z-50">
                                        <div className="p-3 border-b border-border">
                                            <div className="text-sm font-semibold text-foreground">
                                                {user?.first_name && user?.last_name
                                                    ? `${user.first_name} ${user.last_name}`
                                                    : 'Your Account'}
                                            </div>
                                            <div className="text-xs text-muted-foreground mt-1">
                                                {user?.email}
                                            </div>
                                        </div>

                                        <div className="p-2">
                                            <button
                                                onClick={() => { navigate('/account/profile'); setShowUserMenu(false); }}
                                                className="w-full flex items-center space-x-3 px-3 py-2 text-sm text-foreground hover:bg-accent rounded-lg transition-colors"
                                            >
                                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                                                </svg>
                                                <span>Profile Settings</span>
                                            </button>

                                            <button
                                                onClick={() => { navigate('/account/security'); setShowUserMenu(false); }}
                                                className="w-full flex items-center space-x-3 px-3 py-2 text-sm text-foreground hover:bg-accent rounded-lg transition-colors"
                                            >
                                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                                                </svg>
                                                <span>Security & MFA</span>
                                            </button>

                                            <button
                                                onClick={() => { navigate('/account/delegations'); setShowUserMenu(false); }}
                                                className="w-full flex items-center space-x-3 px-3 py-2 text-sm text-foreground hover:bg-accent rounded-lg transition-colors"
                                            >
                                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104c-.251.023-.501.05-.75.082m.75-.082a24.301 24.301 0 014.5 0m0 0v5.714c0 .597.237 1.17.659 1.591L19.8 15.3M14.25 3.104c.251.023.501.05.75.082M19.8 15.3l-1.57.393A9.065 9.065 0 0112 15a9.065 9.065 0 00-6.23-.693L5 14.5m14.8.8l1.402 1.402c1 1 .03 2.698-1.382 2.698H4.18c-1.412 0-2.38-1.698-1.382-2.698L4.2 15.3" />
                                                </svg>
                                                <span>Agent Delegations</span>
                                            </button>

                                            <div className="border-t border-border my-2"></div>

                                            <button
                                                onClick={handleSignOut}
                                                className="w-full flex items-center space-x-3 px-3 py-2 text-sm text-destructive hover:bg-destructive/10 rounded-lg transition-colors"
                                            >
                                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                                                </svg>
                                                <span>Sign Out</span>
                                            </button>
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>
                </div>
            </nav>

            <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
                <Outlet context={{ user }} />
            </main>
        </div>
    );
}

export function useUserContext() {
    const context = useOutletContext<{ user: any }>();
    return context;
}
