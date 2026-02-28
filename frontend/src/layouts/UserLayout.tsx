// STRUCT-2 FIX: Use AuthContext instead of fetching user on every mount and
// calling sessionStorage.clear() on logout.
//
// Previously:
//   - User profile was fetched via authApi.getCurrentUser() on every layout mount
//     (unnecessary API call — AuthContext already has the user from silent refresh)
//   - Logout called sessionStorage.clear() which does NOT clear the in-memory JWT
//     (the user remained authenticated in memory, defeating the AuthContext fix)
//   - The component did not react to auth state changes from other components
//
// Fix:
//   - Read user + isLoading from useAuth() (in-memory, reactive, no extra API call)
//   - Call logout() from useAuth() which clears the in-memory token AND calls the
//     backend to invalidate the HttpOnly refresh cookie
import { useState } from 'react';
import { useNavigate, Outlet, useLocation, useOutletContext } from 'react-router-dom';
import { useAuth } from '../features/auth/AuthContext';
import OrganizationSwitcher from '../components/OrganizationSwitcher';

export default function UserLayout() {
    const navigate = useNavigate();
    const location = useLocation();
    const { user, isLoading, logout } = useAuth();
    const [showUserMenu, setShowUserMenu] = useState(false);

    // STRUCT-2 FIX: logout() from AuthContext clears the in-memory token,
    // calls POST /api/v1/auth/logout to invalidate the HttpOnly refresh cookie,
    // and redirects to the login page. No sessionStorage.clear() needed.
    const handleSignOut = () => {
        logout();
    };

    const isActive = (path: string) => location.pathname === path;

    if (isLoading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
                <div className="text-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
                    <p className="mt-4 text-gray-600 dark:text-gray-400">Loading...</p>
                </div>
            </div>
        );
    }

    // If not loading and no user, AuthContext will redirect to login.
    // Extra safety check in case render happens before redirect.
    if (!user) return null;

    return (
        <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
            <nav className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                    <div className="flex justify-between items-center h-16">
                        {/* Logo */}
                        <div className="flex items-center space-x-8">
                            <h1 className="text-xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-purple-600">
                                IDaaS Platform
                            </h1>

                            {/* Navigation Links */}
                            <div className="hidden md:flex space-x-1">
                                <button
                                    onClick={() => navigate('/dashboard')}
                                    className={`px-3 py-2 text-sm font-medium rounded-lg transition-colors ${isActive('/dashboard')
                                        ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400'
                                        : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                                        }`}
                                >
                                    Dashboard
                                </button>
                                <button
                                    onClick={() => navigate('/team')}
                                    className={`px-3 py-2 text-sm font-medium rounded-lg transition-colors ${isActive('/team')
                                        ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400'
                                        : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                                        }`}
                                >
                                    Team
                                </button>
                                <button
                                    onClick={() => navigate('/security')}
                                    className={`px-3 py-2 text-sm font-medium rounded-lg transition-colors ${isActive('/security')
                                        ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400'
                                        : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                                        }`}
                                >
                                    Security
                                </button>
                                <button
                                    onClick={() => navigate('/billing')}
                                    className={`px-3 py-2 text-sm font-medium rounded-lg transition-colors ${isActive('/billing')
                                        ? 'bg-blue-100 dark:bg-blue-900/30 text-blue-600 dark:text-blue-400'
                                        : 'text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                                        }`}
                                >
                                    Billing
                                </button>
                            </div>
                        </div>

                        {/* Right side: Org Switcher + User Menu */}
                        <div className="flex items-center space-x-4">
                            <OrganizationSwitcher />

                            {/* User Menu */}
                            <div className="relative">
                                <button
                                    onClick={() => setShowUserMenu(!showUserMenu)}
                                    className="flex items-center space-x-3 px-3 py-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                                >
                                    <div className="w-8 h-8 bg-gradient-to-br from-green-400 to-blue-500 rounded-full flex items-center justify-center text-white font-bold">
                                        {user?.email?.charAt(0).toUpperCase() || 'U'}
                                    </div>
                                    <div className="hidden md:block text-left">
                                        <div className="text-sm font-medium text-gray-900 dark:text-white">
                                            {user?.first_name && user?.last_name
                                                ? `${user.first_name} ${user.last_name}`
                                                : user?.email?.split('@')[0] || 'User'}
                                        </div>
                                        <div className="text-xs text-gray-500 dark:text-gray-400">
                                            {user?.email}
                                        </div>
                                    </div>
                                    <svg className="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                                    </svg>
                                </button>

                                {/* Dropdown Menu */}
                                {showUserMenu && (
                                    <div className="absolute right-0 mt-2 w-64 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg shadow-xl z-50">
                                        <div className="p-3 border-b border-gray-200 dark:border-gray-700">
                                            <div className="text-sm font-semibold text-gray-900 dark:text-white">
                                                {user?.first_name && user?.last_name
                                                    ? `${user.first_name} ${user.last_name}`
                                                    : 'Your Account'}
                                            </div>
                                            <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                                                {user?.email}
                                            </div>
                                        </div>

                                        <div className="p-2">
                                            <button
                                                onClick={() => { navigate('/profile'); setShowUserMenu(false); }}
                                                className="w-full flex items-center space-x-3 px-3 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                                            >
                                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                                                </svg>
                                                <span>Profile Settings</span>
                                            </button>

                                            <button
                                                onClick={() => { navigate('/security'); setShowUserMenu(false); }}
                                                className="w-full flex items-center space-x-3 px-3 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                                            >
                                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                                                </svg>
                                                <span>Security & MFA</span>
                                            </button>

                                            <button
                                                onClick={() => { navigate('/api-keys'); setShowUserMenu(false); }}
                                                className="w-full flex items-center space-x-3 px-3 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                                            >
                                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                                                </svg>
                                                <span>API Keys</span>
                                            </button>

                                            <button
                                                onClick={() => { navigate('/billing'); setShowUserMenu(false); }}
                                                className="w-full flex items-center space-x-3 px-3 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                                            >
                                                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />
                                                </svg>
                                                <span>Billing</span>
                                            </button>

                                            <div className="border-t border-gray-200 dark:border-gray-700 my-2"></div>

                                            <button
                                                onClick={handleSignOut}
                                                className="w-full flex items-center space-x-3 px-3 py-2 text-sm text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
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

// Hook for child components to access user from layout
export function useUserContext() {
    const context = useOutletContext<{ user: any }>();
    return context;
}
