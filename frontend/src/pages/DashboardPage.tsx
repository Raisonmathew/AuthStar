import { useNavigate } from 'react-router-dom';
import { useOutletContext } from 'react-router-dom';

interface LayoutContext {
    user: any;
}

export default function DashboardPage() {
    const navigate = useNavigate();
    const { user } = useOutletContext<LayoutContext>();

    return (
        <>
            <div className="mb-8">
                <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
                    Welcome back{user?.firstName ? `, ${user.firstName}` : ''}! 👋
                </h1>
                <p className="text-gray-600 dark:text-gray-400 mt-2">
                    Here's what's happening with your account today.
                </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                <button
                    onClick={() => navigate('/team')}
                    className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow hover:shadow-lg transition-all transform hover:-translate-y-1"
                >
                    <div className="w-12 h-12 bg-blue-100 dark:bg-blue-900/30 rounded-lg flex items-center justify-center mb-4">
                        <svg className="w-6 h-6 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                        </svg>
                    </div>
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                        Team Management
                    </h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                        Invite members and manage roles
                    </p>
                </button>

                <button
                    onClick={() => navigate('/security')}
                    className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow hover:shadow-lg transition-all transform hover:-translate-y-1"
                >
                    <div className="w-12 h-12 bg-green-100 dark:bg-green-900/30 rounded-lg flex items-center justify-center mb-4">
                        <svg className="w-6 h-6 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                        </svg>
                    </div>
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                        Security & MFA
                    </h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                        Enable two-factor authentication
                    </p>
                </button>

                <button
                    onClick={() => navigate('/billing')}
                    className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow hover:shadow-lg transition-all transform hover:-translate-y-1"
                >
                    <div className="w-12 h-12 bg-purple-100 dark:bg-purple-900/30 rounded-lg flex items-center justify-center mb-4">
                        <svg className="w-6 h-6 text-purple-600 dark:text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />
                        </svg>
                    </div>
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                        Billing & Plans
                    </h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                        Manage your subscription
                    </p>
                </button>
            </div>

            {/* Quick Access Cards - Row 2 */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                <button
                    onClick={() => navigate('/api-keys')}
                    className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow hover:shadow-lg transition-all transform hover:-translate-y-1"
                >
                    <div className="w-12 h-12 bg-orange-100 dark:bg-orange-900/30 rounded-lg flex items-center justify-center mb-4">
                        <svg className="w-6 h-6 text-orange-600 dark:text-orange-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                        </svg>
                    </div>
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                        API Keys
                    </h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                        Manage publishable & secret keys
                    </p>
                </button>

                <button
                    onClick={() => navigate('/profile')}
                    className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow hover:shadow-lg transition-all transform hover:-translate-y-1"
                >
                    <div className="w-12 h-12 bg-indigo-100 dark:bg-indigo-900/30 rounded-lg flex items-center justify-center mb-4">
                        <svg className="w-6 h-6 text-indigo-600 dark:text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                        </svg>
                    </div>
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                        Profile Settings
                    </h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                        Update your account information
                    </p>
                </button>
            </div>

            {/* Organization Settings - Row 3 */}
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4">Organization Settings</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                <button
                    onClick={() => navigate('/settings/roles')}
                    className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow hover:shadow-lg transition-all transform hover:-translate-y-1"
                >
                    <div className="w-12 h-12 bg-pink-100 dark:bg-pink-900/30 rounded-lg flex items-center justify-center mb-4">
                        <svg className="w-6 h-6 text-pink-600 dark:text-pink-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
                        </svg>
                    </div>
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                        Roles & Permissions
                    </h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                        Manage access controls and roles
                    </p>
                </button>

                <button
                    onClick={() => navigate('/settings/branding')}
                    className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow hover:shadow-lg transition-all transform hover:-translate-y-1"
                >
                    <div className="w-12 h-12 bg-teal-100 dark:bg-teal-900/30 rounded-lg flex items-center justify-center mb-4">
                        <svg className="w-6 h-6 text-teal-600 dark:text-teal-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 21a4 4 0 01-4-4V5a2 2 0 012-2h4a2 2 0 012 2v12a4 4 0 01-4 4zm0 0h12a2 2 0 002-2v-4a2 2 0 00-2-2h-2.343M11 7.343l1.657-1.657a2 2 0 012.828 0l2.829 2.829a2 2 0 010 2.828l-8.486 8.485M7 17h.01" />
                        </svg>
                    </div>
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
                        Branding & Login
                    </h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400">
                        Customize your login pages
                    </p>
                </button>

                {/* Placeholder for future org settings */}
                <div className="bg-gray-50 dark:bg-gray-800/50 p-6 rounded-lg border-2 border-dashed border-gray-200 dark:border-gray-700 flex flex-col justify-center items-center text-center">
                    <p className="text-gray-400 dark:text-gray-500 font-medium">Coming Soon</p>
                </div>

            </div>

            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
                    <div className="text-sm text-gray-600 dark:text-gray-400 mb-1">Account Status</div>
                    <div className="text-2xl font-bold text-green-600 dark:text-green-400">Active</div>
                </div>

                <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
                    <div className="text-sm text-gray-600 dark:text-gray-400 mb-1">MFA Status</div>
                    <div className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">
                        {user?.mfaEnabled ? 'Enabled' : 'Disabled'}
                    </div>
                </div>

                <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
                    <div className="text-sm text-gray-600 dark:text-gray-400 mb-1">Email Status</div>
                    <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                        {user?.emailVerified ? 'Verified' : 'Unverified'}
                    </div>
                </div>

                <div className="bg-white dark:bg-gray-800 p-6 rounded-lg shadow">
                    <div className="text-sm text-gray-600 dark:text-gray-400 mb-1">Current Plan</div>
                    <div className="text-2xl font-bold text-purple-600 dark:text-purple-400">Free</div>
                </div>
            </div>
        </>
    );
}

