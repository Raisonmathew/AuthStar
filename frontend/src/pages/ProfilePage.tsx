import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../lib/api/client';
import { toast } from 'sonner';

interface User {
    id: string;
    email: string;
    firstName?: string;
    lastName?: string;
    emailVerified: boolean;
    mfaEnabled: boolean;
}

export default function ProfilePage() {
    const navigate = useNavigate();
    const [user, setUser] = useState<User | null>(null);
    const [editing, setEditing] = useState(false);
    const [firstName, setFirstName] = useState('');
    const [lastName, setLastName] = useState('');
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        loadUser();
    }, []);

    const loadUser = async () => {
        try {
            const response = await api.get<User>('/api/v1/user');
            setUser(response.data);
            setFirstName(response.data.firstName || '');
            setLastName(response.data.lastName || '');
        } catch (error) {
            navigate('/sign-in');
        } finally {
            setLoading(false);
        }
    };

    const handleUpdate = async () => {
        try {
            await api.patch('/api/v1/user', { firstName, lastName });
            toast.success('Profile updated successfully!');
            setEditing(false);
            loadUser();
        } catch (error: any) {
            toast.error(error.response?.data?.message || 'Failed to update profile');
        }
    };

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gradient-to-br from-indigo-50 to-purple-100 dark:from-gray-900 dark:to-gray-800 py-8">
            <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
                <button
                    onClick={() => navigate('/dashboard')}
                    className="mb-6 flex items-center text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white transition-colors"
                >
                    <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                    </svg>
                    Back to Dashboard
                </button>

                <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl overflow-hidden">
                    <div className="p-6 bg-gradient-to-r from-indigo-500 to-purple-600">
                        <div className="flex items-center space-x-4">
                            <div className="w-20 h-20 bg-white rounded-full flex items-center justify-center text-indigo-600 font-bold text-3xl">
                                {user?.firstName?.charAt(0) || user?.email.charAt(0).toUpperCase()}
                            </div>
                            <div>
                                <h1 className="text-2xl font-bold text-white">
                                    {user?.firstName && user?.lastName
                                        ? `${user.firstName} ${user.lastName}`
                                        : 'Your Profile'}
                                </h1>
                                <p className="text-indigo-100">{user?.email}</p>
                            </div>
                        </div>
                    </div>

                    <div className="p-6">
                        <div className="space-y-6">
                            {/* Personal Information */}
                            <div>
                                <div className="flex items-center justify-between mb-4">
                                    <h2 className="text-xl font-semibold text-gray-900 dark:text-white">
                                        Personal Information
                                    </h2>
                                    {!editing && (
                                        <button
                                            onClick={() => setEditing(true)}
                                            className="px-4 py-2 text-sm font-medium text-blue-600 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded-lg transition-colors"
                                        >
                                            Edit Profile
                                        </button>
                                    )}
                                </div>

                                {editing ? (
                                    <div className="space-y-4">
                                        <div>
                                            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                                First Name
                                            </label>
                                            <input
                                                type="text"
                                                value={firstName}
                                                onChange={(e) => setFirstName(e.target.value)}
                                                className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:text-white"
                                            />
                                        </div>

                                        <div>
                                            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                                Last Name
                                            </label>
                                            <input
                                                type="text"
                                                value={lastName}
                                                onChange={(e) => setLastName(e.target.value)}
                                                className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:text-white"
                                            />
                                        </div>

                                        <div className="flex space-x-3">
                                            <button
                                                onClick={handleUpdate}
                                                className="flex-1 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-colors"
                                            >
                                                Save Changes
                                            </button>
                                            <button
                                                onClick={() => { setEditing(false); loadUser(); }}
                                                className="flex-1 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 hover:bg-gray-50 dark:hover:bg-gray-700 rounded-lg transition-colors"
                                            >
                                                Cancel
                                            </button>
                                        </div>
                                    </div>
                                ) : (
                                    <div className="space-y-3">
                                        <div className="flex items-center justify-between py-3 border-b border-gray-200 dark:border-gray-700">
                                            <span className="text-sm text-gray-600 dark:text-gray-400">First Name</span>
                                            <span className="text-sm font-medium text-gray-900 dark:text-white">
                                                {user?.firstName || 'Not set'}
                                            </span>
                                        </div>
                                        <div className="flex items-center justify-between py-3 border-b border-gray-200 dark:border-gray-700">
                                            <span className="text-sm text-gray-600 dark:text-gray-400">Last Name</span>
                                            <span className="text-sm font-medium text-gray-900 dark:text-white">
                                                {user?.lastName || 'Not set'}
                                            </span>
                                        </div>
                                        <div className="flex items-center justify-between py-3 border-b border-gray-200 dark:border-gray-700">
                                            <span className="text-sm text-gray-600 dark:text-gray-400">Email</span>
                                            <span className="text-sm font-medium text-gray-900 dark:text-white">
                                                {user?.email}
                                            </span>
                                        </div>
                                    </div>
                                )}
                            </div>

                            {/* Account Status */}
                            <div>
                                <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
                                    Account Status
                                </h2>
                                <div className="space-y-3">
                                    <div className="flex items-center justify-between py-3 border-b border-gray-200 dark:border-gray-700">
                                        <span className="text-sm text-gray-600 dark:text-gray-400">Email Verification</span>
                                        <span className={`text-sm font-medium ${user?.emailVerified ? 'text-green-600' : 'text-yellow-600'}`}>
                                            {user?.emailVerified ? '✓ Verified' : '⚠ Not Verified'}
                                        </span>
                                    </div>
                                    <div className="flex items-center justify-between py-3 border-b border-gray-200 dark:border-gray-700">
                                        <span className="text-sm text-gray-600 dark:text-gray-400">Two-Factor Authentication</span>
                                        <span className={`text-sm font-medium ${user?.mfaEnabled ? 'text-green-600' : 'text-gray-600'}`}>
                                            {user?.mfaEnabled ? '✓ Enabled' : 'Disabled'}
                                        </span>
                                    </div>
                                </div>
                            </div>

                            {/* Quick Actions */}
                            <div>
                                <h2 className="text-xl font-semibold text-gray-900 dark:text-white mb-4">
                                    Quick Actions
                                </h2>
                                <div className="grid grid-cols-2 gap-4">
                                    <button
                                        onClick={() => navigate('/security')}
                                        className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors text-left"
                                    >
                                        <svg className="w-6 h-6 text-blue-600 dark:text-blue-400 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                                        </svg>
                                        <div className="text-sm font-medium text-gray-900 dark:text-white">Enable MFA</div>
                                    </button>

                                    <button
                                        onClick={() => navigate('/billing')}
                                        className="p-4 border border-gray-200 dark:border-gray-700 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors text-left"
                                    >
                                        <svg className="w-6 h-6 text-purple-600 dark:text-purple-400 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />
                                        </svg>
                                        <div className="text-sm font-medium text-gray-900 dark:text-white">Manage Billing</div>
                                    </button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
