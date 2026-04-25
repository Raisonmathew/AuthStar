import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../lib/api/client';
import { useAuth } from '../features/auth/AuthContext';
import { toast } from 'sonner';

// ─── Change Password Modal ────────────────────────────────────────────────────

interface ChangePasswordModalProps {
    onClose: () => void;
}

function ChangePasswordModal({ onClose }: ChangePasswordModalProps) {
    const [currentPassword, setCurrentPassword] = useState('');
    const [newPassword, setNewPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [loading, setLoading] = useState(false);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (newPassword !== confirmPassword) {
            toast.error('New passwords do not match');
            return;
        }
        if (newPassword.length < 8) {
            toast.error('Password must be at least 8 characters');
            return;
        }
        setLoading(true);
        try {
            await api.post('/api/v1/user/change-password', {
                currentPassword,
                newPassword,
            });
            toast.success('Password changed successfully');
            onClose();
        } catch (err: any) {
            const msg = err?.response?.data?.message || err?.response?.data?.error;
            toast.error(msg || 'Failed to change password');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm">
            <div className="bg-card rounded-2xl shadow-2xl border border-border w-full max-w-md">
                <div className="flex items-center justify-between p-6 border-b border-border">
                    <h3 className="text-lg font-bold text-foreground font-heading">Change Password</h3>
                    <button
                        onClick={onClose}
                        className="p-2 text-muted-foreground hover:text-foreground hover:bg-accent rounded-xl transition-colors"
                    >
                        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                        </svg>
                    </button>
                </div>
                <form onSubmit={handleSubmit} className="p-6 space-y-4">
                    <div>
                        <label className="block text-sm font-medium text-foreground mb-1.5">
                            Current password
                        </label>
                        <input
                            type="password"
                            value={currentPassword}
                            onChange={(e) => setCurrentPassword(e.target.value)}
                            required
                            autoComplete="current-password"
                            className="w-full px-4 py-2.5 bg-muted border border-border rounded-xl text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-transparent"
                        />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-foreground mb-1.5">
                            New password
                        </label>
                        <input
                            type="password"
                            value={newPassword}
                            onChange={(e) => setNewPassword(e.target.value)}
                            required
                            minLength={8}
                            autoComplete="new-password"
                            className="w-full px-4 py-2.5 bg-muted border border-border rounded-xl text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-transparent"
                        />
                        <p className="text-xs text-muted-foreground/60 mt-1">Minimum 8 characters</p>
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-foreground mb-1.5">
                            Confirm new password
                        </label>
                        <input
                            type="password"
                            value={confirmPassword}
                            onChange={(e) => setConfirmPassword(e.target.value)}
                            required
                            autoComplete="new-password"
                            className={`w-full px-4 py-2.5 bg-muted border rounded-xl text-foreground placeholder-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:border-transparent ${
                                confirmPassword && newPassword !== confirmPassword
                                    ? 'border-destructive'
                                    : 'border-border'
                            }`}
                        />
                        {confirmPassword && newPassword !== confirmPassword && (
                            <p className="text-xs text-destructive mt-1">Passwords do not match</p>
                        )}
                    </div>
                    <div className="flex gap-3 pt-2">
                        <button
                            type="submit"
                            disabled={loading || (!!confirmPassword && newPassword !== confirmPassword)}
                            className="flex-1 py-2.5 bg-primary hover:bg-primary/90 text-primary-foreground font-semibold rounded-xl transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
                        >
                            {loading && <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary-foreground" />}
                            Change password
                        </button>
                        <button
                            type="button"
                            onClick={onClose}
                            className="px-4 py-2.5 border border-border text-muted-foreground hover:bg-accent rounded-xl transition-colors"
                        >
                            Cancel
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}

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
    // FIX BUG-8: Use logout() from AuthContext so the redirect goes to the
    // correct login path and the in-memory token + HttpOnly cookie are cleared.
    // Previously called navigate('/sign-in') directly which left the session alive.
    const { logout } = useAuth();
    const [user, setUser] = useState<User | null>(null);
    const [editing, setEditing] = useState(false);
    const [firstName, setFirstName] = useState('');
    const [lastName, setLastName] = useState('');
    const [loading, setLoading] = useState(true);
    const [showChangePassword, setShowChangePassword] = useState(false);

    useEffect(() => {
        // Guard against the common React pattern bug where an unmounted
        // component still calls setState (and against logout() firing on a
        // component the user has already navigated away from).
        let cancelled = false;
        const controller = new AbortController();

        (async () => {
            try {
                const response = await api.get('/api/v1/user', { signal: controller.signal });
                if (cancelled) return;
                const d = response.data as any;
                const mapped: User = {
                    id: d.id,
                    email: d.email,
                    firstName: d.first_name ?? d.firstName,
                    lastName: d.last_name ?? d.lastName,
                    emailVerified: d.email_verified ?? d.emailVerified ?? false,
                    mfaEnabled: d.mfa_enabled ?? d.mfaEnabled ?? false,
                };
                setUser(mapped);
                setFirstName(mapped.firstName || '');
                setLastName(mapped.lastName || '');
            } catch (error: any) {
                if (cancelled || error?.code === 'ERR_CANCELED' || error?.name === 'CanceledError') return;
                // FIX BUG-8: Use logout() instead of navigate('/sign-in').
                // logout() clears the in-memory token, calls POST /api/v1/logout to
                // invalidate the HttpOnly refresh cookie, and redirects to the correct
                // login path. navigate('/sign-in') left the session alive in memory.
                logout();
            } finally {
                if (!cancelled) setLoading(false);
            }
        })();

        return () => {
            cancelled = true;
            controller.abort();
        };
    }, [logout]);

    const loadUser = async () => {
        try {
            const response = await api.get('/api/v1/user');
            const d = response.data as any;
            const mapped: User = {
                id: d.id,
                email: d.email,
                firstName: d.first_name ?? d.firstName,
                lastName: d.last_name ?? d.lastName,
                emailVerified: d.email_verified ?? d.emailVerified ?? false,
                mfaEnabled: d.mfa_enabled ?? d.mfaEnabled ?? false,
            };
            setUser(mapped);
            setFirstName(mapped.firstName || '');
            setLastName(mapped.lastName || '');
        } catch (error) {
            // FIX BUG-8: Use logout() instead of navigate('/sign-in').
            // logout() clears the in-memory token, calls POST /api/v1/logout to
            // invalidate the HttpOnly refresh cookie, and redirects to the correct
            // login path. navigate('/sign-in') left the session alive in memory.
            logout();
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
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary"></div>
            </div>
        );
    }

    return (
        <div className="space-y-6">
            {/* Change Password Modal */}
            {showChangePassword && (
                <ChangePasswordModal onClose={() => setShowChangePassword(false)} />
            )}

            <div className="max-w-3xl mx-auto">
                <button
                    onClick={() => navigate('/admin/dashboard')}
                    className="mb-6 flex items-center text-muted-foreground hover:text-foreground transition-colors"
                >
                    <svg className="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                    </svg>
                    Back to Admin Console
                </button>

                <div className="bg-card rounded-xl border border-border overflow-hidden">
                    <div className="p-6 bg-gradient-to-r from-indigo-500 to-purple-600">
                        <div className="flex items-center space-x-4">
                            <div className="w-20 h-20 bg-white rounded-full flex items-center justify-center text-indigo-600 font-bold text-3xl">
                                {user?.firstName?.charAt(0) || user?.email.charAt(0).toUpperCase()}
                            </div>
                            <div>
                                <h1 className="text-2xl font-bold text-white font-heading">
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
                                    <h2 className="text-xl font-semibold text-foreground font-heading">
                                        Personal Information
                                    </h2>
                                    {!editing && (
                                        <button
                                            onClick={() => setEditing(true)}
                                            className="px-4 py-2 text-sm font-medium text-primary hover:bg-primary/10 rounded-xl transition-colors"
                                        >
                                            Edit Profile
                                        </button>
                                    )}
                                </div>

                                {editing ? (
                                    <div className="space-y-4">
                                        <div>
                                            <label className="block text-sm font-medium text-foreground mb-2">
                                                First Name
                                            </label>
                                            <input
                                                type="text"
                                                value={firstName}
                                                onChange={(e) => setFirstName(e.target.value)}
                                                className="w-full px-4 py-2 border border-border rounded-xl focus:ring-2 focus:ring-ring focus:border-transparent bg-muted text-foreground"
                                            />
                                        </div>

                                        <div>
                                            <label className="block text-sm font-medium text-foreground mb-2">
                                                Last Name
                                            </label>
                                            <input
                                                type="text"
                                                value={lastName}
                                                onChange={(e) => setLastName(e.target.value)}
                                                className="w-full px-4 py-2 border border-border rounded-xl focus:ring-2 focus:ring-ring focus:border-transparent bg-muted text-foreground"
                                            />
                                        </div>

                                        <div className="flex space-x-3">
                                            <button
                                                onClick={handleUpdate}
                                                className="flex-1 py-2 bg-primary hover:bg-primary/90 text-primary-foreground font-semibold rounded-xl transition-colors"
                                            >
                                                Save Changes
                                            </button>
                                            <button
                                                onClick={() => { setEditing(false); loadUser(); }}
                                                className="flex-1 py-2 border border-border text-muted-foreground hover:bg-accent rounded-xl transition-colors"
                                            >
                                                Cancel
                                            </button>
                                        </div>
                                    </div>
                                ) : (
                                    <div className="space-y-3">
                                        <div className="flex items-center justify-between py-3 border-b border-border">
                                            <span className="text-sm text-muted-foreground">First Name</span>
                                            <span className="text-sm font-medium text-foreground">
                                                {user?.firstName || 'Not set'}
                                            </span>
                                        </div>
                                        <div className="flex items-center justify-between py-3 border-b border-border">
                                            <span className="text-sm text-muted-foreground">Last Name</span>
                                            <span className="text-sm font-medium text-foreground">
                                                {user?.lastName || 'Not set'}
                                            </span>
                                        </div>
                                        <div className="flex items-center justify-between py-3 border-b border-border">
                                            <span className="text-sm text-muted-foreground">Email</span>
                                            <span className="text-sm font-medium text-foreground">
                                                {user?.email}
                                            </span>
                                        </div>
                                    </div>
                                )}
                            </div>

                            {/* Account Status */}
                            <div>
                                <h2 className="text-xl font-semibold text-foreground font-heading mb-4">
                                    Account Status
                                </h2>
                                <div className="space-y-3">
                                    <div className="flex items-center justify-between py-3 border-b border-border">
                                        <span className="text-sm text-muted-foreground">Email Verification</span>
                                        <span className={`text-sm font-medium ${user?.emailVerified ? 'text-emerald-500' : 'text-yellow-500'}`}>
                                            {user?.emailVerified ? '✓ Verified' : '⚠ Not Verified'}
                                        </span>
                                    </div>
                                    <div className="flex items-center justify-between py-3 border-b border-border">
                                        <span className="text-sm text-muted-foreground">Two-Factor Authentication</span>
                                        <span className={`text-sm font-medium ${user?.mfaEnabled ? 'text-emerald-500' : 'text-muted-foreground'}`}>
                                            {user?.mfaEnabled ? '✓ Enabled' : 'Disabled'}
                                        </span>
                                    </div>
                                </div>
                            </div>

                            {/* Quick Actions */}
                            <div>
                                <h2 className="text-xl font-semibold text-foreground font-heading mb-4">
                                    Quick Actions
                                </h2>
                                <div className="grid grid-cols-2 gap-4">
                                    <button
                                        onClick={() => setShowChangePassword(true)}
                                        className="p-4 border border-border rounded-xl hover:bg-accent transition-colors text-left"
                                    >
                                        <svg className="w-6 h-6 text-orange-500 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" />
                                        </svg>
                                        <div className="text-sm font-medium text-foreground">Change Password</div>
                                        <div className="text-xs text-muted-foreground mt-0.5">Update your password</div>
                                    </button>

                                    <button
                                        onClick={() => navigate('/account/security')}
                                        className="p-4 border border-border rounded-xl hover:bg-accent transition-colors text-left"
                                    >
                                        <svg className="w-6 h-6 text-primary mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                                        </svg>
                                        <div className="text-sm font-medium text-foreground">Security Settings</div>
                                        <div className="text-xs text-muted-foreground mt-0.5">MFA, passkeys & more</div>
                                    </button>

                                    <button
                                        onClick={() => navigate('/admin/settings/billing')}
                                        className="p-4 border border-border rounded-xl hover:bg-accent transition-colors text-left"
                                    >
                                        <svg className="w-6 h-6 text-purple-500 mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />
                                        </svg>
                                        <div className="text-sm font-medium text-foreground">Manage Billing</div>
                                        <div className="text-xs text-muted-foreground mt-0.5">Plans & invoices</div>
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
