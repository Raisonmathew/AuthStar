import { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api } from '../lib/api/client';
import { useAuth } from '../features/auth/AuthContext';
import { toast } from 'sonner';

interface InvitationInfo {
    id: string;
    organization_name: string;
    organization_slug: string;
    email: string;
    role: string;
    inviter_name: string | null;
    expires_at: string;
}

export default function InvitationAcceptPage() {
    const { token } = useParams<{ token: string }>();
    const navigate = useNavigate();
    const { isAuthenticated } = useAuth();
    const [invitation, setInvitation] = useState<InvitationInfo | null>(null);
    const [loading, setLoading] = useState(true);
    const [accepting, setAccepting] = useState(false);
    const [error, setError] = useState<string | null>(null);

    useEffect(() => {
        if (!token) return;
        api.get<InvitationInfo>(`/api/v1/invitations/${token}`)
            .then(res => setInvitation(res.data))
            .catch(err => setError(err.response?.data?.message || 'Invitation not found or expired'))
            .finally(() => setLoading(false));
    }, [token]);

    const handleAccept = async () => {
        if (!token || accepting) return;
        setAccepting(true);
        try {
            await api.post(`/api/v1/invitations/${token}/accept`);
            toast.success(`Joined ${invitation?.organization_name}!`);
            navigate('/');
        } catch (err: any) {
            const msg = err.response?.data?.message || 'Failed to accept invitation';
            toast.error(msg);
            setError(msg);
        } finally {
            setAccepting(false);
        }
    };

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
            </div>
        );
    }

    if (error || !invitation) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
                <div className="max-w-md w-full bg-white dark:bg-gray-800 rounded-lg shadow-lg p-8 text-center">
                    <div className="text-red-500 text-5xl mb-4">✕</div>
                    <h1 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
                        Invalid Invitation
                    </h1>
                    <p className="text-gray-600 dark:text-gray-400 mb-6">
                        {error || 'This invitation link is invalid, expired, or has already been used.'}
                    </p>
                    <button
                        onClick={() => navigate('/')}
                        className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                    >
                        Go to Dashboard
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
            <div className="max-w-md w-full bg-white dark:bg-gray-800 rounded-lg shadow-lg p-8">
                <div className="text-center mb-6">
                    <div className="w-16 h-16 mx-auto bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl flex items-center justify-center text-white text-2xl font-bold mb-4">
                        {invitation.organization_name.charAt(0)}
                    </div>
                    <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
                        You've been invited
                    </h1>
                    <p className="text-gray-600 dark:text-gray-400 mt-2">
                        {invitation.inviter_name
                            ? `${invitation.inviter_name} invited you to join`
                            : 'You have been invited to join'}
                    </p>
                    <p className="text-xl font-semibold text-gray-900 dark:text-white mt-1">
                        {invitation.organization_name}
                    </p>
                </div>

                <div className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4 mb-6 space-y-2">
                    <div className="flex justify-between text-sm">
                        <span className="text-gray-500 dark:text-gray-400">Role</span>
                        <span className="font-medium text-gray-900 dark:text-white capitalize">
                            {invitation.role}
                        </span>
                    </div>
                    <div className="flex justify-between text-sm">
                        <span className="text-gray-500 dark:text-gray-400">Email</span>
                        <span className="font-medium text-gray-900 dark:text-white">
                            {invitation.email}
                        </span>
                    </div>
                    <div className="flex justify-between text-sm">
                        <span className="text-gray-500 dark:text-gray-400">Expires</span>
                        <span className="font-medium text-gray-900 dark:text-white">
                            {new Date(invitation.expires_at).toLocaleDateString()}
                        </span>
                    </div>
                </div>

                {!isAuthenticated ? (
                    <div className="text-center">
                        <p className="text-gray-600 dark:text-gray-400 mb-4">
                            Please sign in to accept this invitation.
                        </p>
                        <button
                            onClick={() => navigate(`/login?redirect=/invitations/${token}`)}
                            className="w-full px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors"
                        >
                            Sign In to Accept
                        </button>
                    </div>
                ) : (
                    <button
                        onClick={handleAccept}
                        disabled={accepting}
                        className="w-full px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white rounded-lg font-medium transition-colors"
                    >
                        {accepting ? 'Joining...' : 'Accept Invitation'}
                    </button>
                )}
            </div>
        </div>
    );
}
