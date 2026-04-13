import { useState, useEffect } from 'react';
import { api } from '../lib/api/client';
import { toast } from 'sonner';

interface Member {
    id: string;
    userId: string;
    role: string;
    email: string;
    firstName?: string;
    lastName?: string;
    createdAt: string;
}

export default function TeamManagementPage() {
    const [members, setMembers] = useState<Member[]>([]);
    const [availableRoles, setAvailableRoles] = useState<{ name: string }[]>([]); // simplified type
    const [inviteEmail, setInviteEmail] = useState('');
    const [inviteRole, setInviteRole] = useState('member');
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        loadData();
    }, []);

    const loadData = async () => {
        const orgId = sessionStorage.getItem('active_org_id');
        if (!orgId) return;

        try {
            const [membersRes, rolesRes] = await Promise.all([
                api.get<Member[]>(`/api/v1/organizations/${orgId}/members`),
                api.get<any[]>(`/api/v1/organizations/${orgId}/roles`)
            ]);
            setMembers(membersRes.data);
            setAvailableRoles(rolesRes.data);
        } catch (error) {
            console.error('Failed to load data:', error);
            toast.error('Failed to load team data');
        } finally {
            setLoading(false);
        }
    };

    const loadMembers = async () => {
        // Legacy wrapper if needed, or just reuse loadData
        loadData();
    };

    const inviteMember = async () => {
        if (!inviteEmail.trim()) return;

        try {
            const orgId = sessionStorage.getItem('active_org_id');
            // B-5: Backend uses /members endpoint (add_member_by_email handler).
            // The /invitations URL does not exist — the backend directly adds existing
            // users by email. If the user doesn't exist yet, the backend returns a
            // descriptive error message asking them to sign up first.
            const res = await api.post<{ success: boolean; message: string }>(
                `/api/v1/organizations/${orgId}/members`,
                { email: inviteEmail, role: inviteRole }
            );

            if (res.data.success) {
                toast.success('Member added successfully!');
            } else {
                toast.error(res.data.message);
            }
            setInviteEmail('');
            loadMembers();
        } catch (error: any) {
            toast.error(error.response?.data?.message || 'Failed to add member');
        }
    };

    const removeMember = async (userId: string) => {
        if (!confirm('Are you sure you want to remove this member?')) return;

        try {
            const orgId = sessionStorage.getItem('active_org_id');
            await api.delete(`/api/v1/organizations/${orgId}/members/${userId}`);
            toast.success('Member removed');
            loadMembers();
        } catch (error: any) {
            toast.error(error.response?.data?.message || 'Failed to remove member');
        }
    };

    const updateRole = async (userId: string, newRole: string) => {
        try {
            const orgId = sessionStorage.getItem('active_org_id');
            await api.patch(`/api/v1/organizations/${orgId}/members/${userId}`, {
                role: newRole,
            });
            toast.success('Role updated');
            loadMembers();
        } catch (error: any) {
            toast.error(error.response?.data?.message || 'Failed to update role');
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
            <div className="bg-card rounded-xl border border-border">
                <div className="p-6 border-b border-border">
                    <h1 className="text-2xl font-bold text-foreground font-heading">
                        Team Management
                    </h1>
                    <p className="text-muted-foreground mt-1">
                        Manage your team members and their roles
                    </p>
                </div>

                {/* Invite Section */}
                <div className="p-6 bg-primary/5 border-b border-border">
                    <h2 className="text-lg font-semibold text-foreground font-heading mb-4">
                        Invite Team Member
                    </h2>
                    <div className="flex space-x-4">
                        <input
                            type="email"
                            value={inviteEmail}
                            onChange={(e) => setInviteEmail(e.target.value)}
                            placeholder="colleague@example.com"
                            className="flex-1 px-4 py-2 border border-border rounded-xl focus:ring-2 focus:ring-ring focus:border-transparent bg-card text-foreground placeholder-muted-foreground"
                        />
                        <select
                            value={inviteRole}
                            onChange={(e) => setInviteRole(e.target.value)}
                            className="px-4 py-2 border border-border rounded-xl focus:ring-2 focus:ring-ring bg-card text-foreground"
                        >
                            <option value="member">Member</option>
                            <option value="admin">Admin</option>
                            {availableRoles
                                .filter(r => r.name !== 'member' && r.name !== 'admin')
                                .map(r => (
                                    <option key={r.name} value={r.name}>{r.name}</option>
                                ))
                            }
                        </select>
                        <button
                            onClick={inviteMember}
                            className="px-6 py-2 bg-primary hover:bg-primary/90 text-primary-foreground font-semibold font-heading rounded-xl transition-colors"
                        >
                            Invite
                        </button>
                    </div>
                </div>

                {/* Members List */}
                <div className="p-6">
                    <h2 className="text-lg font-semibold text-foreground font-heading mb-4">
                        Team Members ({members.length})
                    </h2>

                    <div className="space-y-3">
                        {members.map((member) => (
                            <div
                                key={member.id}
                                className="flex items-center justify-between p-4 bg-muted/50 rounded-xl"
                            >
                                <div className="flex items-center space-x-4">
                                    <div className="w-12 h-12 bg-gradient-to-br from-blue-500 to-purple-600 rounded-full flex items-center justify-center text-white font-bold text-lg">
                                        {member.firstName?.charAt(0) || member.email.charAt(0).toUpperCase()}
                                    </div>
                                    <div>
                                        <div className="font-medium text-foreground">
                                            {member.firstName && member.lastName
                                                ? `${member.firstName} ${member.lastName}`
                                                : member.email}
                                        </div>
                                        <div className="text-sm text-muted-foreground">
                                            {member.email}
                                        </div>
                                    </div>
                                </div>

                                <div className="flex items-center space-x-3">
                                    <select
                                        value={member.role}
                                        onChange={(e) => updateRole(member.userId, e.target.value)}
                                        className="px-3 py-1 border border-border rounded-xl text-sm bg-card text-foreground"
                                    >
                                        <option value="member">Member</option>
                                        <option value="admin">Admin</option>
                                        {availableRoles
                                            .filter(r => r.name !== 'member' && r.name !== 'admin')
                                            .map(r => (
                                                <option key={r.name} value={r.name}>{r.name}</option>
                                            ))
                                            }
                                        </select>

                                        <button
                                            onClick={() => removeMember(member.userId)}
                                            className="p-2 text-destructive hover:bg-destructive/10 rounded-xl transition-colors"
                                            title="Remove member"
                                        >
                                            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                                            </svg>
                                        </button>
                                    </div>
                                </div>
                            ))}

                            {members.length === 0 && (
                                <div className="text-center py-12">
                                    <svg className="w-16 h-16 text-muted-foreground mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
                                    </svg>
                                    <p className="text-muted-foreground">No team members yet</p>
                                    <p className="text-sm text-muted-foreground/60 mt-1">
                                        Invite members to collaborate
                                    </p>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            </div>
    );
}
