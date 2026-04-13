import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../../../lib/api/client';
import { toast } from 'sonner';

interface Role {
    id: string;
    name: string;
    description?: string;
    permissions: string[];
    is_system_role: boolean;
    created_at: string;
}

export default function RolesPage() {
    const navigate = useNavigate();
    const [roles, setRoles] = useState<Role[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        loadRoles();
    }, []);

    const loadRoles = async () => {
        try {
            const orgId = sessionStorage.getItem('active_org_id');
            if (!orgId) return;

            const response = await api.get<Role[]>(`/api/v1/organizations/${orgId}/roles`);
            setRoles(response.data);
        } catch (error) {
            console.error('Failed to load roles:', error);
            toast.error('Failed to load roles');
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async (roleId: string) => {
        if (!confirm('Are you sure you want to delete this role?')) return;

        try {
            const orgId = sessionStorage.getItem('active_org_id');
            await api.delete(`/api/v1/organizations/${orgId}/roles/${roleId}`);
            toast.success('Role deleted');
            loadRoles();
        } catch (error) {
            console.error('Failed to delete role:', error);
            toast.error('Failed to delete role');
        }
    };

    if (loading) return <div className="p-8 text-center text-muted-foreground">Loading roles...</div>;

    return (
        <div className="space-y-6">
            <div className="flex justify-between items-center">
                <div>
                    <h1 className="text-2xl font-bold text-foreground font-heading">Roles & Permissions</h1>
                    <p className="text-muted-foreground mt-1">Manage custom roles for your organization</p>
                </div>
                <button
                    onClick={() => navigate('/admin/user-management/roles/new')}
                    className="px-4 py-2 bg-primary text-primary-foreground rounded-xl font-semibold font-heading hover:bg-primary/90 transition-colors"
                >
                    Create New Role
                </button>
            </div>

            <div className="bg-card rounded-xl border border-border overflow-hidden">
                <table className="min-w-full divide-y divide-border">
                    <thead className="bg-muted/30">
                        <tr>
                            <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Role Name</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Description</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Permissions</th>
                            <th className="px-6 py-3 text-right text-xs font-medium text-muted-foreground uppercase tracking-wider">Actions</th>
                        </tr>
                    </thead>
                    <tbody className="bg-card divide-y divide-border">
                        {roles.length === 0 && (
                            <tr>
                                <td colSpan={4} className="px-6 py-12 text-center text-muted-foreground">
                                    No custom roles found.
                                </td>
                            </tr>
                        )}

                        {roles.map((role) => (
                            <tr key={role.id}>
                                <td className="px-6 py-4 whitespace-nowrap">
                                    <div className="font-medium text-foreground">{role.name}</div>
                                    {role.is_system_role && <span className="text-xs text-primary bg-primary/10 px-2 py-0.5 rounded-full">System</span>}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-muted-foreground">
                                    {role.description || '-'}
                                </td>
                                <td className="px-6 py-4 text-muted-foreground text-sm max-w-xs truncate">
                                    {role.permissions.join(', ') || 'No permissions'}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                    {!role.is_system_role && (
                                        <button
                                            onClick={() => handleDelete(role.id)}
                                            className="text-destructive hover:text-destructive/80"
                                        >
                                            Delete
                                        </button>
                                    )}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>

            <div className="mt-4">
                <button
                    onClick={() => navigate('/admin/dashboard')}
                    className="text-muted-foreground hover:text-foreground transition-colors"
                >
                    &larr; Back to Dashboard
                </button>
            </div>
        </div>
    );
}
