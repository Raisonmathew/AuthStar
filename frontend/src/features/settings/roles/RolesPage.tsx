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

    if (loading) return <div className="p-8 text-center">Loading roles...</div>;

    return (
        <div className="min-h-screen bg-gray-50 py-8">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="flex justify-between items-center mb-6">
                    <div>
                        <h1 className="text-2xl font-bold text-gray-900">Roles & Permissions</h1>
                        <p className="text-gray-600 mt-1">Manage custom roles for your organization</p>
                    </div>
                    <button
                        onClick={() => navigate('/settings/roles/new')}
                        className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors"
                    >
                        Create New Role
                    </button>
                </div>

                <div className="bg-white rounded-lg shadow overflow-hidden">
                    <table className="min-w-full divide-y divide-gray-200">
                        <thead className="bg-gray-50">
                            <tr>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role Name</th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Description</th>
                                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Permissions</th>
                                <th className="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                            </tr>
                        </thead>
                        <tbody className="bg-white divide-y divide-gray-200">
                            {/* System Roles Placeholder (if not returned by API, we might manually list them or just show what API returns) */}
                            {/* The API returns all roles including custom ones. System roles should be in the list if they are in the DB.
                                If 'admin' and 'member' are NOT in DB (hardcoded), they won't show up here unless we mock them.
                                For now, relying on API. */}

                            {roles.length === 0 && (
                                <tr>
                                    <td colSpan={4} className="px-6 py-12 text-center text-gray-500">
                                        No custom roles found.
                                    </td>
                                </tr>
                            )}

                            {roles.map((role) => (
                                <tr key={role.id}>
                                    <td className="px-6 py-4 whitespace-nowrap">
                                        <div className="font-medium text-gray-900">{role.name}</div>
                                        {role.is_system_role && <span className="text-xs text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded-full">System</span>}
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap text-gray-500">
                                        {role.description || '-'}
                                    </td>
                                    <td className="px-6 py-4 text-gray-500 text-sm max-w-xs truncate">
                                        {role.permissions.join(', ') || 'No permissions'}
                                    </td>
                                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                        {!role.is_system_role && (
                                            <button
                                                onClick={() => handleDelete(role.id)}
                                                className="text-red-600 hover:text-red-900"
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
                        onClick={() => navigate('/dashboard')}
                        className="text-gray-600 hover:text-gray-900"
                    >
                        &larr; Back to Dashboard
                    </button>
                </div>
            </div>
        </div>
    );
}
