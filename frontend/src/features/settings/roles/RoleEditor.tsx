import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../../../lib/api/client';
import { toast } from 'sonner';

const PERMISSION_GROUPS = [
    {
        name: 'Organization',
        permissions: [
            { id: 'org:read', label: 'View Organization Details' },
            { id: 'org:update', label: 'Update Organization Settings' },
        ]
    },
    {
        name: 'Team Membership',
        permissions: [
            { id: 'team:read', label: 'View Members' },
            { id: 'team:write', label: 'Invite/Remove Members' },
        ]
    },
    {
        name: 'Billing',
        permissions: [
            { id: 'billing:read', label: 'View Subscription & Invoices' },
            { id: 'billing:write', label: 'Manage Payment Methods' },
        ]
    },
    {
        name: 'Roles',
        permissions: [
            { id: 'roles:read', label: 'View Roles' },
            { id: 'roles:write', label: 'Manage Roles' },
        ]
    },
    {
        name: 'API Keys',
        permissions: [
            { id: 'api_keys:read', label: 'View API Keys' },
            { id: 'api_keys:write', label: 'Create/Revoke API Keys' },
        ]
    }
];

export default function RoleEditor() {
    const navigate = useNavigate();
    const [name, setName] = useState('');
    const [description, setDescription] = useState('');
    const [selectedPermissions, setSelectedPermissions] = useState<Set<string>>(new Set());
    const [loading, setLoading] = useState(false);

    const togglePermission = (permId: string) => {
        const newSet = new Set(selectedPermissions);
        if (newSet.has(permId)) {
            newSet.delete(permId);
        } else {
            newSet.add(permId);
        }
        setSelectedPermissions(newSet);
    };

    const handleSave = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!name.trim()) {
            toast.error('Role name is required');
            return;
        }

        setLoading(true);
        try {
            const orgId = sessionStorage.getItem('active_org_id');
            await api.post(`/api/v1/organizations/${orgId}/roles`, {
                name,
                description,
                permissions: Array.from(selectedPermissions),
            });
            toast.success('Role created successfully');
            navigate('/settings/roles');
        } catch (error: any) {
            console.error('Failed to create role:', error);
            toast.error(error.response?.data?.message || 'Failed to create role');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen bg-gray-50 py-8">
            <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="mb-6">
                    <button
                        onClick={() => navigate('/settings/roles')}
                        className="text-sm text-gray-500 hover:text-gray-700 mb-2"
                    >
                        &larr; Back to Roles
                    </button>
                    <h1 className="text-2xl font-bold text-gray-900">Create New Role</h1>
                </div>

                <form onSubmit={handleSave} className="bg-white rounded-lg shadow overflow-hidden p-6 space-y-6">
                    <div>
                        <label className="block text-sm font-medium text-gray-700">Role Name</label>
                        <input
                            type="text"
                            value={name}
                            onChange={(e) => setName(e.target.value)}
                            className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm p-2 border"
                            placeholder="e.g. Editor"
                        />
                    </div>

                    <div>
                        <label className="block text-sm font-medium text-gray-700">Description</label>
                        <textarea
                            value={description}
                            onChange={(e) => setDescription(e.target.value)}
                            rows={3}
                            className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm p-2 border"
                            placeholder="Can edit content but not settings..."
                        />
                    </div>

                    <div>
                        <h3 className="text-lg font-medium text-gray-900 mb-4">Permissions</h3>
                        <div className="space-y-6">
                            {PERMISSION_GROUPS.map((group) => (
                                <div key={group.name} className="bg-gray-50 p-4 rounded-md">
                                    <h4 className="text-sm font-semibold text-gray-900 uppercase tracking-wider mb-2">
                                        {group.name}
                                    </h4>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                        {group.permissions.map((perm) => (
                                            <label key={perm.id} className="flex items-center space-x-3">
                                                <input
                                                    type="checkbox"
                                                    checked={selectedPermissions.has(perm.id)}
                                                    onChange={() => togglePermission(perm.id)}
                                                    className="h-4 w-4 text-indigo-600 focus:ring-indigo-500 border-gray-300 rounded"
                                                />
                                                <span className="text-sm text-gray-700">{perm.label}</span>
                                            </label>
                                        ))}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>

                    <div className="flex justify-end pt-4 border-t border-gray-200">
                        <button
                            type="button"
                            onClick={() => navigate('/settings/roles')}
                            className="bg-white py-2 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 hover:bg-gray-50 mr-3"
                        >
                            Cancel
                        </button>
                        <button
                            type="submit"
                            disabled={loading}
                            className="inline-flex justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
                        >
                            {loading ? 'Creating...' : 'Create Role'}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    );
}
