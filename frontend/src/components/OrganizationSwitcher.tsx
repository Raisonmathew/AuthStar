import { useState, useEffect } from 'react';
import { api } from '../lib/api/client';
import { useAuth } from '../features/auth/AuthContext';
import { toast } from 'sonner';

interface Organization {
    id: string;
    name: string;
    slug: string;
}

interface SwitchOrgResponse {
    jwt: string;
    user: any;
    organization: Organization;
}

export default function OrganizationSwitcher() {
    const { setAuth } = useAuth();
    const [organizations, setOrganizations] = useState<Organization[]>([]);
    const [activeOrgId, setActiveOrgId] = useState<string | null>(null);
    const [isOpen, setIsOpen] = useState(false);
    const [isSwitching, setIsSwitching] = useState(false);
    const [showCreateModal, setShowCreateModal] = useState(false);
    const [newOrgName, setNewOrgName] = useState('');

    useEffect(() => {
        loadOrganizations();
    }, []);

    const loadOrganizations = async () => {
        try {
            const response = await api.get<Organization[]>('/api/v1/organizations');
            setOrganizations(response.data);

            const savedOrgId = sessionStorage.getItem('active_org_id');
            if (savedOrgId && response.data.some(o => o.id === savedOrgId)) {
                setActiveOrgId(savedOrgId);
            } else if (response.data.length > 0) {
                setActiveOrgId(response.data[0].id);
                sessionStorage.setItem('active_org_id', response.data[0].id);
            }
        } catch (error) {
            console.error('Failed to load organizations:', error);
        }
    };

    const switchOrganization = async (orgId: string) => {
        if (orgId === activeOrgId || isSwitching) return;
        setIsSwitching(true);
        try {
            const response = await api.post<SwitchOrgResponse>('/api/v1/auth/switch-org', {
                organization_id: orgId,
            });
            setActiveOrgId(orgId);
            sessionStorage.setItem('active_org_id', orgId);
            setIsOpen(false);
            // Update auth context with new JWT and user
            setAuth(response.data.jwt, response.data.user);
            toast.success(`Switched to ${response.data.organization.name}`);
        } catch (error: any) {
            toast.error(error.response?.data?.message || 'Failed to switch organization');
        } finally {
            setIsSwitching(false);
        }
    };

    const createOrganization = async () => {
        if (!newOrgName.trim()) return;

        try {
            const response = await api.post<Organization>('/api/v1/organizations', { name: newOrgName });
            toast.success('Organization created!');
            setNewOrgName('');
            setShowCreateModal(false);
            await loadOrganizations();
            switchOrganization(response.data.id);
        } catch (error: any) {
            toast.error(error.response?.data?.message || 'Failed to create organization');
        }
    };

    const activeOrg = organizations.find(org => org.id === activeOrgId);

    return (
        <>
            <div className="relative">
                <button
                    onClick={() => setIsOpen(!isOpen)}
                    className="flex items-center space-x-2 px-4 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
                >
                    <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center text-white font-bold">
                        {activeOrg?.name.charAt(0) || 'P'}
                    </div>
                    <span className="font-medium text-gray-900 dark:text-white">
                        {activeOrg?.name || 'Personal'}
                    </span>
                    <svg className="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                    </svg>
                </button>

                {isOpen && (
                    <div className="absolute top-full mt-2 w-72 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg shadow-xl z-50">
                        <div className="p-2">
                            <div className="text-xs font-semibold text-gray-500 dark:text-gray-400 px-3 py-2">
                                YOUR ORGANIZATIONS
                            </div>

                            {organizations.map((org) => (
                                <button
                                    key={org.id}
                                    onClick={() => switchOrganization(org.id)}
                                    className={`w-full flex items-center space-x-3 px-3 py-2 rounded-lg transition-colors ${org.id === activeOrgId
                                        ? 'bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400'
                                        : 'hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-900 dark:text-white'
                                        }`}
                                >
                                    <div className="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center text-white font-bold text-sm">
                                        {org.name.charAt(0)}
                                    </div>
                                    <div className="flex-1 text-left">
                                        <div className="font-medium">{org.name}</div>
                                        <div className="text-xs text-gray-500 dark:text-gray-400">{org.slug}</div>
                                    </div>
                                    {org.id === activeOrgId && (
                                        <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                                            <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                                        </svg>
                                    )}
                                </button>
                            ))}

                            <div className="border-t border-gray-200 dark:border-gray-700 mt-2 pt-2">
                                <button
                                    onClick={() => { setShowCreateModal(true); setIsOpen(false); }}
                                    className="w-full flex items-center space-x-3 px-3 py-2 text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded-lg transition-colors"
                                >
                                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                                    </svg>
                                    <span className="font-medium">Create Organization</span>
                                </button>
                            </div>
                        </div>
                    </div>
                )}
            </div>

            {/* Create Organization Modal */}
            {showCreateModal && (
                <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
                    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl p-6 w-full max-w-md">
                        <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-4">
                            Create Organization
                        </h2>

                        <div className="mb-4">
                            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                                Organization Name
                            </label>
                            <input
                                type="text"
                                value={newOrgName}
                                onChange={(e) => setNewOrgName(e.target.value)}
                                placeholder="Acme Inc."
                                className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:text-white"
                            />
                        </div>

                        <div className="flex space-x-3">
                            <button
                                onClick={() => setShowCreateModal(false)}
                                className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={createOrganization}
                                className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                            >
                                Create
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </>
    );
}
