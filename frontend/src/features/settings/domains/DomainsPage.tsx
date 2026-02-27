import React, { useEffect, useState } from 'react';
import { api } from '../../../lib/api';
import { toast } from 'sonner';

interface CustomDomain {
    id: string;
    domain: string;
    verification_status: 'pending' | 'verified' | 'failed';
    verification_token: string;
    ssl_status: string;
    is_primary: boolean;
    is_active: boolean;
}

export default function DomainsPage() {
    const [domains, setDomains] = useState<CustomDomain[]>([]);
    const [loading, setLoading] = useState(true);
    const [newDomain, setNewDomain] = useState('');
    const [isAdding, setIsAdding] = useState(false);
    const [verifyModal, setVerifyModal] = useState<CustomDomain | null>(null);

    useEffect(() => {
        fetchDomains();
    }, []);

    const fetchDomains = async () => {
        try {
            const res = await api.get('/api/domains');
            setDomains(res.data);
        } catch (err) {
            console.error(err);
            toast.error('Failed to load domains');
        } finally {
            setLoading(false);
        }
    };

    const handleAddDomain = async (e: React.FormEvent) => {
        e.preventDefault();
        setIsAdding(true);
        try {
            await api.post('/api/domains', { domain: newDomain });
            toast.success('Domain added successfully');
            setNewDomain('');
            fetchDomains();
        } catch (err: any) {
            console.error(err);
            toast.error(err.response?.data?.error || 'Failed to add domain');
        } finally {
            setIsAdding(false);
        }
    };

    const handleDelete = async (id: string) => {
        if (!window.confirm('Are you sure you want to delete this domain?')) return;
        try {
            await api.delete(`/api/domains/${id}`);
            toast.success('Domain deleted');
            fetchDomains();
        } catch (err) {
            console.error(err);
            toast.error('Failed to delete domain');
        }
    };

    const handleVerifyStart = (domain: CustomDomain) => {
        setVerifyModal(domain);
    };

    const handleVerifyCheck = async () => {
        if (!verifyModal) return;
        try {
            const res = await api.post(`/api/domains/${verifyModal.id}/verify`);
            if (res.data.verified) {
                toast.success('Domain verified successfully!');
                setVerifyModal(null);
                fetchDomains();
            } else {
                toast.error('Verification failed. DNS record not found.');
            }
        } catch (err: any) {
            console.error(err);
            toast.error(err.response?.data?.error || 'Verification error');
        }
    };

    const handleSetPrimary = async (id: string) => {
        try {
            await api.post(`/api/domains/${id}/primary`);
            toast.success('Primary domain updated');
            fetchDomains();
        } catch (err) {
            console.error(err);
            toast.error('Failed to set primary domain');
        }
    };

    if (loading) return <div className="p-8 text-white">Loading domains...</div>;

    return (
        <div className="max-w-6xl mx-auto p-6 space-y-8">
            <h1 className="text-2xl font-bold text-white">Custom Domains</h1>

            {/* Add Domain Form */}
            <div className="bg-gray-800 rounded-lg p-6 border border-gray-700">
                <h2 className="text-lg font-medium text-white mb-4">Add New Domain</h2>
                <form onSubmit={handleAddDomain} className="flex gap-4">
                    <input
                        type="text"
                        value={newDomain}
                        onChange={(e) => setNewDomain(e.target.value)}
                        placeholder="e.g. auth.yourcompany.com"
                        className="flex-1 rounded-md bg-gray-900 border-gray-600 text-white px-4 py-2 focus:ring-indigo-500 focus:border-indigo-500"
                        required
                    />
                    <button
                        type="submit"
                        disabled={isAdding}
                        className="bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2 px-6 rounded-md disabled:opacity-50"
                    >
                        {isAdding ? 'Adding...' : 'Add Domain'}
                    </button>
                </form>
            </div>

            {/* Domain List */}
            <div className="bg-gray-800 rounded-lg shadow-lg border border-gray-700 overflow-hidden">
                <table className="min-w-full divide-y divide-gray-700">
                    <thead className="bg-gray-900">
                        <tr>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Domain</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Status</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">Use</th>
                            <th className="px-6 py-3 text-right text-xs font-medium text-gray-400 uppercase tracking-wider">Actions</th>
                        </tr>
                    </thead>
                    <tbody className="bg-gray-800 divide-y divide-gray-700">
                        {domains.map((domain) => (
                            <tr key={domain.id}>
                                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-white">
                                    {domain.domain}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm">
                                    <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${domain.verification_status === 'verified'
                                            ? 'bg-green-100 text-green-800'
                                            : domain.verification_status === 'failed'
                                                ? 'bg-red-100 text-red-800'
                                                : 'bg-yellow-100 text-yellow-800'
                                        }`}>
                                        {domain.verification_status.toUpperCase()}
                                    </span>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-300">
                                    {domain.is_primary ? (
                                        <span className="text-green-400 font-medium">Primary</span>
                                    ) : domain.verification_status === 'verified' ? (
                                        <button
                                            onClick={() => handleSetPrimary(domain.id)}
                                            className="text-indigo-400 hover:text-indigo-300"
                                        >
                                            Set Primary
                                        </button>
                                    ) : '-'}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium space-x-4">
                                    {domain.verification_status !== 'verified' && (
                                        <button
                                            onClick={() => handleVerifyStart(domain)}
                                            className="text-indigo-400 hover:text-indigo-300"
                                        >
                                            Verify
                                        </button>
                                    )}
                                    <button
                                        onClick={() => handleDelete(domain.id)}
                                        className="text-red-400 hover:text-red-300"
                                    >
                                        Delete
                                    </button>
                                </td>
                            </tr>
                        ))}
                        {domains.length === 0 && (
                            <tr>
                                <td colSpan={4} className="px-6 py-4 text-center text-sm text-gray-400">
                                    No custom domains configred.
                                </td>
                            </tr>
                        )}
                    </tbody>
                </table>
            </div>

            {/* Verification Modal */}
            {verifyModal && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black bg-opacity-50">
                    <div className="bg-gray-800 rounded-lg p-6 max-w-lg w-full border border-gray-700 shadow-xl">
                        <h3 className="text-lg font-medium text-white mb-4">Verify Domain Ownership</h3>
                        <p className="text-gray-300 mb-4">
                            To verify <strong>{verifyModal.domain}</strong>, please add the following TXT record to your DNS configuration:
                        </p>

                        <div className="bg-gray-900 p-4 rounded-md mb-6 space-y-3">
                            <div>
                                <label className="block text-xs text-gray-500 uppercase">Type</label>
                                <code className="text-green-400">TXT</code>
                            </div>
                            <div>
                                <label className="block text-xs text-gray-500 uppercase">Host / Name</label>
                                <code className="text-indigo-400">_idaas-verification</code>
                            </div>
                            <div>
                                <label className="block text-xs text-gray-500 uppercase">Value</label>
                                <code className="text-yellow-400 break-all select-all">
                                    idaas-verification={verifyModal.verification_token}
                                </code>
                            </div>
                        </div>

                        <div className="flex justify-end gap-3">
                            <button
                                onClick={() => setVerifyModal(null)}
                                className="px-4 py-2 text-gray-300 hover:text-white"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={handleVerifyCheck}
                                className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-md"
                            >
                                Verify Records
                            </button>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
