import React, { useEffect, useState } from 'react';
import { api } from '../../../lib/api';
import { toast } from 'sonner';

interface CustomDomain {
    id: string;
    domain: string;
    verificationStatus: 'pending' | 'verified' | 'failed';
    sslStatus: string;
    isPrimary: boolean;
    isActive: boolean;
    verificationInstructions?: VerificationInstructions | null;
}

interface VerificationInstructions {
    method: string;
    recordType: string;
    recordName: string;
    recordValue: string;
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

    const getOrgId = () => sessionStorage.getItem('active_org_id') || 'system';

    const fetchDomains = async () => {
        const orgId = getOrgId();
        try {
            const res = await api.get<CustomDomain[]>(`/api/domains?org_id=${encodeURIComponent(orgId)}`);
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
        const orgId = getOrgId();
        setIsAdding(true);
        try {
            await api.post('/api/domains', { org_id: orgId, domain: newDomain });
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
        const orgId = getOrgId();
        try {
            await api.delete(`/api/domains/${id}?org_id=${encodeURIComponent(orgId)}`);
            toast.success('Domain deleted');
            fetchDomains();
        } catch (err) {
            console.error(err);
            toast.error('Failed to delete domain');
        }
    };

    const handleVerifyStart = async (domain: CustomDomain) => {
        try {
            const res = await api.get<CustomDomain>(`/api/domains/${domain.id}`);
            setVerifyModal(res.data);
        } catch (err: any) {
            console.error(err);
            toast.error(err.response?.data?.error || 'Failed to load verification instructions');
        }
    };

    const handleVerifyCheck = async () => {
        if (!verifyModal) return;
        try {
            const res = await api.post<{ verified: boolean }>(`/api/domains/${verifyModal.id}/verify`);
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
        const orgId = getOrgId();
        try {
            await api.post(`/api/domains/${id}/primary?org_id=${encodeURIComponent(orgId)}`);
            toast.success('Primary domain updated');
            fetchDomains();
        } catch (err) {
            console.error(err);
            toast.error('Failed to set primary domain');
        }
    };

    if (loading) return <div className="p-8 text-foreground">Loading domains...</div>;

    return (
        <div className="max-w-6xl mx-auto p-6 space-y-8">
            <h1 className="text-2xl font-bold text-foreground font-heading">Custom Domains</h1>

            {/* Add Domain Form */}
            <div className="bg-card rounded-xl p-6 border border-border">
                <h2 className="text-lg font-medium text-foreground font-heading mb-4">Add New Domain</h2>
                <form onSubmit={handleAddDomain} className="flex gap-4">
                    <input
                        type="text"
                        value={newDomain}
                        onChange={(e) => setNewDomain(e.target.value)}
                        placeholder="e.g. auth.yourcompany.com"
                        className="flex-1 rounded-xl bg-muted border-border text-foreground px-4 py-2 focus:ring-ring focus:border-primary"
                        required
                    />
                    <button
                        type="submit"
                        disabled={isAdding}
                        className="bg-primary hover:bg-primary/90 text-primary-foreground font-semibold font-heading py-2 px-6 rounded-xl disabled:opacity-50 transition-colors"
                    >
                        {isAdding ? 'Adding...' : 'Add Domain'}
                    </button>
                </form>
            </div>

            {/* Domain List */}
            <div className="bg-card rounded-xl shadow-lg border border-border overflow-hidden">
                <table className="min-w-full divide-y divide-border">
                    <thead className="bg-muted/30">
                        <tr>
                            <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Domain</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Status</th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Use</th>
                            <th className="px-6 py-3 text-right text-xs font-medium text-muted-foreground uppercase tracking-wider">Actions</th>
                        </tr>
                    </thead>
                    <tbody className="bg-card divide-y divide-border">
                        {domains.map((domain) => (
                            <tr key={domain.id}>
                                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-foreground">
                                    {domain.domain}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm">
                                    <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${domain.verificationStatus === 'verified'
                                            ? 'bg-green-100 text-green-800'
                                            : domain.verificationStatus === 'failed'
                                                ? 'bg-red-100 text-red-800'
                                                : 'bg-yellow-100 text-yellow-800'
                                        }`}>
                                        {domain.verificationStatus.toUpperCase()}
                                    </span>
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-sm text-foreground">
                                    {domain.isPrimary ? (
                                        <span className="text-emerald-500 font-medium">Primary</span>
                                    ) : domain.verificationStatus === 'verified' ? (
                                        <button
                                            onClick={() => handleSetPrimary(domain.id)}
                                            className="text-primary hover:text-primary/80"
                                        >
                                            Set Primary
                                        </button>
                                    ) : '-'}
                                </td>
                                <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium space-x-4">
                                    {domain.verificationStatus !== 'verified' && (
                                        <button
                                            onClick={() => handleVerifyStart(domain)}
                                            className="text-primary hover:text-primary/80"
                                        >
                                            Verify
                                        </button>
                                    )}
                                    <button
                                        onClick={() => handleDelete(domain.id)}
                                        className="text-destructive hover:text-destructive/80"
                                    >
                                        Delete
                                    </button>
                                </td>
                            </tr>
                        ))}
                        {domains.length === 0 && (
                            <tr>
                                <td colSpan={4} className="px-6 py-4 text-center text-sm text-muted-foreground">
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
                    <div className="bg-card rounded-xl p-6 max-w-lg w-full border border-border shadow-xl">
                        <h3 className="text-lg font-medium text-foreground font-heading mb-4">Verify Domain Ownership</h3>
                        <p className="text-foreground/80 mb-4">
                            To verify <strong>{verifyModal.domain}</strong>, please add the following TXT record to your DNS configuration:
                        </p>

                        <div className="bg-muted p-4 rounded-xl mb-6 space-y-3">
                            <div>
                                <label className="block text-xs text-muted-foreground uppercase">Type</label>
                                <code className="text-emerald-500">{verifyModal.verificationInstructions?.recordType || 'TXT'}</code>
                            </div>
                            <div>
                                <label className="block text-xs text-muted-foreground uppercase">Host / Name</label>
                                <code className="text-primary">{verifyModal.verificationInstructions?.recordName || 'Unavailable'}</code>
                            </div>
                            <div>
                                <label className="block text-xs text-muted-foreground uppercase">Value</label>
                                <code className="text-yellow-400 break-all select-all">
                                    {verifyModal.verificationInstructions?.recordValue || 'Unavailable'}
                                </code>
                            </div>
                        </div>

                        <div className="flex justify-end gap-3">
                            <button
                                onClick={() => setVerifyModal(null)}
                                className="px-4 py-2 text-muted-foreground hover:text-foreground"
                            >
                                Cancel
                            </button>
                            <button
                                onClick={handleVerifyCheck}
                                className="bg-primary hover:bg-primary/90 text-primary-foreground px-4 py-2 rounded-xl transition-colors"
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
