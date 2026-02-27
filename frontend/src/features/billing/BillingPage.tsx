import { useEffect, useState } from 'react';
import { api } from '../../lib/api';
import { toast } from 'sonner';

interface Subscription {
    id: string;
    status: string;
    current_period_end: string;
    plan_amount: number;
    currency: string;
}

interface Invoice {
    id: string;
    amount_paid: number;
    currency: string;
    status: string;
    created: string; // ISO date
    invoice_pdf: string | null;
}

export default function BillingPage() {
    const [subscription, setSubscription] = useState<Subscription | null>(null);
    const [invoices, setInvoices] = useState<Invoice[]>([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchBillingData();
    }, []);

    const fetchBillingData = async () => {
        setLoading(true);
        const orgId = sessionStorage.getItem('active_org_id') || 'default';
        try {
            // Parallel fetch
            const [subRes, invRes] = await Promise.allSettled([
                api.get(`/api/billing/v1/subscription?org_id=${orgId}`),
                api.get(`/api/billing/v1/invoices?org_id=${orgId}`)
            ]);

            if (subRes.status === 'fulfilled') {
                setSubscription(subRes.value.data);
            }
            if (invRes.status === 'fulfilled') {
                setInvoices(invRes.value.data);
            }
        } catch (err) {
            console.error(err);
            toast.error('Failed to load billing information');
        } finally {
            setLoading(false);
        }
    };

    const handleManageSubscription = async () => {
        const orgId = sessionStorage.getItem('active_org_id') || 'default';
        try {
            const res = await api.post('/api/billing/v1/portal', {
                org_id: orgId,
                return_url: window.location.href // Return to this page
            });
            // Redirect to Stripe Portal
            window.location.href = res.data.url;
        } catch (err: any) {
            console.error(err);
            toast.error('Failed to create portal session');
        }
    };

    if (loading) {
        return <div className="p-8 text-white">Loading billing details...</div>;
    }

    return (
        <div className="max-w-4xl mx-auto p-6 space-y-8">
            <h1 className="text-2xl font-bold text-white">Billing & Subscription</h1>

            {/* Subscription Status Card */}
            <div className="bg-gray-800 rounded-lg p-6 shadow-lg border border-gray-700">
                <div className="flex justify-between items-center mb-4">
                    <h2 className="text-xl font-semibold text-white">Current Plan</h2>
                    {subscription && (
                        <span className={`px-3 py-1 rounded-full text-xs font-medium ${subscription.status === 'active' ? 'bg-green-900 text-green-300' : 'bg-yellow-900 text-yellow-300'
                            }`}>
                            {subscription.status.toUpperCase()}
                        </span>
                    )}
                </div>

                {subscription ? (
                    <div className="space-y-4">
                        <p className="text-gray-300">
                            You are subscribed to the <span className="font-bold text-white">Pro Plan</span>.
                        </p>
                        <p className="text-sm text-gray-400">
                            Renews on {new Date(subscription.current_period_end).toLocaleDateString()}
                        </p>
                        <p className="text-2xl font-bold text-white">
                            {(subscription.plan_amount / 100).toLocaleString('en-US', { style: 'currency', currency: subscription.currency.toUpperCase() })}
                            <span className="text-sm font-normal text-gray-400"> / month</span>
                        </p>
                    </div>
                ) : (
                    <div className="text-gray-400">
                        No active subscription found. Please contact sales or upgrade.
                    </div>
                )}

                <div className="mt-6">
                    <button
                        onClick={handleManageSubscription}
                        className="bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2 px-4 rounded-md transition-colors"
                    >
                        Manage Subscription
                    </button>
                    <p className="mt-2 text-xs text-gray-500">
                        Update payment method, download receipts, or cancel plan via Stripe.
                    </p>
                </div>
            </div>

            {/* Invoices List */}
            <div className="bg-gray-800 rounded-lg p-6 shadow-lg border border-gray-700">
                <h2 className="text-xl font-semibold text-white mb-4">Invoice History</h2>

                {invoices.length === 0 ? (
                    <p className="text-gray-400">No invoices available.</p>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="min-w-full text-left text-sm text-gray-300">
                            <thead className="bg-gray-900 text-gray-400 uppercase font-medium">
                                <tr>
                                    <th className="px-4 py-3">Date</th>
                                    <th className="px-4 py-3">Amount</th>
                                    <th className="px-4 py-3">Status</th>
                                    <th className="px-4 py-3">Download</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-gray-700">
                                {invoices.map((inv) => (
                                    <tr key={inv.id} className="hover:bg-gray-750">
                                        <td className="px-4 py-3">
                                            {new Date(inv.created).toLocaleDateString()}
                                        </td>
                                        <td className="px-4 py-3 font-medium text-white">
                                            {(inv.amount_paid / 100).toLocaleString('en-US', { style: 'currency', currency: inv.currency.toUpperCase() })}
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className={`px-2 py-0.5 rounded text-xs ${inv.status === 'paid' ? 'bg-green-900 text-green-300' : 'bg-gray-700 text-gray-300'
                                                }`}>
                                                {inv.status}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3">
                                            {inv.invoice_pdf ? (
                                                <a
                                                    href={inv.invoice_pdf}
                                                    target="_blank"
                                                    rel="noopener noreferrer"
                                                    className="text-indigo-400 hover:text-indigo-300"
                                                >
                                                    PDF
                                                </a>
                                            ) : (
                                                <span className="text-gray-600">-</span>
                                            )}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
}
