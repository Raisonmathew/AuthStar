import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../../lib/api';
import { toast } from 'sonner';

interface PlanDetails {
    name: string;
    amount: number;
    currency: string;
    interval: string;
}

interface Subscription {
    id: string;
    status: string;
    currentPeriodEnd: string;
    cancelAtPeriodEnd: boolean;
    plan: PlanDetails;
}

interface Invoice {
    id: string;
    amountDue: number;
    amountPaid: number;
    currency: string;
    status: string;
    created: number; // Unix timestamp
    invoicePdf: string | null;
    hostedInvoiceUrl: string | null;
}

export default function BillingPage() {
    const [searchParams, setSearchParams] = useSearchParams();
    const [subscription, setSubscription] = useState<Subscription | null>(null);
    const [invoices, setInvoices] = useState<Invoice[]>([]);
    const [loading, setLoading] = useState(true);
    const [showPlans, setShowPlans] = useState(false);
    const [subscribing, setSubscribing] = useState<string | null>(null);

    const plans = [
        {
            id: 'price_free', name: 'Free', price: 0, interval: 'month',
            features: ['100 active users', 'Email/password auth', 'Basic OAuth', 'Community support'],
        },
        {
            id: 'price_1TKBbB0o1JIXYVZyT5zciFcZ', name: 'Pro', price: 49, interval: 'month', popular: true,
            features: ['Unlimited users', 'All auth methods', 'Advanced MFA', 'Priority support', 'Custom branding', 'Audit logs'],
        },
        {
            id: 'price_1TKBbT0o1JIXYVZylc1J90LM', name: 'Enterprise', price: 299, interval: 'month',
            features: ['Everything in Pro', 'SSO/SAML', 'Advanced RBAC', 'SLA guarantee', 'Dedicated support', 'Custom integrations'],
        },
    ];

    useEffect(() => {
        if (searchParams.get('success') === 'true') {
            toast.success('Subscription activated successfully!');
            setSearchParams({}, { replace: true });
        } else if (searchParams.get('canceled') === 'true') {
            toast.info('Checkout was canceled.');
            setSearchParams({}, { replace: true });
        }
        fetchBillingData();
    }, []);

    const fetchBillingData = async () => {
        setLoading(true);
        const orgId = sessionStorage.getItem('active_org_id') || 'default';
        try {
            // Parallel fetch
            const [subRes, invRes] = await Promise.allSettled([
                api.get<Subscription>(`/api/billing/v1/subscription?org_id=${orgId}`),
                api.get<Invoice[]>(`/api/billing/v1/invoices?org_id=${orgId}`)
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
            const res = await api.post<{ url: string }>('/api/billing/v1/portal', {
                org_id: orgId,
                return_url: window.location.href
            });
            window.location.href = res.data.url;
        } catch (err: any) {
            console.error(err);
            toast.error('Failed to create portal session');
        }
    };

    const handleSubscribe = async (priceId: string) => {
        if (priceId === 'price_free') {
            toast.info('Free plan is the default — no checkout needed.');
            return;
        }
        const orgId = sessionStorage.getItem('active_org_id') || 'default';
        setSubscribing(priceId);
        try {
            const res = await api.post<{ url: string }>('/api/billing/v1/checkout', {
                org_id: orgId,
                price_id: priceId,
                success_url: window.location.origin + '/billing?success=true',
                cancel_url: window.location.origin + '/billing?canceled=true',
            });
            if (res.data.url) {
                toast.success('Redirecting to checkout...');
                window.location.href = res.data.url;
            }
        } catch (err: any) {
            console.error(err);
            toast.error(err.response?.data?.message || 'Failed to start checkout');
        } finally {
            setSubscribing(null);
        }
    };

    const handleCancelSubscription = async () => {
        if (!subscription || !confirm('Are you sure you want to cancel your subscription?')) return;
        const orgId = sessionStorage.getItem('active_org_id') || 'default';
        try {
            await api.post('/api/billing/v1/subscription/cancel', {
                _org_id: orgId,
                subscription_id: subscription.id,
                immediately: false,
            });
            toast.success('Subscription will be canceled at end of billing period.');
            fetchBillingData();
        } catch (err: any) {
            console.error(err);
            toast.error('Failed to cancel subscription');
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
                            You are subscribed to the <span className="font-bold text-white">{subscription.plan.name}</span>.
                        </p>
                        <p className="text-sm text-gray-400">
                            Renews on {new Date(subscription.currentPeriodEnd).toLocaleDateString()}
                        </p>
                        <p className="text-2xl font-bold text-white">
                            {(subscription.plan.amount / 100).toLocaleString('en-US', { style: 'currency', currency: subscription.plan.currency.toUpperCase() })}
                            <span className="text-sm font-normal text-gray-400"> / {subscription.plan.interval}</span>
                        </p>
                        {subscription.cancelAtPeriodEnd && (
                            <p className="text-sm text-yellow-400">⚠️ Subscription will cancel at end of current period</p>
                        )}
                    </div>
                ) : (
                    <div className="text-center py-4">
                        <p className="text-gray-400 mb-4">
                            No active subscription found. Choose a plan to get started.
                        </p>
                        <button
                            onClick={() => setShowPlans(true)}
                            className="bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2 px-6 rounded-md transition-colors"
                        >
                            View Plans
                        </button>
                    </div>
                )}

                {subscription && (
                <div className="mt-6 flex space-x-3">
                    <button
                        onClick={handleManageSubscription}
                        className="bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2 px-4 rounded-md transition-colors"
                    >
                        Manage Subscription
                    </button>
                    <button
                        onClick={() => setShowPlans(true)}
                        className="bg-gray-700 hover:bg-gray-600 text-white font-medium py-2 px-4 rounded-md transition-colors"
                    >
                        Change Plan
                    </button>
                    {!subscription.cancelAtPeriodEnd && (
                        <button
                            onClick={handleCancelSubscription}
                            className="border border-red-700 text-red-400 hover:bg-red-900/20 font-medium py-2 px-4 rounded-md transition-colors"
                        >
                            Cancel
                        </button>
                    )}
                </div>
                )}
            </div>

            {/* Plan Selection Cards */}
            {showPlans && (
                <div className="grid md:grid-cols-3 gap-6">
                    {plans.map((plan) => (
                        <div
                            key={plan.id}
                            className={`bg-gray-800 rounded-lg shadow-lg border overflow-hidden ${
                                plan.popular ? 'border-indigo-500 ring-2 ring-indigo-500/50' : 'border-gray-700'
                            }`}
                        >
                            {plan.popular && (
                                <div className="bg-gradient-to-r from-indigo-600 to-purple-600 text-white text-center py-1.5 text-xs font-semibold">
                                    Most Popular
                                </div>
                            )}
                            <div className="p-6">
                                <h3 className="text-xl font-bold text-white mb-1">{plan.name}</h3>
                                <div className="mb-4">
                                    <span className="text-3xl font-bold text-white">${plan.price}</span>
                                    <span className="text-gray-400 text-sm">/{plan.interval}</span>
                                </div>
                                <ul className="space-y-2 mb-6 text-sm">
                                    {plan.features.map((f, i) => (
                                        <li key={i} className="flex items-center text-gray-300">
                                            <span className="text-green-400 mr-2">✓</span>{f}
                                        </li>
                                    ))}
                                </ul>
                                <button
                                    onClick={() => handleSubscribe(plan.id)}
                                    disabled={subscribing === plan.id}
                                    className={`w-full py-2 font-medium rounded-md transition-colors ${
                                        plan.popular
                                            ? 'bg-indigo-600 hover:bg-indigo-700 text-white'
                                            : 'bg-gray-700 hover:bg-gray-600 text-white'
                                    } disabled:opacity-50`}
                                >
                                    {subscribing === plan.id ? 'Processing...' : plan.price === 0 ? 'Current Plan' : 'Subscribe'}
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            )}

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
                                            {new Date(inv.created * 1000).toLocaleDateString()}
                                        </td>
                                        <td className="px-4 py-3 font-medium text-white">
                                            {(inv.amountPaid / 100).toLocaleString('en-US', { style: 'currency', currency: inv.currency.toUpperCase() })}
                                        </td>
                                        <td className="px-4 py-3">
                                            <span className={`px-2 py-0.5 rounded text-xs ${inv.status === 'paid' ? 'bg-green-900 text-green-300' : 'bg-gray-700 text-gray-300'
                                                }`}>
                                                {inv.status}
                                            </span>
                                        </td>
                                        <td className="px-4 py-3">
                                            {inv.invoicePdf ? (
                                                <a
                                                    href={inv.invoicePdf}
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
