import { useState, useEffect } from 'react';
import { useAuth } from '../features/auth/hooks/useAuth';
import { api } from '../lib/api';
import { toast } from 'sonner';

interface Subscription {
    id: string;
    status: string;
    currentPeriodEnd: string;
    cancelAtPeriodEnd: boolean;
    plan: {
        name: string;
        amount: number;
        currency: string;
        interval: string;
    };
}


export default function BillingPage() {
    const { organizationId } = useAuth();
    const [subscription, setSubscription] = useState<Subscription | null>(null);
    const [loading, setLoading] = useState(true);
    const [showPlans, setShowPlans] = useState(false);

    const plans = [
        {
            id: 'price_free',
            name: 'Free',
            price: 0,
            interval: 'month',
            features: [
                '100 active users',
                'Email/password auth',
                'Basic OAuth',
                'Community support',
            ],
        },
        {
            id: 'price_pro',
            name: 'Pro',
            price: 49,
            interval: 'month',
            popular: true,
            features: [
                'Unlimited users',
                'All authentication methods',
                'Advanced MFA',
                'Priority support',
                'Custom branding',
                'Audit logs',
            ],
        },
        {
            id: 'price_enterprise',
            name: 'Enterprise',
            price: 299,
            interval: 'month',
            features: [
                'Everything in Pro',
                'SSO/SAML',
                'Advanced RBAC',
                'SLA guarantee',
                'Dedicated support',
                'Custom integrations',
            ],
        },
    ];

    useEffect(() => {
        if (organizationId) {
            loadSubscription();
        } else {
            setLoading(false);
        }
    }, [organizationId]);

    const loadSubscription = async () => {
        if (!organizationId) return;
        try {
            const response = await api.get<Subscription>('/api/billing/v1/subscription', {
                params: { org_id: organizationId }
            });
            setSubscription(response.data);
        } catch (error: any) {
            console.error('Failed to load subscription:', error);
            // Ignore 404 (no sub)
        } finally {
            setLoading(false);
        }
    };

    const subscribe = async (priceId: string) => {
        if (priceId === 'price_free') {
            toast.info('Free plan is default.');
            return;
        }

        try {
            const response = await api.post<{ url?: string }>('/api/billing/v1/checkout', {
                org_id: organizationId,
                price_id: priceId,
                success_url: window.location.origin + '/billing?success=true',
                cancel_url: window.location.origin + '/billing?canceled=true',
            });

            if (response.data.url) {
                toast.success('Redirecting to Stripe...');
                window.location.href = response.data.url;
            } else {
                toast.error('Failed to start checkout');
            }
        } catch (error: any) {
            toast.error(error.response?.data?.message || 'Failed to subscribe');
        }
    };

    const cancelSubscription = async () => {
        if (!confirm('Are you sure you want to cancel your subscription?')) return;
        toast.info('Cancellation not fully implemented in demo.');
    };

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gradient-to-br from-purple-50 to-blue-100 dark:from-gray-900 dark:to-gray-800 py-8">
            <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8">
                <div className="text-center mb-8">
                    <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
                        Billing & Subscription
                    </h1>
                    <p className="text-gray-600 dark:text-gray-400 mt-2">
                        Manage your subscription and billing
                    </p>
                </div>

                {subscription ? (
                    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl p-6 mb-8">
                        <div className="flex items-center justify-between mb-6">
                            <div>
                                <h2 className="text-2xl font-bold text-gray-900 dark:text-white">
                                    Current Plan: {subscription.plan.name}
                                </h2>
                                <p className="text-gray-600 dark:text-gray-400 mt-1">
                                    Status: <span className={`font-medium ${subscription.status === 'active' ? 'text-green-600' : 'text-yellow-600'}`}>
                                        {subscription.status}
                                    </span>
                                </p>
                            </div>
                            <div className="text-right">
                                <div className="text-3xl font-bold text-gray-900 dark:text-white">
                                    ${subscription.plan.amount}
                                </div>
                                <div className="text-sm text-gray-500 dark:text-gray-400">
                                    per {subscription.plan.interval}
                                </div>
                            </div>
                        </div>

                        <div className="grid grid-cols-2 gap-4 mb-6">
                            <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
                                <p className="text-sm text-gray-600 dark:text-gray-400">Next billing date</p>
                                <p className="text-lg font-semibold text-gray-900 dark:text-white mt-1">
                                    {new Date(subscription.currentPeriodEnd).toLocaleDateString()}
                                </p>
                            </div>
                            <div className="bg-gray-50 dark:bg-gray-700/50 rounded-lg p-4">
                                <p className="text-sm text-gray-600 dark:text-gray-400">Auto-renew</p>
                                <p className="text-lg font-semibold text-gray-900 dark:text-white mt-1">
                                    {subscription.cancelAtPeriodEnd ? 'Disabled' : 'Enabled'}
                                </p>
                            </div>
                        </div>

                        <div className="flex space-x-4">
                            <button
                                onClick={() => setShowPlans(true)}
                                className="flex-1 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-colors"
                            >
                                Change Plan
                            </button>
                            {!subscription.cancelAtPeriodEnd && (
                                <button
                                    onClick={cancelSubscription}
                                    className="flex-1 py-2 border border-red-300 dark:border-red-700 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 font-medium rounded-lg transition-colors"
                                >
                                    Cancel Subscription
                                </button>
                            )}
                        </div>
                    </div>
                ) : (
                    <div className="text-center bg-white dark:bg-gray-800 rounded-lg shadow-xl p-8 mb-8">
                        <svg className="w-20 h-20 text-gray-400 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z" />
                        </svg>
                        <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
                            No Active Subscription
                        </h2>
                        <p className="text-gray-600 dark:text-gray-400 mb-6">
                            Choose a plan to get started
                        </p>
                        <button
                            onClick={() => setShowPlans(true)}
                            className="px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-colors"
                        >
                            View Plans
                        </button>
                    </div>
                )}

                {showPlans && (
                    <div className="grid md:grid-cols-3 gap-6">
                        {plans.map((plan) => (
                            <div
                                key={plan.id}
                                className={`bg-white dark:bg-gray-800 rounded-lg shadow-xl overflow-hidden ${plan.popular ? 'ring-2 ring-blue-600 transform scale-105' : ''
                                    }`}
                            >
                                {plan.popular && (
                                    <div className="bg-gradient-to-r from-blue-600 to-purple-600 text-white text-center py-2 text-sm font-semibold">
                                        Most Popular
                                    </div>
                                )}
                                <div className="p-6">
                                    <h3 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">
                                        {plan.name}
                                    </h3>
                                    <div className="mb-6">
                                        <span className="text-4xl font-bold text-gray-900 dark:text-white">
                                            ${plan.price}
                                        </span>
                                        <span className="text-gray-600 dark:text-gray-400">
                                            /{plan.interval}
                                        </span>
                                    </div>

                                    <ul className="space-y-3 mb-6">
                                        {plan.features.map((feature, i) => (
                                            <li key={i} className="flex items-start">
                                                <svg className="w-5 h-5 text-green-500 mr-2 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                                                </svg>
                                                <span className="text-gray-700 dark:text-gray-300">{feature}</span>
                                            </li>
                                        ))}
                                    </ul>

                                    <button
                                        onClick={() => subscribe(plan.id)}
                                        className={`w-full py-2 font-medium rounded-lg transition-colors ${plan.popular
                                            ? 'bg-blue-600 hover:bg-blue-700 text-white'
                                            : 'bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 text-gray-900 dark:text-white'
                                            }`}
                                    >
                                        {plan.price === 0 ? 'Start Free' : 'Subscribe'}
                                    </button>
                                </div>
                            </div>
                        ))}
                    </div>
                )}
            </div>
        </div>
    );
}
