import { useEffect, useState } from 'react';

interface StatCard {
    name: string;
    value: string;
    change: string;
    trend: 'up' | 'down' | 'neutral';
    icon: React.ReactNode;
    color: string;
}

export default function AdminDashboardPage() {
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        // Simulate loading
        setTimeout(() => setLoading(false), 500);
    }, []);

    const stats: StatCard[] = [
        {
            name: 'Total Users',
            value: '12,847',
            change: '+12.5%',
            trend: 'up',
            color: 'from-blue-500 to-blue-600',
            icon: <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" /></svg>,
        },
        {
            name: 'Active Sessions',
            value: '2,156',
            change: '+8.2%',
            trend: 'up',
            color: 'from-emerald-500 to-emerald-600',
            icon: <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>,
        },
        {
            name: 'Policy Executions',
            value: '89,421',
            change: '+24.3%',
            trend: 'up',
            color: 'from-purple-500 to-purple-600',
            icon: <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>,
        },
        {
            name: 'SSO Logins',
            value: '4,582',
            change: '+5.7%',
            trend: 'up',
            color: 'from-amber-500 to-orange-600',
            icon: <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" /></svg>,
        },
    ];

    const recentActivity = [
        { action: 'New user registered', user: 'john.doe@example.com', time: '2 minutes ago', type: 'user' },
        { action: 'SSO login via Okta', user: 'sarah.smith@corp.com', time: '5 minutes ago', type: 'sso' },
        { action: 'Policy updated', user: 'admin@platform.io', time: '12 minutes ago', type: 'policy' },
        { action: 'Password reset requested', user: 'mike.jones@example.com', time: '18 minutes ago', type: 'security' },
        { action: 'New app registered', user: 'admin@platform.io', time: '25 minutes ago', type: 'app' },
    ];

    const getActivityIcon = (type: string) => {
        switch (type) {
            case 'user': return <div className="w-8 h-8 rounded-full bg-blue-500/20 flex items-center justify-center"><svg className="w-4 h-4 text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" /></svg></div>;
            case 'sso': return <div className="w-8 h-8 rounded-full bg-emerald-500/20 flex items-center justify-center"><svg className="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" /></svg></div>;
            case 'policy': return <div className="w-8 h-8 rounded-full bg-purple-500/20 flex items-center justify-center"><svg className="w-4 h-4 text-purple-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg></div>;
            case 'security': return <div className="w-8 h-8 rounded-full bg-amber-500/20 flex items-center justify-center"><svg className="w-4 h-4 text-amber-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg></div>;
            default: return <div className="w-8 h-8 rounded-full bg-slate-500/20 flex items-center justify-center"><svg className="w-4 h-4 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6z" /></svg></div>;
        }
    };

    if (loading) {
        return (
            <div className="flex items-center justify-center h-64">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500"></div>
            </div>
        );
    }

    return (
        <div className="space-y-6 lg:space-y-8">
            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 lg:gap-6">
                {stats.map((stat) => (
                    <div
                        key={stat.name}
                        className="relative overflow-hidden bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-slate-700/50 hover:border-slate-600/50 transition-all duration-300 group"
                    >
                        {/* Gradient accent */}
                        <div className={`absolute top-0 right-0 w-32 h-32 bg-gradient-to-br ${stat.color} opacity-10 rounded-full -translate-y-16 translate-x-16 group-hover:opacity-20 transition-opacity`}></div>

                        <div className="flex items-start justify-between relative z-10">
                            <div>
                                <p className="text-sm font-medium text-slate-400 font-heading">{stat.name}</p>
                                <p className="text-3xl font-bold text-white mt-2 font-heading tracking-tight">{stat.value}</p>
                                <div className="flex items-center mt-2 gap-1">
                                    {stat.trend === 'up' && (
                                        <svg className="w-4 h-4 text-emerald-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 10l7-7m0 0l7 7m-7-7v18" /></svg>
                                    )}
                                    <span className={`text-sm font-bold ${stat.trend === 'up' ? 'text-emerald-400' : 'text-red-400'}`}>
                                        {stat.change}
                                    </span>
                                    <span className="text-xs text-slate-500 font-medium ml-1">vs last month</span>
                                </div>
                            </div>
                            <div className={`p-3 rounded-xl bg-gradient-to-br ${stat.color} shadow-lg shadow-black/20 group-hover:scale-110 transition-transform duration-300`}>
                                <div className="text-white">{stat.icon}</div>
                            </div>
                        </div>
                    </div>
                ))}
            </div>

            {/* Main Content Row */}
            <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
                {/* Activity Chart Placeholder */}
                <div className="xl:col-span-2 bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-slate-700/50">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-6">
                        <div>
                            <h3 className="text-lg font-bold text-white font-heading">Authentication Activity</h3>
                            <p className="text-sm text-slate-400">Login volume over time</p>
                        </div>
                        <select className="bg-slate-700/50 text-white text-sm rounded-xl px-4 py-2 border border-slate-600/50 focus:ring-2 focus:ring-indigo-500 focus:border-transparent outline-none cursor-pointer hover:bg-slate-700 transition-colors">
                            <option>Last 7 days</option>
                            <option>Last 30 days</option>
                            <option>Last 90 days</option>
                        </select>
                    </div>

                    {/* Simple bar chart visualization */}
                    <div className="flex items-end justify-between h-56 gap-2 sm:gap-4 px-2 sm:px-4 pt-4 border-t border-slate-700/30">
                        {[65, 45, 80, 55, 95, 70, 85].map((height, i) => (
                            <div key={i} className="flex-1 flex flex-col items-center gap-3 group cursor-pointer">
                                <div className="relative w-full flex-1 flex items-end">
                                    <div
                                        className="w-full bg-gradient-to-t from-indigo-600/80 to-indigo-400/80 rounded-t-lg transition-all duration-300 group-hover:from-indigo-500 group-hover:to-indigo-300 group-hover:shadow-[0_0_15px_rgba(99,102,241,0.3)]"
                                        style={{ height: `${height}%` }}
                                    ></div>
                                    <div className="absolute -top-8 left-1/2 -translate-x-1/2 bg-slate-900 text-white text-xs py-1 px-2 rounded opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap border border-slate-700 shadow-xl z-20">
                                        {height * 12} logins
                                    </div>
                                </div>
                                <span className="text-xs font-medium text-slate-500 group-hover:text-indigo-400 transition-colors">{['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][i]}</span>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Recent Activity */}
                <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-slate-700/50 flex flex-col">
                    <h3 className="text-lg font-bold text-white font-heading mb-6">Recent Activity</h3>
                    <div className="space-y-6 flex-1">
                        {recentActivity.map((activity, i) => (
                            <div key={i} className="flex items-start gap-4 group">
                                <div className="mt-1 relative">
                                    {getActivityIcon(activity.type)}
                                    {i !== recentActivity.length - 1 && (
                                        <div className="absolute top-8 left-1/2 -translate-x-1/2 w-px h-full bg-slate-700/50 -mb-4"></div>
                                    )}
                                </div>
                                <div className="flex-1 min-w-0 pt-0.5">
                                    <p className="text-sm text-white font-medium group-hover:text-indigo-300 transition-colors">{activity.action}</p>
                                    <p className="text-xs text-slate-400 truncate mt-0.5">{activity.user}</p>
                                </div>
                                <span className="text-xs text-slate-500 whitespace-nowrap pt-1 font-medium bg-slate-800/50 px-2 py-0.5 rounded">{activity.time}</span>
                            </div>
                        ))}
                    </div>
                    <button className="w-full mt-6 py-3 rounded-xl text-sm font-medium text-indigo-300 bg-indigo-500/10 border border-indigo-500/20 hover:bg-indigo-500/20 hover:border-indigo-500/30 transition-all duration-200">
                        View Full History
                    </button>
                </div>
            </div>

            {/* Quick Actions */}
            <div className="bg-slate-800/50 backdrop-blur-sm rounded-2xl p-6 border border-slate-700/50">
                <h3 className="text-lg font-bold text-white font-heading mb-4">Quick Actions</h3>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                    {[
                        { name: 'Add User', icon: '👤', color: 'from-blue-500 to-blue-600', desc: 'Invite new member' },
                        { name: 'Create Policy', icon: '🛡️', color: 'from-purple-500 to-purple-600', desc: 'Define access rules' },
                        { name: 'Configure SSO', icon: '🔑', color: 'from-amber-500 to-orange-600', desc: 'Connect providers' },
                        { name: 'View Audit Log', icon: '📋', color: 'from-emerald-500 to-emerald-600', desc: 'Check system logs' },
                    ].map((action) => (
                        <button
                            key={action.name}
                            className="flex items-center gap-4 p-4 bg-slate-800 hover:bg-slate-700/80 rounded-xl border border-slate-700/50 hover:border-slate-600 transition-all duration-200 group text-left"
                        >
                            <span className={`w-12 h-12 rounded-xl bg-gradient-to-br ${action.color} flex items-center justify-center text-2xl shadow-lg group-hover:scale-105 transition-transform`}>
                                {action.icon}
                            </span>
                            <div>
                                <span className="block text-sm font-bold text-white font-heading">{action.name}</span>
                                <span className="text-xs text-slate-400 group-hover:text-slate-300">{action.desc}</span>
                            </div>
                        </button>
                    ))}
                </div>
            </div>
        </div>
    );
}

