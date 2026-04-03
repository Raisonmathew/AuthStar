import { useState, useEffect } from 'react';
import { Outlet, Link, useNavigate, useLocation } from 'react-router-dom';
import { toast } from 'sonner';
// FIX BUG-4+5: Use AuthContext for auth guard and logout.
// Previously used sessionStorage.getItem('jwt') which is always null after the
// CRITICAL-10+11 fix (JWTs are now stored in-memory only, never in Web Storage).
// This caused the admin area to immediately redirect to login on every page load.
import { useAuth } from './auth/AuthContext';

// Icons (inline SVG for simplicity)
const Icons = {
    dashboard: <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 5a1 1 0 011-1h14a1 1 0 011 1v2a1 1 0 01-1 1H5a1 1 0 01-1-1V5zM4 13a1 1 0 011-1h6a1 1 0 011 1v6a1 1 0 01-1 1H5a1 1 0 01-1-1v-6zM16 13a1 1 0 011-1h2a1 1 0 011 1v6a1 1 0 01-1 1h-2a1 1 0 01-1-1v-6z" /></svg>,
    apps: <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z" /></svg>,
    policy: <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>,
    audit: <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01" /></svg>,
    branding: <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7 21a4 4 0 01-4-4V5a2 2 0 012-2h4a2 2 0 012 2v12a4 4 0 01-4 4zm0 0h12a2 2 0 002-2v-4a2 2 0 00-2-2h-2.343M11 7.343l1.657-1.657a2 2 0 012.828 0l2.829 2.829a2 2 0 010 2.828l-8.486 8.485M7 17h.01" /></svg>,
    domain: <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" /></svg>,
    sso: <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z" /></svg>,
    // P2-5 FIX: Added loginMethods icon for the new sidebar nav item
    loginMethods: <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>,
    logout: <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" /></svg>,
    menu: <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 6h16M4 12h16M4 18h16" /></svg>,
    close: <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M6 18L18 6M6 6l12 12" /></svg>
};

export default function AdminLayout() {
    const navigate = useNavigate();
    const location = useLocation();
    const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
    // FIX BUG-4: Read auth state from in-memory AuthContext, not sessionStorage
    const { isAuthenticated, isLoading, user, logout, token } = useAuth();

    // Protect Admin Routes
    // FIX BUG-4: Guard against the in-memory token being absent.
    // isLoading=true during the initial silent refresh — wait for it to complete
    // before deciding to redirect, to avoid a flash redirect on page reload.
    useEffect(() => {
        if (!isLoading && !isAuthenticated) {
            navigate('/u/admin');
            return;
        }
        // Defense-in-depth: check JWT session_type is 'admin'.
        // Backend EIAA is the real enforcement; this prevents accidental navigation.
        if (!isLoading && isAuthenticated && token) {
            try {
                const payload = JSON.parse(atob(token.split('.')[1]));
                if (payload.session_type !== 'admin') {
                    navigate('/dashboard');
                }
            } catch {
                // Malformed token — let backend reject on next API call
            }
        }
    }, [isAuthenticated, isLoading, navigate, token]);

    const handleLogout = () => {
        // FIX BUG-5: Use AuthContext logout() which:
        //   1. Clears the in-memory JWT
        //   2. Calls POST /api/v1/logout to invalidate the HttpOnly refresh cookie
        //   3. Redirects to the login path configured in AuthProvider
        // Previously this only cleared sessionStorage (which no longer holds the JWT)
        // so the user remained authenticated in memory.
        logout();
        toast.success('Logged out');
    };

    const navItems = [
        { name: 'Dashboard', path: '/admin/dashboard', icon: Icons.dashboard },
        { name: 'App Registry', path: '/admin/apps', icon: Icons.apps },
        { name: 'Policies', path: '/admin/policies', icon: Icons.policy },
        { name: 'Audit Logs', path: '/admin/audit', icon: Icons.audit },
        { name: 'Branding', path: '/admin/branding', icon: Icons.branding },
        { name: 'Custom Domains', path: '/admin/domains', icon: Icons.domain },
        { name: 'SSO Connections', path: '/admin/sso', icon: Icons.sso },
        // P2-5 FIX: Add Login Methods to sidebar — route exists in App.tsx but was missing from nav
        { name: 'Login Methods', path: '/admin/auth/login-methods', icon: Icons.loginMethods },
    ];

    return (
        <div className="min-h-screen bg-slate-900 font-sans text-slate-100 flex overflow-hidden">
            {/* Mobile Menu Backdrop */}
            {isMobileMenuOpen && (
                <div
                    className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 lg:hidden"
                    onClick={() => setIsMobileMenuOpen(false)}
                />
            )}

            {/* Sidebar */}
            <aside
                className={`
                    fixed inset-y-0 left-0 z-50 w-72 bg-slate-900 border-r border-slate-800 transform transition-transform duration-300 ease-in-out
                    flex flex-col
                    ${isMobileMenuOpen ? 'translate-x-0' : '-translate-x-full'}
                    lg:static lg:translate-x-0
                `}
            >
                {/* Logo Area */}
                <div className="h-16 flex items-center px-6 border-b border-slate-800 bg-slate-900/50 backdrop-blur-xl">
                    <div className="flex items-center gap-3">
                        <div className="w-8 h-8 rounded-lg bg-gradient-to-tr from-indigo-500 to-purple-500 flex items-center justify-center shadow-lg shadow-indigo-500/20">
                            <span className="font-heading font-bold text-white text-lg leading-none">ID</span>
                        </div>
                        <div>
                            <h1 className="font-heading font-bold text-lg text-white leading-none">IDaaS Admin</h1>
                            <span className="text-[10px] font-medium text-slate-500 tracking-wider uppercase">Enterprise</span>
                        </div>
                    </div>
                </div>

                {/* Navigation */}
                <nav className="flex-1 overflow-y-auto py-6 px-3 space-y-1">
                    {navItems.map((item) => {
                        const isActive = location.pathname.startsWith(item.path);
                        return (
                            <Link
                                key={item.path}
                                to={item.path}
                                onClick={() => setIsMobileMenuOpen(false)}
                                className={`flex items-center gap-3 px-3 py-2.5 rounded-xl transition-all duration-200 group ${isActive
                                    ? 'bg-indigo-500/10 text-indigo-400'
                                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800/50'
                                    }`}
                            >
                                <div className={`p-1.5 rounded-lg transition-colors ${isActive ? 'bg-indigo-500/20 text-indigo-400' : 'bg-slate-800/50 text-slate-500 group-hover:text-slate-300'
                                    }`}>
                                    {item.icon}
                                </div>
                                <span className={`font-medium ${isActive ? 'font-semibold' : ''}`}>{item.name}</span>
                                {isActive && (
                                    <div className="ml-auto w-1.5 h-1.5 rounded-full bg-indigo-500 shadow-[0_0_8px_rgba(99,102,241,0.6)]" />
                                )}
                            </Link>
                        );
                    })}
                </nav>

                {/* User Profile / Logout */}
                <div className="p-4 border-t border-slate-800 bg-slate-900/50">
                    <button
                        onClick={handleLogout}
                        className="flex items-center gap-3 w-full p-2 rounded-xl text-slate-400 hover:text-red-400 hover:bg-red-500/5 transition-colors group"
                    >
                        <div className="p-1.5 rounded-lg bg-slate-800/50 text-slate-500 group-hover:text-red-400 group-hover:bg-red-500/10 transition-colors">
                            {Icons.logout}
                        </div>
                        <div className="flex-1 text-left">
                            {/* FIX BUG-4: Show real user name from AuthContext instead of hardcoded "Admin User" */}
                            <p className="text-sm font-medium text-slate-200">
                                {user?.first_name && user?.last_name
                                    ? `${user.first_name} ${user.last_name}`
                                    : user?.email?.split('@')[0] || 'Admin User'}
                            </p>
                            <p className="text-xs text-slate-500">Sign out</p>
                        </div>
                    </button>
                </div>
            </aside>

            {/* Main Content Area */}
            <div className="flex-1 flex flex-col min-w-0 bg-slate-950 overflow-hidden">
                {/* Mobile Header */}
                <header className="h-16 flex items-center justify-between px-4 border-b border-slate-800 bg-slate-900/50 backdrop-blur-md lg:hidden z-30 sticky top-0">
                    <div className="flex items-center gap-3">
                        <button
                            onClick={() => setIsMobileMenuOpen(true)}
                            className="p-2 -ml-2 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800"
                        >
                            {Icons.menu}
                        </button>
                        <span className="font-heading font-bold text-lg text-white">
                            {navItems.find(i => location.pathname.startsWith(i.path))?.name}
                        </span>
                    </div>
                </header>

                {/* Content Scroll Area */}
                <main className="flex-1 overflow-y-auto p-4 lg:p-8 scroll-smooth">
                    <div className="max-w-7xl mx-auto space-y-8">
                        {/* Desktop Header */}
                        <div className="hidden lg:flex items-center justify-between mb-8">
                            <div>
                                <h2 className="font-heading text-2xl font-bold text-white tracking-tight">
                                    {navItems.find(i => location.pathname.startsWith(i.path))?.name || 'Dashboard'}
                                </h2>
                                <p className="text-sm text-slate-400 mt-1">Manage your identity platform</p>
                            </div>
                            <div className="flex gap-4">
                                <div className="h-9 px-3 flex items-center gap-2 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-medium">
                                    <span className="relative flex h-2 w-2">
                                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                                        <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                                    </span>
                                    System Operational
                                </div>
                            </div>
                        </div>

                        <Outlet />
                    </div>
                </main>
            </div>
        </div>
    );
}
