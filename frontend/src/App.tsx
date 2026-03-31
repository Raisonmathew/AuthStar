import React from 'react';
import { BrowserRouter, Routes, Route, Navigate, useParams } from 'react-router-dom';
import { Toaster } from 'sonner';
// CRITICAL-10+11 FIX: Wrap entire app with AuthProvider so all components
// get reactive auth state from memory (not localStorage/sessionStorage)
import { AuthProvider, useAuth } from './features/auth/AuthContext';
import UserLayout from './layouts/UserLayout';
import DashboardPage from './pages/DashboardPage';
import ProfilePage from './pages/ProfilePage';
import MFAEnrollmentPage from './pages/MFAEnrollmentPage';
import TeamManagementPage from './pages/TeamManagementPage';
import BillingPage from './features/billing/BillingPage';
import APIKeysPage from './pages/APIKeysPage';
import AdminLayout from './features/AdminLayout';
import AdminDashboardPage from './features/dashboard/AdminDashboardPage';
import AppRegistryPage from './features/apps/AppRegistryPage';
import { ConfigListPage } from './features/policy-builder/pages/ConfigListPage';
import { ConfigDetailPage } from './features/policy-builder/pages/ConfigDetailPage';
import AuditLogPage from './features/audit/AuditLogPage';
import BrandingPage from './features/settings/branding/BrandingPage';
import RolesPage from './features/settings/roles/RolesPage';
import RoleEditor from './features/settings/roles/RoleEditor';
import AuthFlowPage from './features/auth/AuthFlowPage';
import LoginMethodsPage from './features/settings/auth/LoginMethodsPage';
import DomainsPage from './features/settings/domains/DomainsPage';
import SSOPage from './features/settings/sso/SSOPage';
import StepUpModal from './features/auth/StepUpModal';
import InvitationAcceptPage from './pages/InvitationAcceptPage';
import './styles/globals.css';

// ---------------------------------------------------------------------------
// E-1 FIX: Global Error Boundary — prevents unhandled JS errors from showing
// a blank white screen. Catches render errors in any child component tree.
// ---------------------------------------------------------------------------
interface ErrorBoundaryState { hasError: boolean; error: Error | null }
class ErrorBoundary extends React.Component<
    { children: React.ReactNode },
    ErrorBoundaryState
> {
    constructor(props: { children: React.ReactNode }) {
        super(props);
        this.state = { hasError: false, error: null };
    }
    static getDerivedStateFromError(error: Error): ErrorBoundaryState {
        return { hasError: true, error };
    }
    componentDidCatch(error: Error, info: React.ErrorInfo) {
        console.error('[ErrorBoundary] Uncaught error:', error, info.componentStack);
    }
    render() {
        if (this.state.hasError) {
            return (
                <div className="min-h-screen bg-gray-950 flex items-center justify-center p-8">
                    <div className="max-w-md w-full bg-gray-900 rounded-xl p-8 border border-red-800 text-center">
                        <h1 className="text-2xl font-bold text-red-400 mb-3">Something went wrong</h1>
                        <p className="text-gray-400 text-sm mb-6">
                            An unexpected error occurred. Please reload the page.
                            If the problem persists, contact support.
                        </p>
                        <p className="text-gray-600 text-xs font-mono mb-6 break-all">
                            {this.state.error?.message}
                        </p>
                        <button
                            onClick={() => window.location.reload()}
                            className="bg-indigo-600 hover:bg-indigo-700 text-white px-6 py-2 rounded-lg text-sm font-medium"
                        >
                            Reload Page
                        </button>
                    </div>
                </div>
            );
        }
        return this.props.children;
    }
}

// ---------------------------------------------------------------------------
// E-2 FIX: AppLoadingGuard — prevents flash of login redirect during the
// initial silent refresh. AuthContext starts with isLoading=true; this guard
// shows a full-page spinner until the refresh completes (success or failure).
// Without this, protected routes render before auth state is known, causing
// a visible redirect flash to the login page on every page load.
// ---------------------------------------------------------------------------
function AppLoadingGuard({ children }: { children: React.ReactNode }) {
    const { isLoading } = useAuth();
    if (isLoading) {
        return (
            <div className="min-h-screen bg-gray-950 flex items-center justify-center">
                <div className="flex flex-col items-center gap-4">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-500" />
                    <p className="text-gray-500 text-sm">Loading...</p>
                </div>
            </div>
        );
    }
    return <>{children}</>;
}

// Helper for preserving slug in legacy redirects
function HostedRedirect() {
    const { slug } = useParams();
    return <Navigate to={`/u/${slug || 'default'}`} replace />;
}

function App() {
    return (
        // AuthProvider must wrap BrowserRouter so that useNavigate is available
        // inside AuthProvider's logout() if needed, and so all route components
        // can call useAuth() to get reactive auth state.
        <ErrorBoundary>
        <AuthProvider loginPath="/u/default">
        <BrowserRouter>
        <AppLoadingGuard>
            <Routes>
                <Route path="/" element={<Navigate to="/dashboard" replace />} />

                {/* EIAA-Compliant Auth Flow Routes */}
                <Route path="/u/:slug" element={<AuthFlowPage intent="login" />} />
                <Route path="/u/:slug/signup" element={<AuthFlowPage intent="signup" />} />
                <Route path="/u/:slug/reset-password" element={<AuthFlowPage intent="resetpassword" />} />

                {/* Invitation acceptance — standalone page (user might not be logged in) */}
                <Route path="/invitations/:token" element={<InvitationAcceptPage />} />

                {/* Legacy Redirects - Now Context Aware */}
                <Route path="/sign-in" element={<Navigate to="/u/default" replace />} />
                <Route path="/sign-up" element={<Navigate to="/u/default/signup" replace />} />
                <Route path="/hosted/:slug" element={<HostedRedirect />} />

                {/* User Area - Protected with UserLayout */}
                <Route element={<UserLayout />}>
                    <Route path="/dashboard" element={<DashboardPage />} />
                    <Route path="/profile" element={<ProfilePage />} />
                    <Route path="/security" element={<MFAEnrollmentPage />} />
                    <Route path="/team" element={<TeamManagementPage />} />
                    <Route path="/billing" element={<BillingPage />} />
                    <Route path="/api-keys" element={<APIKeysPage />} />
                    {/* STRUCT-5 FIX: Add /settings/* routes referenced by DashboardPage navigation.
                        Previously only /settings/roles existed; /settings/branding caused a blank page. */}
                    <Route path="/settings/roles" element={<RolesPage />} />
                    <Route path="/settings/roles/new" element={<RoleEditor />} />
                    <Route path="/settings/branding" element={<BrandingPage />} />
                    <Route path="/settings/domains" element={<DomainsPage />} />
                    <Route path="/settings/sso" element={<SSOPage />} />
                    <Route path="/settings/auth/login-methods" element={<LoginMethodsPage />} />
                </Route>

                {/* Admin Routes - EIAA Redirects */}
                <Route path="/admin" element={<Navigate to="/admin/dashboard" replace />} />
                <Route path="/admin/login" element={<Navigate to="/u/admin" replace />} />
                <Route path="/admin/signup" element={<Navigate to="/u/admin/signup" replace />} />

                {/* Protected Admin Area */}
                <Route path="/admin" element={<AdminLayout />}>
                    <Route path="dashboard" element={<AdminDashboardPage />} />
                    <Route path="apps" element={<AppRegistryPage />} />
                    <Route path="policies" element={<ConfigListPage />} />
                    <Route path="policies/:configId" element={<ConfigDetailPage />} />
                    <Route path="auth/login-methods" element={<LoginMethodsPage />} />
                    <Route path="audit" element={<AuditLogPage />} />
                    <Route path="branding" element={<BrandingPage />} />
                    <Route path="domains" element={<DomainsPage />} />
                    <Route path="sso" element={<SSOPage />} />
                </Route>
            </Routes>
            <StepUpModal />
            <Toaster position="top-right" />
        </AppLoadingGuard>
        </BrowserRouter>
        </AuthProvider>
        </ErrorBoundary>
    );
}

export default App;

