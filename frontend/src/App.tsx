import { BrowserRouter, Routes, Route, Navigate, useParams } from 'react-router-dom';
import { Toaster } from 'sonner';
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
import { AdminPoliciesPage } from './pages/AdminPoliciesPage';
import AuditLogPage from './features/audit/AuditLogPage';
import BrandingPage from './features/settings/branding/BrandingPage';
import RolesPage from './features/settings/roles/RolesPage';
import RoleEditor from './features/settings/roles/RoleEditor';
import AuthFlowPage from './features/auth/AuthFlowPage';
import LoginMethodsPage from './features/settings/auth/LoginMethodsPage';
import DomainsPage from './features/settings/domains/DomainsPage';
import SSOPage from './features/settings/sso/SSOPage';
import StepUpModal from './features/auth/StepUpModal';
import './styles/globals.css';

// Helper for preserving slug in legacy redirects
function HostedRedirect() {
    const { slug } = useParams();
    return <Navigate to={`/u/${slug || 'default'}`} replace />;
}

function App() {
    return (
        <BrowserRouter>
            <Routes>
                <Route path="/" element={<Navigate to="/dashboard" replace />} />

                {/* EIAA-Compliant Auth Flow Routes */}
                <Route path="/u/:slug" element={<AuthFlowPage intent="login" />} />
                <Route path="/u/:slug/signup" element={<AuthFlowPage intent="signup" />} />
                <Route path="/u/:slug/reset-password" element={<AuthFlowPage intent="resetpassword" />} />

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
                    <Route path="/settings/roles" element={<RolesPage />} />
                    <Route path="/settings/roles/new" element={<RoleEditor />} />
                </Route>

                {/* Admin Routes - EIAA Redirects */}
                <Route path="/admin" element={<Navigate to="/admin/dashboard" replace />} />
                <Route path="/admin/login" element={<Navigate to="/u/admin" replace />} />
                <Route path="/admin/signup" element={<Navigate to="/u/admin/signup" replace />} />

                {/* Protected Admin Area */}
                <Route path="/admin" element={<AdminLayout />}>
                    <Route path="dashboard" element={<AdminDashboardPage />} />
                    <Route path="apps" element={<AppRegistryPage />} />
                    <Route path="policies" element={<AdminPoliciesPage />} />
                    <Route path="auth/login-methods" element={<LoginMethodsPage />} />
                    <Route path="audit" element={<AuditLogPage />} />
                    <Route path="branding" element={<BrandingPage />} />
                    <Route path="domains" element={<DomainsPage />} />
                    <Route path="sso" element={<SSOPage />} />
                </Route>
            </Routes>
            <StepUpModal />
            <Toaster position="top-right" />
        </BrowserRouter>
    );
}

export default App;

