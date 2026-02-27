import { useState } from 'react';
import { User } from '../types';

interface AuthState {
    user: User | null;
    token: string | null;
    isAuthenticated: boolean;
    organizationId: string | null;
}

export function useAuth() {
    const [auth] = useState<AuthState>(() => {
        const adminToken = localStorage.getItem('admin_token');
        const adminUserStr = localStorage.getItem('admin_user');

        const tenantToken = sessionStorage.getItem('jwt');
        const tenantUserStr = sessionStorage.getItem('auth_user');

        const token = adminToken || tenantToken;
        const userStr = adminUserStr || tenantUserStr;

        let user: User | null = null;
        try {
            if (userStr) {
                user = JSON.parse(userStr);
            }
        } catch (e) {
            console.error('Failed to parse user from storage', e);
        }

        return {
            token,
            user,
            isAuthenticated: !!token,
            organizationId: user?.organization_id || null
        };
    });

    return auth;
}
