import React, { createContext, useContext } from 'react';
import IDaaSClient from '@idaas/client';

export interface IDaaSConfig {
    publishableKey: string;
    apiUrl?: string; // Optional override
}

interface IDaaSContextType {
    config: IDaaSConfig;
    client: IDaaSClient;
}

const IDaaSContext = createContext<IDaaSContextType | undefined>(undefined);

export interface IDaaSProviderProps {
    publishableKey: string;
    apiUrl?: string; // Optional override for self-hosted
    children: React.ReactNode;
}

/**
 * Parse publishable key to extract instance ID and environment
 * Format: pk_{env}_{instanceId}
 * Example: pk_live_acme123 -> { env: 'live', instanceId: 'acme123' }
 */
function parsePublishableKey(key: string): { env: string; instanceId: string; apiUrl: string } {
    const parts = key.split('_');

    if (parts.length < 3 || parts[0] !== 'pk') {
        throw new Error('Invalid publishable key format. Expected: pk_{env}_{instanceId}');
    }

    const env = parts[1]; // 'test' or 'live'
    const instanceId = parts.slice(2).join('_'); // Everything after env

    // Map to API URL based on environment
    const apiUrl = env === 'test'
        ? `https://${instanceId}.idaas-test.dev`
        : `https://${instanceId}.idaas.app`;

    return { env, instanceId, apiUrl };
}

/**
 * IDaaS Provider - Wrap your app with this to configure IDaaS globally
 * 
 * @example
 * ```tsx
 * <IDaaSProvider publishableKey="pk_live_acme123">
 *   <App />
 * </IDaaSProvider>
 * ```
 */
export function IDaaSProvider({ publishableKey, apiUrl: apiUrlOverride, children }: IDaaSProviderProps) {
    // Parse key to get API URL
    const { apiUrl: parsedApiUrl } = parsePublishableKey(publishableKey);
    const apiUrl = apiUrlOverride || parsedApiUrl;

    const config: IDaaSConfig = { publishableKey, apiUrl };
    const client = new IDaaSClient({ apiUrl, apiKey: publishableKey });

    // Start automatic token refresh
    React.useEffect(() => {
        const interval = setInterval(() => {
            const jwt = sessionStorage.getItem('jwt');
            if (jwt) {
                client.refreshToken().catch(() => {
                    // Token refresh failed, user might need to re-authenticate
                });
            }
        }, 50000); // Refresh every 50 seconds

        return () => clearInterval(interval);
    }, [client]);

    return (
        <IDaaSContext.Provider value={{ config, client }}>
            {children}
        </IDaaSContext.Provider>
    );
}

/**
 * Hook to access IDaaS configuration and client
 */
export function useIDaaS() {
    const context = useContext(IDaaSContext);
    if (!context) {
        throw new Error('useIDaaS must be used within IDaaSProvider');
    }
    return context;
}
