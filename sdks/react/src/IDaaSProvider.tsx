import React, { createContext, useContext, useState, useEffect } from 'react';
import { IDaaSClient } from '@idaas/core';
import type { SdkManifest } from '@idaas/core';

export interface IDaaSConfig {
    publishableKey: string;
    apiUrl?: string;
}

interface IDaaSContextType {
    config: IDaaSConfig;
    client: IDaaSClient;
    manifest: SdkManifest | null;
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

    const env = parts[1];
    const instanceId = parts.slice(2).join('_');

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
    const { apiUrl: parsedApiUrl, instanceId } = parsePublishableKey(publishableKey);
    const apiUrl = apiUrlOverride || parsedApiUrl;

    const config: IDaaSConfig = { publishableKey, apiUrl };
    const client = new IDaaSClient({ apiUrl, apiKey: publishableKey });

    const [manifest, setManifest] = useState<SdkManifest | null>(null);

    // Fetch tenant manifest on mount to get branding + field config.
    useEffect(() => {
        client.getManifest(instanceId).then(setManifest).catch(() => {
            // Non-fatal: SDK works without manifest (defaults applied)
        });
    }, [instanceId]);

    // Proactive token refresh (browser mode)
    useEffect(() => {
        const interval = setInterval(() => {
            const jwt = sessionStorage.getItem('jwt');
            if (jwt) {
                client.refreshToken().catch(() => {});
            }
        }, 50000);
        return () => clearInterval(interval);
    }, [client]);

    // Apply branding CSS custom properties from manifest
    const brandingStyle = manifest?.branding
        ? ({
              '--idaas-primary': manifest.branding.primary_color,
              '--idaas-bg': manifest.branding.background_color,
              '--idaas-text': manifest.branding.text_color,
              '--idaas-font': manifest.branding.font_family,
          } as React.CSSProperties)
        : undefined;

    return (
        <IDaaSContext.Provider value={{ config, client, manifest }}>
            <div style={brandingStyle}>
                {children}
            </div>
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
