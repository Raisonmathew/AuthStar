import React, { createContext, useContext, useState, useEffect, useMemo, useRef } from 'react';
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

// Exported so consumers can read the context conditionally without violating
// the Rules of Hooks (e.g. UserButton which can fall back to a propApiUrl).
export const IDaaSContext = createContext<IDaaSContextType | undefined>(undefined);

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

    // Memoize so identity is stable across renders. Recreating IDaaSClient
    // on every render previously caused the manifest fetch and token-refresh
    // interval to re-arm continuously — leaking timers and triggering a
    // "thundering herd" of refresh calls.
    const config = useMemo<IDaaSConfig>(
        () => ({ publishableKey, apiUrl }),
        [publishableKey, apiUrl],
    );
    const client = useMemo(
        () => new IDaaSClient({ apiUrl, apiKey: publishableKey }),
        [apiUrl, publishableKey],
    );

    const [manifest, setManifest] = useState<SdkManifest | null>(null);

    // Fetch tenant manifest on mount; cancel via flag if unmounted before resolve.
    useEffect(() => {
        let cancelled = false;
        client
            .getManifest(instanceId)
            .then((m) => {
                if (!cancelled) setManifest(m);
            })
            .catch(() => {
                // Non-fatal: SDK works without manifest (defaults applied)
            });
        return () => {
            cancelled = true;
        };
    }, [client, instanceId]);

    // Proactive token refresh (browser mode).
    //
    // Adds ±10% jitter to the 50s base interval so a fleet of tabs/devices
    // doesn't synchronize on the same refresh tick after a coordinated event
    // (e.g. browser wake from sleep, page reload after deploy).
    const inflightRef = useRef(false);
    useEffect(() => {
        const baseMs = 50_000;
        const jitter = () => baseMs * (0.9 + Math.random() * 0.2); // 45s–55s
        let timer: ReturnType<typeof setTimeout> | undefined;
        let cancelled = false;
        const schedule = () => {
            if (cancelled) return;
            timer = setTimeout(async () => {
                if (cancelled) return;
                if (!inflightRef.current && sessionStorage.getItem('jwt')) {
                    inflightRef.current = true;
                    try {
                        await client.refreshToken();
                    } catch {
                        // Network/auth failure — caller will surface on next API call
                    } finally {
                        inflightRef.current = false;
                    }
                }
                schedule();
            }, jitter());
        };
        schedule();
        return () => {
            cancelled = true;
            if (timer) clearTimeout(timer);
        };
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

    const ctxValue = useMemo(
        () => ({ config, client, manifest }),
        [config, client, manifest],
    );

    return (
        <IDaaSContext.Provider value={ctxValue}>
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
