import FingerprintJS from '@fingerprintjs/fingerprintjs';

export interface DeviceSignals {
    user_agent: string;
    platform: string;
    screen_resolution?: string;
    locale: string;
    webauthn_available: boolean;
    device_cookie_id?: string;
}

// Initialize FingerprintJS agent
const fpPromise = FingerprintJS.load();

export async function getDeviceSignals(): Promise<DeviceSignals> {
    const fp = await fpPromise;
    const result = await fp.get();

    // Get basic browser signals
    const user_agent = navigator.userAgent;
    const platform = navigator.platform;
    const locale = navigator.language;
    const screen_resolution = `${window.screen.width}x${window.screen.height}`;

    // Check WebAuthn availability
    let webauthn_available = false;
    try {
        if (window.PublicKeyCredential) {
            webauthn_available = await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
        }
    } catch (e) {
        console.warn('WebAuthn check failed', e);
    }

    // Use FingerprintJS visitorId as a persistent device identifier
    // In a real implementation, you might want to store a long-lived cookie as well
    const device_cookie_id = result.visitorId;

    return {
        user_agent,
        platform,
        screen_resolution,
        locale,
        webauthn_available,
        device_cookie_id
    };
}
