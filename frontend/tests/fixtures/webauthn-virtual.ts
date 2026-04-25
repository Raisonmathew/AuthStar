/**
 * WebAuthn Virtual Authenticator — CDP-based
 *
 * Uses Chrome DevTools Protocol `WebAuthn` domain to add a virtual
 * authenticator to the browser.  This is the proper E2E approach:
 * the browser's real WebAuthn stack runs, but backed by a virtual device
 * rather than hardware.
 *
 * Usage:
 *   const auth = await addVirtualAuthenticator(page);
 *   // … perform passkey registration / login …
 *   await removeVirtualAuthenticator(page, auth.authenticatorId);
 */

import { Page, CDPSession } from '@playwright/test';

export interface VirtualAuthenticatorOptions {
    /** 'ctap2' (default) or 'u2f' */
    protocol?: 'ctap2' | 'u2f';
    /** 'usb' | 'ble' | 'nfc' | 'internal' (default: 'internal') */
    transport?: 'usb' | 'ble' | 'nfc' | 'internal';
    /** Whether the authenticator supports resident keys (default: true) */
    hasResidentKey?: boolean;
    /** Whether the authenticator supports user verification (default: true) */
    hasUserVerification?: boolean;
    /** Whether user verification is simulated as passing (default: true) */
    isUserVerified?: boolean;
}

export interface VirtualAuthenticator {
    authenticatorId: string;
    cdpSession: CDPSession;
}

/**
 * Enable the WebAuthn domain and add a virtual authenticator.
 */
export async function addVirtualAuthenticator(
    page: Page,
    opts: VirtualAuthenticatorOptions = {},
): Promise<VirtualAuthenticator> {
    const cdpSession = await page.context().newCDPSession(page);

    await cdpSession.send('WebAuthn.enable');

    const result = await cdpSession.send('WebAuthn.addVirtualAuthenticator', {
        options: {
            protocol: opts.protocol ?? 'ctap2',
            transport: opts.transport ?? 'internal',
            hasResidentKey: opts.hasResidentKey ?? true,
            hasUserVerification: opts.hasUserVerification ?? true,
            isUserVerified: opts.isUserVerified ?? true,
        },
    });

    return {
        authenticatorId: result.authenticatorId,
        cdpSession,
    };
}

/**
 * Remove a virtual authenticator and disable the WebAuthn domain.
 */
export async function removeVirtualAuthenticator(
    page: Page,
    auth: VirtualAuthenticator,
): Promise<void> {
    await auth.cdpSession.send('WebAuthn.removeVirtualAuthenticator', {
        authenticatorId: auth.authenticatorId,
    });
    await auth.cdpSession.send('WebAuthn.disable');
    await auth.cdpSession.detach();
}

/**
 * Get all credentials stored in the virtual authenticator.
 */
export async function getCredentials(
    auth: VirtualAuthenticator,
): Promise<Array<{ credentialId: string; rpId: string; userHandle: string }>> {
    const result = await auth.cdpSession.send('WebAuthn.getCredentials', {
        authenticatorId: auth.authenticatorId,
    });
    return (result.credentials ?? []).map((c: any) => ({
        credentialId: c.credentialId,
        rpId: c.rpId,
        userHandle: c.userHandle,
    }));
}

/**
 * Clear all credentials from the virtual authenticator.
 */
export async function clearCredentials(
    auth: VirtualAuthenticator,
): Promise<void> {
    await auth.cdpSession.send('WebAuthn.clearCredentials', {
        authenticatorId: auth.authenticatorId,
    });
}

/**
 * Set whether the virtual authenticator should simulate user verification
 * as succeeding or failing.
 */
export async function setUserVerified(
    auth: VirtualAuthenticator,
    verified: boolean,
): Promise<void> {
    await auth.cdpSession.send('WebAuthn.setUserVerified', {
        authenticatorId: auth.authenticatorId,
        isUserVerified: verified,
    });
}
