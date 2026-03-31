import type { SdkManifest } from './types';

const FLOW_API = '/api/auth/flow';

// ─── Event Detail Types ───────────────────────────────────────────────────────

export interface FlowStepEvent {
    step: unknown;         // UiStep from backend — typed by consumers
    manifest: SdkManifest | null;
    flowId: string;
}

export interface FlowDecisionEvent {
    decisionRef: string;
    achievedAal?: string;
}

export interface FlowErrorEvent {
    message: string;
    recoverable: boolean;
}

// ─── FlowManager ─────────────────────────────────────────────────────────────

/**
 * FSM wrapper over the IDaaS EIAA flow REST API.
 *
 * Fires DOM-style events so it works without any framework:
 *  - `"step"` — a new UI step is ready to render
 *  - `"decision"` — flow is complete, decision_ref is available
 *  - `"error"` — a recoverable or fatal error occurred
 *
 * @example
 * ```ts
 * const fm = new FlowManager({ apiUrl: 'https://api.example.com', orgId: 'my-org' });
 * fm.addEventListener('step', e => renderStep(e.detail.step, e.detail.manifest));
 * fm.addEventListener('decision', e => completeSignIn(e.detail.decisionRef));
 * await fm.init();
 * ```
 */
export class FlowManager extends EventTarget {
    private readonly apiUrl: string;
    private readonly orgId: string;
    private flowId: string | null = null;
    private flowToken: string | null = null;
    private manifest: SdkManifest | null = null;

    constructor(config: { apiUrl: string; orgId: string }) {
        super();
        this.apiUrl = config.apiUrl.replace(/\/$/, '');
        this.orgId = config.orgId;
    }

    // ─── Public API ───────────────────────────────────────────────────────────

    /** Initialise a new authentication flow for the configured org. */
    async init(): Promise<void> {
        const data = await this.post(`${FLOW_API}/init`, {
            org_id: this.orgId,
        });

        this.flowId = (data.flow_id as string) ?? null;
        this.flowToken = (data.flow_token as string) ?? null;
        this.manifest = (data.manifest as SdkManifest) ?? null;

        if (data.ui_step) {
            this.emitStep(data.ui_step);
        }
    }

    /**
     * Identify the user by their email / username.
     * Fires `"step"` with the next challenge (e.g. password, passkey, OTP).
     */
    async identify(identifier: string): Promise<void> {
        this.assertInitialised();
        const data = await this.post(
            `${FLOW_API}/${this.flowId}/identify`,
            { identifier },
        );
        this.handleStepResponse(data);
    }

    /**
     * Submit a response for the current step.
     * @param capability - EIAA capability string (e.g. `"Password"`, `"Totp"`, `"Passkey"`)
     * @param value      - credential value or OTP code
     */
    async submit(capability: string, value: string): Promise<void> {
        this.assertInitialised();
        const data = await this.post(
            `${FLOW_API}/${this.flowId}/submit`,
            { capability, value },
        );
        this.handleStepResponse(data);
    }

    /**
     * Complete the flow. Only valid after the backend returns `decision_ref`.
     * For signup flows the frontend must call `commitDecision` separately.
     */
    async get(): Promise<void> {
        this.assertInitialised();
        const data = await this.fetch(`${FLOW_API}/${this.flowId}`);
        this.handleStepResponse(data);
    }

    // ─── Private Helpers ──────────────────────────────────────────────────────

    private handleStepResponse(data: Record<string, unknown>): void {
        if (data.decision_ref) {
            this.dispatchEvent(
                Object.assign(new Event('decision'), {
                    detail: {
                        decisionRef: data.decision_ref as string,
                        achievedAal: data.achieved_aal as string | undefined,
                    } satisfies FlowDecisionEvent,
                }),
            );
            return;
        }

        if (data.ui_step) {
            this.emitStep(data.ui_step);
        }

        // Update EIAA context if server returned updated manifest
        if (data.manifest) {
            this.manifest = data.manifest as SdkManifest;
        }
    }

    private emitStep(step: unknown): void {
        this.dispatchEvent(
            Object.assign(new Event('step'), {
                detail: {
                    step,
                    manifest: this.manifest,
                    flowId: this.flowId ?? '',
                } satisfies FlowStepEvent,
            }),
        );
    }

    private assertInitialised(): void {
        if (!this.flowId || !this.flowToken) {
            throw new Error('FlowManager: call init() before other methods');
        }
    }

    private async post(path: string, body: unknown): Promise<Record<string, unknown>> {
        const headers: HeadersInit = { 'Content-Type': 'application/json' };
        if (this.flowToken) {
            headers['Authorization'] = `Bearer ${this.flowToken}`;
        }

        const response = await fetch(`${this.apiUrl}${path}`, {
            method: 'POST',
            headers,
            body: JSON.stringify(body),
            credentials: 'include',
        });

        if (!response.ok) {
            const text = await response.text().catch(() => response.statusText);
            const error: FlowErrorEvent = {
                message: `[${response.status}] ${text}`,
                recoverable: response.status < 500,
            };
            this.dispatchEvent(Object.assign(new Event('error'), { detail: error }));
            throw new Error(error.message);
        }

        return response.json();
    }

    private async fetch(path: string): Promise<Record<string, unknown>> {
        const headers: HeadersInit = {};
        if (this.flowToken) {
            headers['Authorization'] = `Bearer ${this.flowToken}`;
        }

        const response = await fetch(`${this.apiUrl}${path}`, {
            headers,
            credentials: 'include',
        });

        if (!response.ok) {
            const text = await response.text().catch(() => response.statusText);
            const error: FlowErrorEvent = {
                message: `[${response.status}] ${text}`,
                recoverable: response.status < 500,
            };
            this.dispatchEvent(Object.assign(new Event('error'), { detail: error }));
            throw new Error(error.message);
        }

        return response.json();
    }
}
