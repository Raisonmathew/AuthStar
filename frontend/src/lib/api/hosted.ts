import { api } from '../../lib/api';

export interface BrandingSafeConfig {
    logo_url?: string;
    primary_color: string;
    background_color: string;
    text_color: string;
    font_family: string;
}

export interface OrganizationHostedConfig {
    org_id: string;
    slug: string;
    display_name: string;
    branding: BrandingSafeConfig;
    login_methods: {
        email_password: boolean;
        passkey: boolean;
        sso: boolean;
    };
}

export type UiStep =
    | { type: 'email'; label: string; required: boolean }
    | { type: 'password'; label: string }
    | { type: 'otp'; label: string }
    | { type: 'error'; message: string };

export interface InitFlowRequest {
    org_id: string;
    app_id?: string;
    redirect_uri?: string;
    state?: string;
}

export interface InitFlowResponse {
    flow_id: string;
    flow_token: string;  // GAP-5 FIX: ephemeral token from init_flow
    ui_step: UiStep;
}

export type SubmitStepResponse =
    | { flow_id: string; ui_step: UiStep }
    | { status: 'decision_ready'; decision_ref: string };

/**
 * Hosted page API + EIAA flow engine client.
 *
 * - `getOrgConfig` — calls the **active** `/api/hosted/organizations/:slug`
 *   endpoint to fetch org branding/config for the login page.
 * - All auth flow methods (`initFlow`, `identifyUser`, `submitStep`,
 *   `completeFlow`) use the **new** EIAA flow engine at `/api/auth/flow`.
 *   The legacy hosted flow routes at `/api/hosted/auth/flows` are deprecated
 *   and log warnings on each call.
 *
 * GAP-5: All post-init requests include the ephemeral `flow_token` as a
 * Bearer token. The backend validates with SHA-256 + constant-time comparison.
 */
export const hostedApi = {
    getOrgConfig: (slug: string) =>
        api.get<OrganizationHostedConfig>(`/api/hosted/organizations/${slug}`),

    /** Initialize a new EIAA flow. Returns flow_id + flow_token. */
    initFlow: (data: InitFlowRequest) =>
        api.post<InitFlowResponse>('/api/auth/flow/init', data),

    /**
     * GAP-6 FIX (BUG-13): Identify the user by email/username.
     * This triggers risk re-evaluation and returns updated capabilities.
     * Previously the frontend incorrectly used submitStep for this.
     */
    identifyUser: (flowId: string, identifier: string, flowToken: string) =>
        api.post<SubmitStepResponse>(
            `/api/auth/flow/${flowId}/identify`,
            { identifier },
            { headers: { Authorization: `Bearer ${flowToken}` } }
        ),

    /** Submit a credential step (password, OTP, passkey, etc.) */
    submitStep: (flowId: string, stepType: string, value: string, flowToken: string) =>
        api.post<SubmitStepResponse>(
            `/api/auth/flow/${flowId}/submit`,
            { type: stepType, value },
            { headers: { Authorization: `Bearer ${flowToken}` } }
        ),

    /** Complete the flow — issues JWT + session cookie */
    completeFlow: (flowId: string, flowToken: string) =>
        api.post<any>(
            `/api/auth/flow/${flowId}/complete`,
            {},
            { headers: { Authorization: `Bearer ${flowToken}` } }
        ),
};
