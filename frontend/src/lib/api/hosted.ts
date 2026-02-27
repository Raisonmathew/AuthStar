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
    ui_step: UiStep;
}

export type SubmitStepResponse =
    | { flow_id: string; ui_step: UiStep }
    | { status: 'decision_ready'; decision_ref: string };

export const hostedApi = {
    getOrgConfig: (slug: string) =>
        api.get<OrganizationHostedConfig>(`/api/hosted/organizations/${slug}`),

    initFlow: (data: InitFlowRequest) =>
        api.post<InitFlowResponse>('/api/hosted/auth/flows', data),

    submitStep: (flowId: string, stepType: string, value: string) =>
        api.post<SubmitStepResponse>(`/api/hosted/auth/flows/${flowId}/submit`, { type: stepType, value }),
};
