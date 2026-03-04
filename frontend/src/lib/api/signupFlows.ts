import { api } from '../api';

export interface InitFlowRequest {
    signup_ticket_id: string;
}

export interface InitFlowResponse {
    flow_id: string;
    ui_step: UiStep;
}

export type UiStep =
    | { type: 'verification_code'; label: string; attempts_remaining: number }
    | { type: 'error'; message: string };

export interface SubmitRequest {
    type: string;
    value: string;
}

export type SubmitResponse =
    | { status: 'decision_ready'; decision_ref: string }
    | { flow_id: string; ui_step: UiStep };

export interface CommitResult {
    status: string;
    user_id: string;
    identity_id: string;
}

// NEW-4 FIX: All paths now include /api prefix to match backend mount point
// (router.rs: `.nest("/api/signup", signup_routes::router())`).
// Without this, requests work in dev (Vite proxy) but 404 in production.
export const signupFlowsApi = {
    initFlow: (data: InitFlowRequest) =>
        api.post<InitFlowResponse>('/api/signup/flows', data),

    submitStep: (flowId: string, data: SubmitRequest) =>
        api.post<SubmitResponse>(`/api/signup/flows/${flowId}/submit`, data),

    // FIX-FUNC-4 (frontend): Backend now requires flow_id in the request body to
    // prove the caller completed the signup flow before committing the decision.
    // Previously this sent no body, causing a 422 Unprocessable Entity response.
    commitDecision: (decisionRef: string, flowId: string) =>
        api.post<CommitResult>(`/api/signup/decisions/${decisionRef}/commit`, { flow_id: flowId }),
};
