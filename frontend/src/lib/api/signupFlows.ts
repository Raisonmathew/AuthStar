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

export const signupFlowsApi = {
    initFlow: (data: InitFlowRequest) =>
        api.post<InitFlowResponse>('/signup/flows', data),

    submitStep: (flowId: string, data: SubmitRequest) =>
        api.post<SubmitResponse>(`/signup/flows/${flowId}/submit`, data),

    commitDecision: (decisionRef: string) =>
        api.post<CommitResult>(`/signup/decisions/${decisionRef}/commit`),
};
