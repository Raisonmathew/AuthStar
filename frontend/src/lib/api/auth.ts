import { api } from './client';

export interface SignUpRequest {
    email: string;
    password: string;
    firstName?: string;
    lastName?: string;
}

export interface SignUpResponse {
    ticketId: string;
    status: string;
    requiresVerification: boolean;
}

export interface VerifyEmailRequest {
    ticketId: string;
    code: string;
}

export interface SignInRequest {
    identifier: string;
    password: string;
}

export interface SignInResponse {
    user: any;
    sessionId: string;
    jwt: string;
    mfaRequired?: boolean;
    challengeToken?: string;
}

export const authApi = {
    signUp: (data: SignUpRequest) =>
        api.post<SignUpResponse>('/api/v1/sign-up', data),

    verifyEmail: (data: VerifyEmailRequest) =>
        api.post('/api/v1/verify', data),

    signIn: (data: SignInRequest) =>
        api.post<SignInResponse>('/api/v1/sign-in', data),

    signOut: () =>
        api.post('/api/v1/sign-out'),

    refreshToken: () =>
        api.post('/api/v1/token/refresh'),

    getCurrentUser: () =>
        api.get('/api/v1/user'),
};
