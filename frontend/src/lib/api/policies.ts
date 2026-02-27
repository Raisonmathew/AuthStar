import { api } from '../api';

export interface Policy {
    id: string;
    created_at: string;
    tenant_id: string;
    action: string;
    version: number;
    spec: any;
}

export interface CreatePolicyRequest {
    action: string;
    spec: any;
}

export const policiesApi = {
    list: async (): Promise<Policy[]> => {
        const response = await api.get<Policy[]>('/admin/v1/policies');
        return response.data;
    },

    get: async (id: string): Promise<Policy> => {
        const response = await api.get<Policy>(`/admin/v1/policies/${id}`);
        return response.data;
    },

    create: async (request: CreatePolicyRequest): Promise<Policy> => {
        const response = await api.post<Policy>('/admin/v1/policies', request);
        return response.data;
    },
};
