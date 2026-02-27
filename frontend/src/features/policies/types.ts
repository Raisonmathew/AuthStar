export interface Policy {
    id: string;
    created_at: string;
    tenant_id: string;
    action: string;
    version: number;
    spec: Record<string, any>; // JSON AST
}

export interface CreatePolicyRequest {
    action: string;
    spec: Record<string, any>;
}
