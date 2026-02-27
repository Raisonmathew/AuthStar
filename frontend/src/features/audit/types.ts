export interface ExecutionLog {
    id: string;
    created_at: string;
    capsule_id: string | null;
    capsule_hash_b64: string;
    decision: Record<string, any>;
    nonce_b64: string;
    client_id: string | null;
    ip_text: string | null;
}
