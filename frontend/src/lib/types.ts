
/**
 * EIAA: Structured requirement from capsule
 * Matches the backend `Requirement` struct in `attestation_verifier.rs`.
 */
export interface Requirement {
    required_assurance?: string;
    acceptable_capabilities?: string[];
    disallowed_capabilities?: string[];
    require_phishing_resistant: boolean;
    session_restrictions?: string[];
}
