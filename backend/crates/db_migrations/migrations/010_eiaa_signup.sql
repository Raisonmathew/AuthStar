-- EIAA-Compliant Signup: Extend signup_tickets
ALTER TABLE signup_tickets ADD COLUMN IF NOT EXISTS flow_id TEXT;
ALTER TABLE signup_tickets ADD COLUMN IF NOT EXISTS decision_ref TEXT;
ALTER TABLE signup_tickets ADD COLUMN IF NOT EXISTS capsule_version TEXT NOT NULL DEFAULT 'signup_capsule_v1';
ALTER TABLE signup_tickets ADD COLUMN IF NOT EXISTS last_attempt_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_signup_tickets_flow_id ON signup_tickets(flow_id) WHERE flow_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_signup_tickets_decision_ref ON signup_tickets(decision_ref) WHERE decision_ref IS NOT NULL;

COMMENT ON COLUMN signup_tickets.flow_id IS 'EIAA flow ID bound to this signup ticket';
COMMENT ON COLUMN signup_tickets.decision_ref IS 'Attestation decision reference after completion';
COMMENT ON COLUMN signup_tickets.capsule_version IS 'Signup capsule version used for this ticket';
