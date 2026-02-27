-- Billing & Subscription Domain

-- Subscriptions table
CREATE TABLE subscriptions (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('sub'),
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    stripe_subscription_id VARCHAR(255) NOT NULL UNIQUE,
    stripe_customer_id VARCHAR(255) NOT NULL,
    stripe_price_id VARCHAR(255),
    status VARCHAR(50) NOT NULL CHECK (status IN ('active', 'past_due', 'canceled', 'incomplete', 'incomplete_expired', 'trialing', 'unpaid')),
    current_period_start TIMESTAMPTZ NOT NULL,
    current_period_end TIMESTAMPTZ NOT NULL,
    cancel_at_period_end BOOLEAN DEFAULT FALSE,
    canceled_at TIMESTAMPTZ,
    trial_start TIMESTAMPTZ,
    trial_end TIMESTAMPTZ
);

CREATE INDEX idx_subscriptions_org_id ON subscriptions(organization_id);
CREATE INDEX idx_subscriptions_stripe_id ON subscriptions(stripe_subscription_id);
CREATE INDEX idx_subscriptions_status ON subscriptions(status);
CREATE TRIGGER update_subscriptions_updated_at BEFORE UPDATE ON subscriptions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Subscription items table
CREATE TABLE subscription_items (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('subitem'),
    subscription_id VARCHAR(64) NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
    stripe_subscription_item_id VARCHAR(255) NOT NULL UNIQUE,
    stripe_price_id VARCHAR(255) NOT NULL,
    quantity INT NOT NULL DEFAULT 1,
    metadata JSONB DEFAULT '{}'
);

CREATE INDEX idx_subscription_items_sub_id ON subscription_items(subscription_id);

-- Invoices table
CREATE TABLE invoices (
    id VARCHAR(64) PRIMARY KEY DEFAULT generate_prefixed_id('inv'),
    organization_id VARCHAR(64) REFERENCES organizations(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    stripe_invoice_id VARCHAR(255) NOT NULL UNIQUE,
    amount_due BIGINT NOT NULL,
    amount_paid BIGINT NOT NULL,
    currency VARCHAR(3) DEFAULT 'usd',
    status VARCHAR(50) NOT NULL CHECK (status IN ('draft', 'open', 'paid', 'void', 'uncollectible')),
    hosted_invoice_url TEXT,
    invoice_pdf TEXT,
    due_date TIMESTAMPTZ,
    paid_at TIMESTAMPTZ
);

CREATE INDEX idx_invoices_org_id ON invoices(organization_id);
CREATE INDEX idx_invoices_stripe_id ON invoices(stripe_invoice_id);
CREATE INDEX idx_invoices_status ON invoices(status);

COMMENT ON TABLE subscriptions IS 'Stripe subscription sync';
COMMENT ON TABLE subscription_items IS 'Line items for metered/seat-based billing';
COMMENT ON TABLE invoices IS 'Invoice history synced from Stripe';
