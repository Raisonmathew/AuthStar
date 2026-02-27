use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use chrono::{DateTime, Utc};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Plan {
    pub id: String,
    pub name: String,
    pub price_cents: i64,
    pub billing_interval: String, // "month", "year"
    pub stripe_price_id: String,
    pub features: Value, // JSON entitlements
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Customer {
    pub id: String,
    pub tenant_id: String,
    pub email: Option<String>,
    pub stripe_customer_id: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Subscription {
    pub id: String,
    pub tenant_id: String,
    pub plan_id: String,
    pub status: String, // trialing, active, past_due, canceled
    pub current_period_end: Option<DateTime<Utc>>,
    pub stripe_subscription_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}


#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct SubscriptionItem {
    pub id: String,
    pub subscription_id: String,
    pub price_id: String,
    pub quantity: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct Invoice {
    pub id: String,
    pub subscription_id: String,
    pub amount_due: i64,
    pub amount_paid: i64,
    pub status: String, // paid, open, void, uncollectible
    pub stripe_invoice_id: Option<String>,
    pub created_at: DateTime<Utc>,
}

// --- Stripe Webhook Payloads ---

#[derive(Debug, Deserialize)]
pub struct StripeEvent {
    pub id: String,
    pub r#type: String,
    pub data: StripeEventData,
}

#[derive(Debug, Deserialize)]
pub struct StripeEventData {
    pub object: Value, // We'll manually interpret this based on `type`
}

#[derive(Debug, Deserialize)]
pub struct StripeSession {
    pub customer: Option<String>,
    pub subscription: Option<String>,
    pub metadata: Option<StripeMetadata>,
}

#[derive(Debug, Deserialize)]
pub struct StripeMetadata {
    pub organization_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct StripeSubscription {
    pub id: String,
    pub customer: String,
    pub status: String,
    pub current_period_end: i64,
}

#[derive(Debug, Deserialize)]
pub struct StripeInvoice {
    pub id: String,
    pub subscription: Option<String>,
    pub status: Option<String>,
    pub payment_intent: Option<String>,
}
