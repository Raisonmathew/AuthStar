use crate::models::{StripeEvent, StripeInvoice, StripeSession, StripeSubscription};
use crate::services::StripeService;
use shared_types::{AppError, Result};
use sqlx::PgPool;

#[derive(Clone)]
pub struct WebhookService {
    db: PgPool,
    stripe: StripeService,
}

impl WebhookService {
    pub fn new(db: PgPool, stripe: StripeService) -> Self {
        Self { db, stripe }
    }

    /// Handle a verified webhook payload.
    ///
    /// CRITICAL-8 FIX: Implements idempotency via the `stripe_webhook_events` table.
    /// Before processing any event, we attempt to INSERT the event ID. If the INSERT
    /// succeeds (rows_affected == 1), we process the event. If it fails due to a
    /// unique constraint violation (rows_affected == 0), the event was already processed
    /// and we skip it. This is safe because Stripe guarantees at-least-once delivery.
    pub async fn handle_webhook(&self, payload: String) -> Result<()> {
        let event: StripeEvent = serde_json::from_str(&payload)
            .map_err(|e| AppError::BadRequest(format!("Invalid JSON: {e}")))?;

        tracing::info!(
            event_id = %event.id,
            event_type = %event.r#type,
            "Received Stripe webhook"
        );

        // CRITICAL-8: Idempotency check — attempt to claim this event ID.
        // Uses INSERT ... ON CONFLICT DO NOTHING to atomically check-and-insert.
        let claim_result = sqlx::query(
            r#"
            INSERT INTO stripe_webhook_events (event_id, event_type, received_at)
            VALUES ($1, $2, NOW())
            ON CONFLICT (event_id) DO NOTHING
            "#,
        )
        .bind(&event.id)
        .bind(&event.r#type)
        .execute(&self.db)
        .await?;

        if claim_result.rows_affected() == 0 {
            // Event already processed — skip silently (idempotent)
            tracing::info!(
                event_id = %event.id,
                "Skipping duplicate Stripe webhook event (already processed)"
            );
            return Ok(());
        }

        // Process the event — wrap in a result so we can mark it failed if needed
        let process_result = self.dispatch_event(&event).await;

        match &process_result {
            Ok(_) => {
                // Mark event as successfully processed
                sqlx::query(
                    "UPDATE stripe_webhook_events SET processed_at = NOW(), status = 'processed' WHERE event_id = $1"
                )
                .bind(&event.id)
                .execute(&self.db)
                .await?;
            }
            Err(e) => {
                // Mark event as failed so it can be retried or investigated
                sqlx::query(
                    "UPDATE stripe_webhook_events SET status = 'failed', error = $1 WHERE event_id = $2"
                )
                .bind(e.to_string())
                .bind(&event.id)
                .execute(&self.db)
                .await?;
                tracing::error!(
                    event_id = %event.id,
                    error = %e,
                    "Stripe webhook processing failed"
                );
            }
        }

        process_result
    }

    /// Dispatch a Stripe event to the appropriate handler.
    async fn dispatch_event(&self, event: &StripeEvent) -> Result<()> {
        match event.r#type.as_str() {
            "checkout.session.completed" => {
                let session: StripeSession = serde_json::from_value(event.data.object.clone())
                    .map_err(|e| AppError::Internal(format!("Bad session schema: {e}")))?;
                self.handle_checkout_completed(session).await?;
            }
            "invoice.paid" => {
                let invoice: StripeInvoice = serde_json::from_value(event.data.object.clone())
                    .map_err(|e| AppError::Internal(format!("Bad invoice schema: {e}")))?;
                self.handle_invoice_paid(invoice).await?;
            }
            "invoice.payment_failed" => {
                let invoice: StripeInvoice = serde_json::from_value(event.data.object.clone())
                    .map_err(|e| AppError::Internal(format!("Bad invoice schema: {e}")))?;
                self.handle_invoice_payment_failed(invoice).await?;
            }
            "customer.subscription.created" => {
                let sub: StripeSubscription = serde_json::from_value(event.data.object.clone())
                    .map_err(|e| AppError::Internal(format!("Bad subscription schema: {e}")))?;
                self.handle_subscription_created(sub).await?;
            }
            "customer.subscription.updated" => {
                let sub: StripeSubscription = serde_json::from_value(event.data.object.clone())
                    .map_err(|e| AppError::Internal(format!("Bad subscription schema: {e}")))?;
                self.handle_subscription_updated(sub).await?;
            }
            "customer.subscription.deleted" => {
                let sub: StripeSubscription = serde_json::from_value(event.data.object.clone())
                    .map_err(|e| AppError::Internal(format!("Bad subscription schema: {e}")))?;
                self.handle_subscription_deleted(sub).await?;
            }
            _ => {
                tracing::info!(event_type = %event.r#type, "Unhandled Stripe event type");
            }
        }

        Ok(())
    }

    async fn handle_checkout_completed(&self, session: StripeSession) -> Result<()> {
        let org_id = session
            .metadata
            .and_then(|m| m.organization_id)
            .ok_or(AppError::Internal("No organization_id in metadata".into()))?;
        let sub_id = session
            .subscription
            .ok_or(AppError::Internal("No subscription in session".into()))?;
        let cust_id = session
            .customer
            .ok_or(AppError::Internal("No customer in session".into()))?;

        // 1. Update Organization with Stripe customer ID
        sqlx::query("UPDATE organizations SET stripe_customer_id = $1 WHERE id = $2")
            .bind(&cust_id)
            .bind(&org_id)
            .execute(&self.db)
            .await?;

        // 2. Fetch full subscription details from Stripe and create local record
        match self.stripe.get_subscription(&sub_id).await {
            Ok(sub_json) => {
                let status = sub_json["status"].as_str().unwrap_or("active");
                // In Stripe dahlia API (2026+), period fields are on items, not subscription top level
                let first_item = &sub_json["items"]["data"][0];
                let period_start = first_item["current_period_start"].as_i64()
                    .or_else(|| sub_json["current_period_start"].as_i64())
                    .unwrap_or(0);
                let period_end = first_item["current_period_end"].as_i64()
                    .or_else(|| sub_json["current_period_end"].as_i64())
                    .unwrap_or(0);
                let cancel_at_end = sub_json["cancel_at_period_end"].as_bool().unwrap_or(false);
                let price_id = first_item["price"]["id"]
                    .as_str()
                    .or_else(|| first_item["plan"]["id"].as_str())
                    .map(|s| s.to_string());

                let ps = chrono::DateTime::from_timestamp(period_start, 0)
                    .unwrap_or_else(chrono::Utc::now);
                let pe = chrono::DateTime::from_timestamp(period_end, 0)
                    .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::days(30));

                sqlx::query(
                    r#"INSERT INTO subscriptions
                       (organization_id, stripe_subscription_id, stripe_customer_id, stripe_price_id,
                        status, current_period_start, current_period_end, cancel_at_period_end)
                       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                       ON CONFLICT (stripe_subscription_id) DO UPDATE SET
                        status = EXCLUDED.status,
                        current_period_start = EXCLUDED.current_period_start,
                        current_period_end = EXCLUDED.current_period_end,
                        cancel_at_period_end = EXCLUDED.cancel_at_period_end,
                        stripe_price_id = EXCLUDED.stripe_price_id"#,
                )
                .bind(&org_id)
                .bind(&sub_id)
                .bind(&cust_id)
                .bind(&price_id)
                .bind(status)
                .bind(ps)
                .bind(pe)
                .bind(cancel_at_end)
                .execute(&self.db)
                .await?;

                tracing::info!("Subscription {} created in DB for org {}", sub_id, org_id);
            }
            Err(e) => {
                tracing::error!("Failed to fetch subscription {} from Stripe: {}. Will rely on subscription.created event.", sub_id, e);
            }
        }

        tracing::info!("Checkout completed for org: {}, sub: {}", org_id, sub_id);
        Ok(())
    }

    async fn handle_invoice_paid(&self, invoice: StripeInvoice) -> Result<()> {
        let sub_id = match invoice.subscription {
            Some(id) => id,
            None => {
                tracing::info!("Invoice {} paid but has no subscription (one-time charge), skipping", invoice.id);
                return Ok(());
            }
        };

        // Update subscription status to active if it was past_due
        sqlx::query("UPDATE subscriptions SET status = 'active' WHERE stripe_subscription_id = $1")
            .bind(&sub_id)
            .execute(&self.db)
            .await?;

        tracing::info!("Invoice paid for subscription: {}", sub_id);
        Ok(())
    }

    async fn handle_invoice_payment_failed(&self, invoice: StripeInvoice) -> Result<()> {
        let sub_id = invoice
            .subscription
            .ok_or(AppError::Internal("No sub in invoice".into()))?;

        // Mark subscription as past_due
        sqlx::query(
            "UPDATE subscriptions SET status = 'past_due' WHERE stripe_subscription_id = $1",
        )
        .bind(&sub_id)
        .execute(&self.db)
        .await?;

        tracing::warn!("Invoice payment failed for subscription: {}", sub_id);
        Ok(())
    }

    async fn handle_subscription_created(&self, sub: StripeSubscription) -> Result<()> {
        let period_start = sub.period_start()
            .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
            .unwrap_or_else(chrono::Utc::now);
        let period_end = sub.period_end()
            .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
            .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::days(30));
        let cancel_at_end = sub.cancel_at_period_end.unwrap_or(false);
        let price_id = sub.items
            .as_ref()
            .and_then(|items| items.data.first())
            .and_then(|item| item.price.as_ref())
            .map(|p| p.id.clone());

        // Look up org by customer ID
        let org_id: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM organizations WHERE stripe_customer_id = $1",
        )
        .bind(&sub.customer)
        .fetch_optional(&self.db)
        .await?;

        let org_id = org_id
            .map(|r| r.0)
            .ok_or_else(|| AppError::Internal(format!("No org for customer {}", sub.customer)))?;

        sqlx::query(
            r#"INSERT INTO subscriptions
               (organization_id, stripe_subscription_id, stripe_customer_id, stripe_price_id,
                status, current_period_start, current_period_end, cancel_at_period_end)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
               ON CONFLICT (stripe_subscription_id) DO UPDATE SET
                status = EXCLUDED.status,
                current_period_start = EXCLUDED.current_period_start,
                current_period_end = EXCLUDED.current_period_end,
                cancel_at_period_end = EXCLUDED.cancel_at_period_end,
                stripe_price_id = EXCLUDED.stripe_price_id"#,
        )
        .bind(&org_id)
        .bind(&sub.id)
        .bind(&sub.customer)
        .bind(&price_id)
        .bind(&sub.status)
        .bind(period_start)
        .bind(period_end)
        .bind(cancel_at_end)
        .execute(&self.db)
        .await?;

        tracing::info!("Subscription created: {} for org {}", sub.id, org_id);
        Ok(())
    }

    async fn handle_subscription_updated(&self, sub: StripeSubscription) -> Result<()> {
        // Sync subscription status and period end
        let period_end = sub.period_end()
            .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
            .unwrap_or_else(|| chrono::Utc::now() + chrono::Duration::days(30));
        let cancel_at_end = sub.cancel_at_period_end.unwrap_or(false);
        let price_id = sub.items
            .as_ref()
            .and_then(|items| items.data.first())
            .and_then(|item| item.price.as_ref())
            .map(|p| p.id.clone());

        sqlx::query(
            r#"UPDATE subscriptions
               SET status = $1, current_period_end = $2, cancel_at_period_end = $3, stripe_price_id = COALESCE($4, stripe_price_id)
               WHERE stripe_subscription_id = $5"#
        )
            .bind(&sub.status)
            .bind(period_end)
            .bind(cancel_at_end)
            .bind(&price_id)
            .bind(&sub.id)
            .execute(&self.db)
            .await?;

        tracing::info!("Subscription updated: {} -> status={}", sub.id, sub.status);
        Ok(())
    }

    async fn handle_subscription_deleted(&self, sub: StripeSubscription) -> Result<()> {
        // Mark local subscription as canceled
        sqlx::query(
            "UPDATE subscriptions SET status = 'canceled' WHERE stripe_subscription_id = $1",
        )
        .bind(&sub.id)
        .execute(&self.db)
        .await?;

        tracing::info!("Subscription deleted: {}", sub.id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::models::{StripeEvent, StripeInvoice, StripeSession, StripeSubscription};

    #[test]
    fn test_stripe_event_deserialization() {
        let json = r#"{
            "id": "evt_123",
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "customer": "cus_xxx",
                    "subscription": "sub_xxx",
                    "metadata": {"organization_id": "org_abc"}
                }
            }
        }"#;

        let event: StripeEvent = serde_json::from_str(json).unwrap();

        assert_eq!(event.id, "evt_123");
        assert_eq!(event.r#type, "checkout.session.completed");
    }

    #[test]
    fn test_stripe_session_deserialization() {
        let json = r#"{
            "customer": "cus_123",
            "subscription": "sub_456",
            "metadata": {"organization_id": "org_789"}
        }"#;

        let session: StripeSession = serde_json::from_str(json).unwrap();

        assert_eq!(session.customer, Some("cus_123".to_string()));
        assert_eq!(session.subscription, Some("sub_456".to_string()));
        assert_eq!(
            session.metadata.unwrap().organization_id,
            Some("org_789".to_string())
        );
    }

    #[test]
    fn test_stripe_subscription_deserialization() {
        let json = r#"{
            "id": "sub_123",
            "customer": "cus_456",
            "status": "active",
            "current_period_end": 1735689600
        }"#;

        let sub: StripeSubscription = serde_json::from_str(json).unwrap();

        assert_eq!(sub.id, "sub_123");
        assert_eq!(sub.customer, "cus_456");
        assert_eq!(sub.status, "active");
        assert_eq!(sub.current_period_end, Some(1735689600));
    }

    #[test]
    fn test_stripe_invoice_deserialization() {
        let json = r#"{
            "id": "in_123",
            "subscription": "sub_456",
            "status": "paid",
            "payment_intent": "pi_789"
        }"#;

        let invoice: StripeInvoice = serde_json::from_str(json).unwrap();

        assert_eq!(invoice.id, "in_123");
        assert_eq!(invoice.subscription, Some("sub_456".to_string()));
        assert_eq!(invoice.status, Some("paid".to_string()));
    }

    #[test]
    fn test_stripe_invoice_minimal() {
        // Invoice with minimal fields
        let json = r#"{"id": "in_123"}"#;

        let invoice: StripeInvoice = serde_json::from_str(json).unwrap();

        assert_eq!(invoice.id, "in_123");
        assert!(invoice.subscription.is_none());
        assert!(invoice.status.is_none());
    }

    #[test]
    fn test_stripe_session_without_metadata() {
        let json = r#"{
            "customer": "cus_123",
            "subscription": "sub_456"
        }"#;

        let session: StripeSession = serde_json::from_str(json).unwrap();

        assert!(session.metadata.is_none());
    }

    #[test]
    fn test_stripe_event_unknown_type() {
        let json = r#"{
            "id": "evt_999",
            "type": "unknown.event.type",
            "data": {"object": {}}
        }"#;

        let event: StripeEvent = serde_json::from_str(json).unwrap();

        assert_eq!(event.r#type, "unknown.event.type");
        // Unknown events should parse successfully (we just don't handle them)
    }

    #[test]
    fn test_subscription_status_values() {
        // Test various subscription statuses
        for status in ["active", "past_due", "canceled", "trialing", "incomplete"] {
            let json = format!(
                r#"{{
                "id": "sub_test",
                "customer": "cus_test",
                "status": "{status}",
                "current_period_end": 1735689600
            }}"#
            );

            let sub: StripeSubscription = serde_json::from_str(&json).unwrap();
            assert_eq!(sub.status, status);
        }
    }
}
