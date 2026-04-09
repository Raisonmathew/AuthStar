use crate::routes::guards::ensure_org_access;
use crate::state::AppState;
use auth_core::jwt::Claims;
use axum::{
    extract::{Extension, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use shared_types::AppError;

/// Routes for read-only billing operations
pub fn read_routes() -> Router<AppState> {
    Router::new()
        .route("/subscription", get(get_subscription))
        .route("/invoices", get(list_invoices))
}

/// Routes for billing write operations
pub fn write_routes() -> Router<AppState> {
    Router::new()
        .route("/checkout", post(create_checkout))
        .route("/subscription/cancel", post(cancel_subscription))
        .route("/portal", post(create_portal_session))
}

/// Webhook route (no auth, Stripe signature verified)
pub fn webhook_route() -> Router<AppState> {
    Router::new().route("/webhook", post(handle_webhook))
}

#[derive(Deserialize)]
struct CheckoutReq {
    org_id: String,
    price_id: String,
    success_url: String,
    cancel_url: String,
    customer_email: Option<String>,
}

#[derive(Serialize)]
struct CheckoutResp {
    url: String,
}

async fn create_checkout(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CheckoutReq>,
) -> Result<Json<CheckoutResp>, AppError> {
    ensure_org_access(&state, &claims, &req.org_id).await?;
    let url = state
        .stripe_service
        .create_checkout_session(
            &req.org_id,
            &req.price_id,
            &req.success_url,
            &req.cancel_url,
            req.customer_email.as_deref(),
        )
        .await
        .map_err(|e| AppError::External(e.to_string()))?;

    Ok(Json(CheckoutResp { url }))
}

async fn handle_webhook(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Result<StatusCode, AppError> {
    let sig_header = headers
        .get("Stripe-Signature")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| AppError::BadRequest("Missing signature".into()))?;

    // Verify signature
    state
        .stripe_service
        .verify_signature(&body, sig_header, &state.config.stripe.webhook_secret)
        .map_err(|e| AppError::BadRequest(format!("Invalid signature: {e}")))?;

    state
        .webhook_service
        .handle_webhook(body)
        .await
        .map_err(|e| AppError::Internal(format!("Processing failed: {e}")))?;

    Ok(StatusCode::OK)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")] // Match frontend convention
struct SubscriptionDetails {
    id: String,
    status: String,
    current_period_end: chrono::DateTime<chrono::Utc>,
    cancel_at_period_end: bool,
    plan: PlanDetails,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PlanDetails {
    name: String,
    amount: i64,
    currency: String,
    interval: String,
}

use axum::extract::Query;

#[derive(Deserialize)]
struct GetSubParams {
    org_id: String,
}

async fn get_subscription(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(params): Query<GetSubParams>,
) -> Result<Json<Option<SubscriptionDetails>>, AppError> {
    ensure_org_access(&state, &claims, &params.org_id).await?;
    #[derive(sqlx::FromRow)]
    struct SubRow {
        stripe_subscription_id: String,
        status: String,
        current_period_end: chrono::DateTime<chrono::Utc>,
        cancel_at_period_end: Option<bool>,
        stripe_price_id: Option<String>,
    }

    let sub = sqlx::query_as::<_, SubRow>(
        r#"
        SELECT stripe_subscription_id, status, current_period_end, cancel_at_period_end, stripe_price_id
        FROM subscriptions
        WHERE organization_id = $1 AND status = 'active'
        ORDER BY created_at DESC
        LIMIT 1
        "#,
    )
    .bind(&params.org_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| AppError::Database(e.to_string()))?;

    if let Some(s) = sub {
        // Fetch real plan details from Stripe using the price ID
        let plan = if let Some(price_id) = s.stripe_price_id.as_ref() {
            match state.stripe_service.get_price(price_id).await {
                Ok(price_info) => PlanDetails {
                    name: price_info["nickname"]
                        .as_str()
                        .unwrap_or("Subscription Plan")
                        .to_string(),
                    amount: price_info["unit_amount"].as_i64().unwrap_or(0),
                    currency: price_info["currency"].as_str().unwrap_or("usd").to_string(),
                    interval: price_info["recurring"]["interval"]
                        .as_str()
                        .unwrap_or("month")
                        .to_string(),
                },
                Err(e) => {
                    tracing::warn!("Failed to fetch price {} from Stripe: {}", price_id, e);
                    PlanDetails {
                        name: "Plan details unavailable".to_string(),
                        amount: 0,
                        currency: "usd".to_string(),
                        interval: "month".to_string(),
                    }
                }
            }
        } else {
            PlanDetails {
                name: "Plan details unavailable".to_string(),
                amount: 0,
                currency: "usd".to_string(),
                interval: "month".to_string(),
            }
        };

        Ok(Json(Some(SubscriptionDetails {
            id: s.stripe_subscription_id,
            status: s.status,
            current_period_end: s.current_period_end,
            cancel_at_period_end: s.cancel_at_period_end.unwrap_or(false),
            plan,
        })))
    } else {
        // Return null instead of 404 for missing subscription
        Ok(Json(None))
    }
}

// Cancel subscription request
#[derive(Deserialize)]
struct CancelSubReq {
    _org_id: String,
    subscription_id: String,
    immediately: Option<bool>,
}

async fn cancel_subscription(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<CancelSubReq>,
) -> Result<Json<serde_json::Value>, AppError> {
    ensure_org_access(&state, &claims, &req._org_id).await?;
    let result = state
        .stripe_service
        .cancel_subscription(&req.subscription_id, req.immediately.unwrap_or(false))
        .await
        .map_err(|e| AppError::External(e.to_string()))?;

    Ok(Json(result))
}

// Create portal session
#[derive(Deserialize)]
struct PortalReq {
    org_id: String,
    return_url: String,
}

#[derive(Serialize)]
struct PortalResp {
    url: String,
}

async fn create_portal_session(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Json(req): Json<PortalReq>,
) -> Result<Json<PortalResp>, AppError> {
    ensure_org_access(&state, &claims, &req.org_id).await?;
    let url = state
        .stripe_service
        .create_portal_session(&req.org_id, &req.return_url)
        .await
        .map_err(|e| AppError::External(e.to_string()))?;

    Ok(Json(PortalResp { url }))
}

// List invoices
#[derive(Deserialize)]
struct InvoicesParams {
    org_id: String,
    limit: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InvoiceItem {
    id: String,
    amount_due: i64,
    amount_paid: i64,
    currency: String,
    status: String,
    created: i64,
    invoice_pdf: Option<String>,
    hosted_invoice_url: Option<String>,
}

async fn list_invoices(
    State(state): State<AppState>,
    Extension(claims): Extension<Claims>,
    Query(params): Query<InvoicesParams>,
) -> Result<Json<Vec<InvoiceItem>>, AppError> {
    ensure_org_access(&state, &claims, &params.org_id).await?;
    // Try to get invoices, return empty array if Stripe fails
    let invoices = match state
        .stripe_service
        .list_invoices(&params.org_id, params.limit.unwrap_or(10))
        .await
    {
        Ok(inv) => inv,
        Err(e) => {
            tracing::warn!("Failed to fetch invoices from Stripe: {}", e);
            // Return empty array instead of 500 error
            return Ok(Json(Vec::new()));
        }
    };

    let items: Vec<InvoiceItem> = invoices
        .iter()
        .map(|inv| InvoiceItem {
            id: inv["id"].as_str().unwrap_or_default().to_string(),
            amount_due: inv["amount_due"].as_i64().unwrap_or(0),
            amount_paid: inv["amount_paid"].as_i64().unwrap_or(0),
            currency: inv["currency"].as_str().unwrap_or("usd").to_string(),
            status: inv["status"].as_str().unwrap_or("draft").to_string(),
            created: inv["created"].as_i64().unwrap_or(0),
            invoice_pdf: inv["invoice_pdf"].as_str().map(|s| s.to_string()),
            hosted_invoice_url: inv["hosted_invoice_url"].as_str().map(|s| s.to_string()),
        })
        .collect();

    Ok(Json(items))
}

// Guard consolidated in routes::guards module
