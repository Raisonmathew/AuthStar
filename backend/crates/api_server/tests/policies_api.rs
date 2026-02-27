//! Policy API Integration Tests
//!
//! Tests for the tenant policy management API endpoints.
//! Note: These tests require a running database and proper .env.test configuration.

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;

/// Test listing policies returns empty array for new tenant
#[tokio::test]
#[ignore = "requires database"]
async fn test_list_policies_empty() {
    let (app, jwt) = common::setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/policies")
                .header(header::AUTHORIZATION, format!("Bearer {}", jwt))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

/// Test creating a new policy version
#[tokio::test]
#[ignore = "requires database"]
async fn test_create_policy() {
    let (app, jwt) = common::setup_test_app().await;

    let policy_spec = json!({
        "steps": [
            {"type": "verify_identity"},
            {"type": "allow"}
        ]
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/policies")
                .header(header::AUTHORIZATION, format!("Bearer {}", jwt))
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_string(&json!({
                    "action": "test:read",
                    "spec": policy_spec,
                    "description": "Test policy"
                })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::CREATED);
}

/// Test unauthorized access returns 401
#[tokio::test]
#[ignore = "requires database"]
async fn test_unauthorized_access() {
    let (app, _) = common::setup_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/policies")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
