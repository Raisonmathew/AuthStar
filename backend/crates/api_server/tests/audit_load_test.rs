//! Audit Writer Load Test
//!
//! Tests the throughput of the async audit writer under load.
//! Run with: cargo test --test audit_load_test -- --ignored --nocapture

use api_server::services::{AuditWriterBuilder, AuditRecord, AuditDecision};
use chrono::Utc;
use std::time::Instant;

/// Test audit writer throughput
/// Measures how many records can be written per second
#[tokio::test]
#[ignore = "requires database"]
async fn test_audit_writer_throughput() {
    let database_url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            println!("Skipping load test - no DATABASE_URL");
            return;
        }
    };

    let db = sqlx::PgPool::connect(&database_url)
        .await
        .expect("Failed to connect to database");

    // Create writer with production-like settings
    let writer = AuditWriterBuilder::new(db.clone())
        .batch_size(100)
        .flush_interval_ms(100)
        .channel_size(50_000)
        .build();

    // Generate test records
    let record_count = 10_000;
    let start = Instant::now();

    for i in 0..record_count {
        let record = create_test_record(i);
        writer.record(record);
    }

    let write_time = start.elapsed();
    
    // Wait for flush
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let total_time = start.elapsed();
    let records_per_sec = record_count as f64 / write_time.as_secs_f64();

    println!("=== Audit Writer Load Test Results ===");
    println!("Records: {record_count}");
    println!("Write time: {write_time:?}");
    println!("Total time (with flush): {total_time:?}");
    println!("Throughput: {records_per_sec:.0} records/sec");

    // Assert minimum throughput (should handle at least 5k/sec)
    assert!(records_per_sec > 5000.0, "Throughput too low: {records_per_sec:.0}/sec");

    // Cleanup test data
    sqlx::query("DELETE FROM eiaa_executions WHERE decision_ref LIKE 'dec_loadtest_%'")
        .execute(&db)
        .await
        .ok();
}

fn create_test_record(i: usize) -> AuditRecord {
    AuditRecord {
        decision_ref: format!("dec_loadtest_{i}"),
        capsule_hash_b64: "testhash123".to_string(),
        capsule_version: "1.0".to_string(),
        action: "loadtest:action".to_string(),
        tenant_id: "org_loadtest".to_string(),
        input_digest: "testdigest".to_string(),
        nonce_b64: "testnonce".to_string(),
        decision: AuditDecision {
            allow: true,
            reason: None,
        },
        attestation_signature_b64: "testsig".to_string(),
        attestation_timestamp: Utc::now(),
        attestation_hash_b64: None,
        user_id: Some("usr_loadtest".to_string()),
        input_context: None,
    }
}
