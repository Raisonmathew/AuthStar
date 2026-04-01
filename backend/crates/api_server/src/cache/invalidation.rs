//! Cache Invalidation Message Protocol
//!
//! Defines the message format for distributed cache invalidation across API replicas.
//! Messages are published to Redis pub/sub and consumed by all replicas to maintain
//! cache consistency.

use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use uuid::Uuid;

/// Scope of cache invalidation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InvalidationScope {
    /// Invalidate a specific capsule for a tenant
    Capsule {
        tenant_id: String,
        action: String,
    },
    
    /// Invalidate all capsules for a tenant
    TenantCapsules {
        tenant_id: String,
    },
    
    /// Invalidate runtime public key cache entry
    RuntimeKey {
        key_id: String,
    },
    
    /// Invalidate all runtime keys
    AllRuntimeKeys,
    
    /// Global cache flush (emergency only)
    Global,
}

/// Cache invalidation message
///
/// Published to Redis pub/sub channel `cache:invalidate` when cache entries
/// need to be invalidated across all API replicas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidationMessage {
    /// Unique message ID for deduplication
    pub message_id: Uuid,
    
    /// Timestamp when invalidation was triggered (Unix milliseconds)
    pub timestamp_ms: u64,
    
    /// Replica that triggered the invalidation
    pub source_replica_id: String,
    
    /// What to invalidate
    pub scope: InvalidationScope,
    
    /// Optional reason for audit trail
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl InvalidationMessage {
    /// Create a new invalidation message
    pub fn new(scope: InvalidationScope, replica_id: String) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        
        Self {
            message_id: Uuid::new_v4(),
            timestamp_ms,
            source_replica_id: replica_id,
            scope,
            reason: None,
        }
    }
    
    /// Add a reason for the invalidation
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }
    
    /// Serialize to JSON for Redis pub/sub
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }
    
    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invalidation_message_serialization() {
        let msg = InvalidationMessage::new(
            InvalidationScope::Capsule {
                tenant_id: "org_123".to_string(),
                action: "user:read".to_string(),
            },
            "replica-1".to_string(),
        )
        .with_reason("Policy updated");

        // Serialize to JSON
        let json = msg.to_json().expect("Failed to serialize");
        
        // Deserialize back
        let deserialized = InvalidationMessage::from_json(&json)
            .expect("Failed to deserialize");
        
        assert_eq!(deserialized.message_id, msg.message_id);
        assert_eq!(deserialized.source_replica_id, "replica-1");
        assert_eq!(deserialized.reason, Some("Policy updated".to_string()));
        
        match deserialized.scope {
            InvalidationScope::Capsule { tenant_id, action } => {
                assert_eq!(tenant_id, "org_123");
                assert_eq!(action, "user:read");
            }
            _ => panic!("Wrong scope type"),
        }
    }

    #[test]
    fn test_all_scope_types() {
        let scopes = vec![
            InvalidationScope::Capsule {
                tenant_id: "org_123".to_string(),
                action: "user:read".to_string(),
            },
            InvalidationScope::TenantCapsules {
                tenant_id: "org_123".to_string(),
            },
            InvalidationScope::RuntimeKey {
                key_id: "key_abc".to_string(),
            },
            InvalidationScope::AllRuntimeKeys,
            InvalidationScope::Global,
        ];

        for scope in scopes {
            let msg = InvalidationMessage::new(scope.clone(), "test".to_string());
            let json = msg.to_json().expect("Failed to serialize");
            let deserialized = InvalidationMessage::from_json(&json)
                .expect("Failed to deserialize");
            assert_eq!(deserialized.scope, scope);
        }
    }

    #[test]
    fn test_message_without_reason() {
        let msg = InvalidationMessage::new(
            InvalidationScope::Global,
            "replica-1".to_string(),
        );

        let json = msg.to_json().expect("Failed to serialize");
        assert!(!json.contains("\"reason\""), "Reason should be omitted when None");
        
        let deserialized = InvalidationMessage::from_json(&json)
            .expect("Failed to deserialize");
        assert_eq!(deserialized.reason, None);
    }
}

// Made with Bob
