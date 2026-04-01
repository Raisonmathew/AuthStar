//! Phase 4: Audit system resilience — disk-based overflow queue
//!
//! When the in-memory audit channel is full, records are written to a
//! sled embedded database on disk instead of being dropped. A background
//! worker drains the overflow queue back into PostgreSQL.

pub mod overflow_queue;
