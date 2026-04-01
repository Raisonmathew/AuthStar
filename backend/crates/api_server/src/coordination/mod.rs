//! Phase 6: Background task coordination via Redis leader election
//!
//! Ensures only one replica runs each background task (e.g., baseline
//! computation) to avoid duplicate work and race conditions.

pub mod leader_election;
