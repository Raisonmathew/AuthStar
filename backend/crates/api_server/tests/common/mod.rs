//! Shared test infrastructure for API server integration tests.
//!
//! Re-exports from sub-modules so tests can write:
//! ```rust
//! mod common;
//! use common::harness::{TestHarness, create_test_state, test_client};
//! use common::seed::{seed_org, seed_user, seed_identity};
//! ```

pub mod harness;
pub mod seed;
