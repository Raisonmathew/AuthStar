//! Background Jobs for Risk Engine
//!
//! Periodic jobs for baseline computation and cleanup.

mod baseline_job;

pub use baseline_job::BaselineComputationJob;
