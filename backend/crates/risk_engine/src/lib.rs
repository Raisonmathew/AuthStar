//! EIAA Risk Engine
//!
//! A deterministic signal-processing system that converts raw environmental
//! evidence into normalized risk facts that constrain assurance and capabilities.
//!
//! The Risk Engine:
//! - Collects raw signals (network, device, behavior, history)
//! - Normalizes signals into typed facts
//! - Scores and classifies risk
//! - Applies decay to persistent risk state
//! - Derives assurance constraints
//!
//! The Risk Engine does NOT:
//! - Authenticate users
//! - Authorize actions
//! - Execute policy
//! - Issue tokens
//! - Render UI

pub mod signals;
pub mod scoring;
pub mod decay;
pub mod rules;
pub mod engine;
pub mod jobs;

pub use engine::{RiskEngine, RiskEvaluation, RequestContext, SubjectContext};
pub use scoring::RiskScorer;
pub use decay::{RiskDecayService, DecayModel, StabilizingEvent, RemediationAction};
pub use signals::{
    SignalCollector, RawSignals, NetworkInput, WebDeviceInput, 
    IpLocateClient, UserLocationService, GeoLocation, GeoVelocityResult,
};
pub use jobs::BaselineComputationJob;

// Re-export from shared_types for convenience
pub use shared_types::{
    AssuranceLevel, Capability,
    RiskContext, RiskConstraints, RiskLevel,
    DeviceTrust, IpReputation, GeoVelocity, AccountStability,
    AsnType, SessionRestriction,
};
