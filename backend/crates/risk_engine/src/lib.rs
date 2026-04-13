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

pub mod decay;
pub mod engine;
pub mod hibp;
pub mod jobs;
pub mod rules;
pub mod scoring;
pub mod signals;

pub use decay::{DecayModel, RemediationAction, RiskDecayService, StabilizingEvent};
pub use engine::{RequestContext, RiskEngine, RiskEvaluation, SubjectContext};
pub use jobs::BaselineComputationJob;
pub use scoring::RiskScorer;
pub use hibp::HibpClient;
pub use signals::{
    GeoLocation, GeoVelocityResult, IpLocateClient, NetworkInput, RawSignals, SignalCollector,
    UserLocationService, WebDeviceInput,
};

// Re-export from shared_types for convenience
pub use shared_types::{
    AccountStability, AsnType, AssuranceLevel, Capability, DeviceTrust, GeoVelocity, IpReputation,
    RiskConstraints, RiskContext, RiskLevel, SessionRestriction,
};
