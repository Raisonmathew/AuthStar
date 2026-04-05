//! EIAA Authentication and Assurance Types
//!
//! This module contains the core types for EIAA-compliant authentication:
//! - AssuranceLevel (AAL0-AAL3)
//! - Capability (authentication methods with AAL mapping)
//! - Risk context types (DeviceTrust, IpReputation, etc.)
//! - Risk constraints for capsule integration

mod assurance;
mod capability;
mod risk;

pub use assurance::AssuranceLevel;
pub use capability::Capability;
pub use risk::{
    AccountStability, AsnType, DeviceTrust, GeoVelocity, IpReputation, RiskConstraints,
    RiskContext, RiskLevel, SessionRestriction,
};
