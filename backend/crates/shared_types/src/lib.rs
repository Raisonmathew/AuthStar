pub mod error;
pub mod response;
pub mod id_generator;
pub mod pagination;
pub mod validation;
pub mod auth;

pub use error::{AppError, Result};
pub use response::{ApiResponse, SuccessResponse, ErrorResponse};
pub use id_generator::generate_id;
pub use pagination::{PaginationParams, PaginatedResponse};

// EIAA Auth types
pub use auth::{
    AssuranceLevel, Capability,
    RiskContext, RiskConstraints, RiskLevel,
    DeviceTrust, IpReputation, GeoVelocity, AccountStability,
    AsnType, SessionRestriction,
};

