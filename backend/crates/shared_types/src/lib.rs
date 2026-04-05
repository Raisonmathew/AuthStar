pub mod auth;
pub mod error;
pub mod id_generator;
pub mod pagination;
pub mod response;
pub mod validation;

pub use error::{AppError, Result};
pub use id_generator::generate_id;
pub use pagination::{PaginatedResponse, PaginationParams};
pub use response::{ApiResponse, ErrorResponse, SuccessResponse};

// EIAA Auth types
pub use auth::{
    AccountStability, AsnType, AssuranceLevel, Capability, DeviceTrust, GeoVelocity, IpReputation,
    RiskConstraints, RiskContext, RiskLevel, SessionRestriction,
};
