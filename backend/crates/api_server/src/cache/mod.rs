// Cache coordination module for distributed cache invalidation
pub mod invalidation;
pub mod invalidation_bus;
pub mod metrics;

// Re-export commonly used types
pub use invalidation::{InvalidationMessage, InvalidationScope};
pub use invalidation_bus::InvalidationBus;

// Made with Bob
