// Library exports for api_server crate
// This enables unit testing of services and other modules

pub mod audit; // Phase 4: Audit system resilience (overflow queue)
pub mod bootstrap;
pub mod cache; // Phase 2: Distributed cache coordination
pub mod capsules;
pub mod clients;
pub mod config;
pub mod coordination;
pub mod db; // Phase 3: Database connection management
pub mod middleware;
pub mod redis;
pub mod router;
pub mod routes;
pub mod services;
pub mod state; // Phase 6: Leader election for background tasks
