// Library exports for api_server crate
// This enables unit testing of services and other modules

pub mod config;
pub mod state;
pub mod router;
pub mod routes;
pub mod services;
pub mod clients;
pub mod capsules;
pub mod middleware;
pub mod bootstrap;
pub mod redis;
pub mod cache; // Phase 2: Distributed cache coordination
pub mod db;    // Phase 3: Database connection management
