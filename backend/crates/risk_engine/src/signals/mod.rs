//! Signal Collection Services
//!
//! Collects and normalizes raw signals from various sources.

pub mod attestation;
mod behavior;
mod device;
mod history;
pub mod iplocate;
pub mod location;
mod network;

pub use attestation::{
    AppIntegrity, AttestationPlatform, AttestationResult, DeviceAttestationService, DeviceIntegrity,
};
pub use behavior::{BehaviorSignalService, BehaviorSignals};
pub use device::{DeviceRecord, DeviceSignalService, DeviceSignals, WebDeviceInput};
pub use history::{HistorySignalService, HistorySignals};
pub use iplocate::{IpLocateClient, IpLocateResponse};
pub use location::{GeoLocation, GeoVelocityResult, UserGeoBaseline, UserLocationService};
pub use network::{NetworkInput, NetworkSignalService, NetworkSignals};

/// Raw signals collected from all services
#[derive(Debug, Clone, Default)]
pub struct RawSignals {
    pub network: NetworkSignals,
    pub device: DeviceSignals,
    pub behavior: BehaviorSignals,
    pub history: HistorySignals,
}

/// Collector that aggregates all signal services
#[derive(Clone)]
pub struct SignalCollector {
    pub network: NetworkSignalService,
    pub device: DeviceSignalService,
    pub behavior: BehaviorSignalService,
    pub history: HistorySignalService,
    pub location: UserLocationService,
}

impl SignalCollector {
    pub fn new(db: sqlx::PgPool) -> Self {
        Self::with_iplocate(db, IpLocateClient::disabled())
    }

    /// Create with IPLocate client for real IP intelligence
    pub fn with_iplocate(db: sqlx::PgPool, iplocate: IpLocateClient) -> Self {
        Self {
            network: NetworkSignalService::new(iplocate),
            device: DeviceSignalService::new(db.clone()),
            behavior: BehaviorSignalService::with_db(db.clone()),
            history: HistorySignalService::new(db.clone()),
            location: UserLocationService::new(db),
        }
    }

    /// Collect all signals in parallel
    pub async fn collect(
        &self,
        network_input: &NetworkInput,
        device_input: Option<&WebDeviceInput>,
        user_id: Option<&str>,
    ) -> RawSignals {
        let ((mut network, ip_data), device, behavior, history) = tokio::join!(
            self.network.analyze(network_input, user_id),
            self.device.analyze(device_input, user_id),
            self.behavior.analyze(user_id),
            self.history.analyze(user_id),
        );

        // Enrich network signals with geo velocity if we have user_id and location data
        if let (Some(uid), Some(data)) = (user_id, ip_data) {
            let current = location::GeoLocation {
                ip_address: data.ip.clone(),
                country_code: data.country_code,
                city: data.city,
                latitude: data.latitude,
                longitude: data.longitude,
            };

            if let Ok(velocity) = self.location.analyze_velocity(uid, &current).await {
                network.country_changed = velocity.country_changed;

                // Map velocity km/h to risk level
                if velocity.is_impossible_travel {
                    network.geo_velocity = shared_types::GeoVelocity::Impossible;
                } else if let Some(v) = velocity.velocity_km_h {
                    if v > 500.0 {
                        network.geo_velocity = shared_types::GeoVelocity::Impossible;
                    } else if v > 100.0 {
                        network.geo_velocity = shared_types::GeoVelocity::Unlikely;
                    } else {
                        network.geo_velocity = shared_types::GeoVelocity::Normal;
                    }
                }
            }
        }

        RawSignals {
            network,
            device,
            behavior,
            history,
        }
    }
}
