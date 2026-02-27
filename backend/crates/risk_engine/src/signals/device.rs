//! Device Signal Service
//!
//! Analyzes device binding, trust state, and fingerprint stability.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

use shared_types::DeviceTrust;

/// Parse trust state from database string
fn parse_trust_state(s: String) -> DeviceTrust {
    match s.as_str() {
        "known" => DeviceTrust::Known,
        "new" => DeviceTrust::New,
        "changed" => DeviceTrust::Changed,
        "compromised" => DeviceTrust::Compromised,
        _ => DeviceTrust::Unknown,
    }
}

/// Web device input signals
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebDeviceInput {
    pub user_agent: String,
    pub platform: String,
    pub screen_resolution: Option<String>,
    pub locale: String,
    pub webauthn_available: bool,
    pub device_cookie_id: Option<String>,
}

/// Mobile device input signals
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileDeviceInput {
    pub app_installation_id: String,
    pub os_version: String,
    pub patch_level: Option<String>,
    pub secure_enclave_available: bool,
    pub keystore_available: bool,
}

/// Device record stored in database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub id: String,
    pub device_id: String,
    pub subject_id: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub platform: String,
    pub signals_hash: String,
    pub trust_state: DeviceTrust,
    pub compromise_flags: Vec<String>,
    pub successful_auths: u32,
}

/// Normalized device signals
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceSignals {
    pub trust: DeviceTrust,
    pub device_id: Option<String>,
    pub platform: Option<String>,
    pub signals_hash: Option<String>,
    pub webauthn_available: bool,
}

/// Device signal analysis service
#[derive(Clone)]
pub struct DeviceSignalService {
    db: sqlx::PgPool,
}

impl DeviceSignalService {
    pub fn new(db: sqlx::PgPool) -> Self {
        Self { db }
    }
    
    /// Analyze device signals and derive trust
    pub async fn analyze(
        &self,
        input: Option<&WebDeviceInput>,
        _user_id: Option<&str>,
    ) -> DeviceSignals {
        let Some(input) = input else {
            // No device info provided
            return DeviceSignals {
                trust: DeviceTrust::Unknown,
                ..Default::default()
            };
        };
        
        let device_id = input.device_cookie_id.clone();
        let signals_hash = Self::hash_signals(input);
        
        // If no device ID, this is an unknown device
        let Some(did) = &device_id else {
            return DeviceSignals {
                trust: DeviceTrust::Unknown,
                device_id: None,
                platform: Some(input.platform.clone()),
                signals_hash: Some(signals_hash),
                webauthn_available: input.webauthn_available,
            };
        };
        
        // Load existing device record
        let record = self.load_device(did).await;
        
        let trust = match record {
            None => {
                // First time seeing this device ID - it's "new"
                DeviceTrust::New
            }
            Some(rec) => {
                // Check for compromise flags
                if !rec.compromise_flags.is_empty() {
                    DeviceTrust::Compromised
                } else if rec.signals_hash != signals_hash {
                    // Material change in device fingerprint
                    DeviceTrust::Changed
                } else if rec.successful_auths >= 3 {
                    // Stable device with history
                    DeviceTrust::Known
                } else {
                    // Still building trust
                    DeviceTrust::New
                }
            }
        };
        
        DeviceSignals {
            trust,
            device_id: Some(did.clone()),
            platform: Some(input.platform.clone()),
            signals_hash: Some(signals_hash),
            webauthn_available: input.webauthn_available,
        }
    }
    
    /// Hash device signals for comparison (no PII stored)
    fn hash_signals(input: &WebDeviceInput) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.user_agent.as_bytes());
        hasher.update(input.platform.as_bytes());
        hasher.update(input.locale.as_bytes());
        if let Some(res) = &input.screen_resolution {
            hasher.update(res.as_bytes());
        }
        hasher.update(if input.webauthn_available { b"1" } else { b"0" });
        hex::encode(hasher.finalize())
    }
    
    /// Load device record from database
    async fn load_device(&self, device_id: &str) -> Option<DeviceRecord> {
        // Use runtime query - table may not exist yet
        let row = sqlx::query(
            r#"
            SELECT 
                id, device_id, subject_id, first_seen, last_seen,
                platform, signals_hash, trust_state,
                compromise_flags, successful_auths
            FROM device_records
            WHERE device_id = $1
            "#
        )
        .bind(device_id)
        .fetch_optional(&self.db)
        .await
        .ok()
        .flatten();
        
        row.map(|r| {
            use sqlx::Row;
            DeviceRecord {
                id: r.get("id"),
                device_id: r.get("device_id"),
                subject_id: r.get("subject_id"),
                first_seen: r.get("first_seen"),
                last_seen: r.get("last_seen"),
                platform: r.get("platform"),
                signals_hash: r.get("signals_hash"),
                trust_state: parse_trust_state(r.get::<String, _>("trust_state")),
                compromise_flags: r.get::<serde_json::Value, _>("compromise_flags")
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                    .unwrap_or_default(),
                successful_auths: r.get::<i32, _>("successful_auths") as u32,
            }
        })
    }
    
    /// Create or update device record after successful auth
    pub async fn record_successful_auth(
        &self,
        device_id: &str,
        user_id: &str,
        input: &WebDeviceInput,
    ) -> Result<(), sqlx::Error> {
        let signals_hash = Self::hash_signals(input);
        let now = Utc::now();
        
        sqlx::query(
            r#"
            INSERT INTO device_records (
                id, device_id, subject_id, first_seen, last_seen,
                platform, signals_hash, trust_state, compromise_flags, successful_auths
            )
            VALUES ($1, $2, $3, $4, $4, $5, $6, 'new', '[]', 1)
            ON CONFLICT (device_id) DO UPDATE SET
                last_seen = $4,
                signals_hash = $6,
                successful_auths = device_records.successful_auths + 1,
                trust_state = CASE 
                    WHEN device_records.successful_auths >= 2 THEN 'known'
                    ELSE device_records.trust_state
                END
            "#
        )
        .bind(shared_types::generate_id("dev"))
        .bind(device_id)
        .bind(user_id)
        .bind(now)
        .bind(&input.platform)
        .bind(&signals_hash)
        .execute(&self.db)
        .await?;
        
        Ok(())
    }
    
    /// Generate a new device ID
    pub fn generate_device_id() -> String {
        shared_types::generate_id("dev")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hash_signals() {
        let input = WebDeviceInput {
            user_agent: "Mozilla/5.0".to_string(),
            platform: "web".to_string(),
            screen_resolution: Some("1920x1080".to_string()),
            locale: "en-US".to_string(),
            webauthn_available: true,
            device_cookie_id: None,
        };
        
        let hash1 = DeviceSignalService::hash_signals(&input);
        let hash2 = DeviceSignalService::hash_signals(&input);
        
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // SHA256 hex
    }
    
    #[test]
    fn test_hash_signals_differs() {
        let input1 = WebDeviceInput {
            user_agent: "Mozilla/5.0".to_string(),
            platform: "web".to_string(),
            screen_resolution: None,
            locale: "en-US".to_string(),
            webauthn_available: true,
            device_cookie_id: None,
        };
        
        let input2 = WebDeviceInput {
            user_agent: "Chrome/100".to_string(),
            ..input1.clone()
        };
        
        let hash1 = DeviceSignalService::hash_signals(&input1);
        let hash2 = DeviceSignalService::hash_signals(&input2);
        
        assert_ne!(hash1, hash2);
    }
}
