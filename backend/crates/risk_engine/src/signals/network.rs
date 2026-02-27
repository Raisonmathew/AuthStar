//! Network Signal Service
//!
//! Analyzes IP addresses for reputation, ASN type, and geo velocity.

use std::net::IpAddr;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use shared_types::{IpReputation, GeoVelocity, AsnType};
use super::iplocate::{IpLocateClient, IpLocateResponse};

/// Raw network input from request
#[derive(Debug, Clone)]
pub struct NetworkInput {
    pub remote_ip: IpAddr,
    pub x_forwarded_for: Option<String>,
    pub user_agent: String,
    pub accept_language: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Normalized network signals
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkSignals {
    pub ip_reputation: IpReputation,
    pub asn_type: AsnType,
    pub geo_velocity: GeoVelocity,
    pub country: Option<String>,
    pub country_changed: bool,
    pub is_phishing_source: bool,
}

impl NetworkSignals {
    /// Signals for private/local IPs
    pub fn private() -> Self {
        Self {
            ip_reputation: IpReputation::Low,
            asn_type: AsnType::Residential,
            geo_velocity: GeoVelocity::Normal,
            country: None,
            country_changed: false,
            is_phishing_source: false,
        }
    }
}

/// Network signal analysis service
#[derive(Clone)]
pub struct NetworkSignalService {
    iplocate: IpLocateClient,
}

impl NetworkSignalService {
    pub fn new(iplocate: IpLocateClient) -> Self {
        Self { iplocate }
    }
    
    /// Analyze network signals from request
    pub async fn analyze(&self, input: &NetworkInput, user_id: Option<&str>) -> (NetworkSignals, Option<IpLocateResponse>) {
        // Step 1: Check for private/reserved IPs
        if Self::is_private_or_reserved(&input.remote_ip) {
            return (NetworkSignals::private(), None);
        }
        
        // Step 2: Use IPLocate API if available, fallback to heuristics
        if let Some(ipdata) = self.iplocate.lookup(input.remote_ip).await {
            return self.analyze_with_iplocate(ipdata, user_id);
        }
        
        // Fallback: Use heuristic-based analysis
        self.analyze_with_heuristics(input, user_id)
    }
    
    /// Analyze using IPLocate.io API response
    fn analyze_with_iplocate(&self, ipdata: IpLocateResponse, _user_id: Option<&str>) -> (NetworkSignals, Option<IpLocateResponse>) {
        // Map threat flags to ASN type
        let is_vpn = ipdata.is_vpn.unwrap_or(false);
        let is_proxy = ipdata.is_proxy.unwrap_or(false);
        let is_tor = ipdata.is_tor.unwrap_or(false);
        let is_datacenter = ipdata.is_datacenter.unwrap_or(false);
        
        let asn_type = if is_tor || is_vpn || is_proxy {
            AsnType::Anonymous
        } else if is_datacenter {
            AsnType::Hosting
        } else {
            AsnType::Residential
        };
        
        // Derive IP reputation
        let ip_reputation = if is_tor || is_proxy {
            IpReputation::High
        } else if is_vpn || is_datacenter {
            IpReputation::Medium
        } else {
            IpReputation::Low
        };
        
        // Phishing risk - Tor or proxy sources are high risk
        let is_phishing_source = is_tor || is_proxy;
        
        let signals = NetworkSignals {
            ip_reputation,
            asn_type,
            geo_velocity: GeoVelocity::Normal, // Calculated by SignalCollector
            country: ipdata.country_code.clone(),
            country_changed: false, // Calculated by SignalCollector
            is_phishing_source,
        };

        (signals, Some(ipdata))
    }
    
    /// Fallback heuristic-based analysis
    fn analyze_with_heuristics(&self, input: &NetworkInput, user_id: Option<&str>) -> (NetworkSignals, Option<IpLocateResponse>) {
        let asn_type = self.classify_asn_heuristic(&input.remote_ip);
        let ip_reputation = self.derive_reputation(&asn_type, &input.remote_ip);
        let country = self.lookup_country_heuristic(&input.remote_ip);
        
        let geo_velocity = if user_id.is_some() {
            GeoVelocity::Normal
        } else {
            GeoVelocity::Normal
        };
        
        let is_phishing_source = asn_type == AsnType::Anonymous || ip_reputation == IpReputation::High;
        
        let signals = NetworkSignals {
            ip_reputation,
            asn_type,
            geo_velocity,
            country,
            country_changed: false,
            is_phishing_source,
        };

        (signals, None)
    }
    
    fn is_private_or_reserved(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                v4.is_private() || v4.is_loopback() || v4.is_link_local()
            }
            IpAddr::V6(v6) => {
                v6.is_loopback() || v6.is_unspecified()
            }
        }
    }
    
    fn classify_asn_heuristic(&self, ip: &IpAddr) -> AsnType {
        // Simplified heuristic - fallback when IPLocate unavailable
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                // AWS ranges (simplified)
                if octets[0] == 52 || octets[0] == 54 || octets[0] == 35 {
                    return AsnType::Hosting;
                }
                // Google Cloud
                if octets[0] == 34 || octets[0] == 35 {
                    return AsnType::Hosting;
                }
                // DigitalOcean
                if octets[0] == 167 && octets[1] == 99 {
                    return AsnType::Hosting;
                }
            }
            _ => {}
        }
        AsnType::Residential
    }
    
    fn derive_reputation(&self, asn_type: &AsnType, _ip: &IpAddr) -> IpReputation {
        match asn_type {
            AsnType::Anonymous => IpReputation::High,
            AsnType::Hosting => IpReputation::Medium,
            AsnType::Residential => IpReputation::Low,
        }
    }
    
    fn lookup_country_heuristic(&self, _ip: &IpAddr) -> Option<String> {
        // Heuristic fallback - no country data without API
        None
    }
}

impl Default for NetworkSignalService {
    fn default() -> Self {
        Self::new(IpLocateClient::disabled())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    
    #[tokio::test]
    async fn test_private_ip() {
        let service = NetworkSignalService::new(IpLocateClient::disabled());
        let input = NetworkInput {
            remote_ip: IpAddr::from_str("192.168.1.1").unwrap(),
            x_forwarded_for: None,
            user_agent: "test".to_string(),
            accept_language: None,
            timestamp: Utc::now(),
        };
        
        let (signals, _) = service.analyze(&input, None).await;
        
        assert_eq!(signals.ip_reputation, IpReputation::Low);
        assert_eq!(signals.asn_type, AsnType::Residential);
    }
    
    #[tokio::test]
    async fn test_hosting_ip() {
        let service = NetworkSignalService::new(IpLocateClient::disabled());
        let input = NetworkInput {
            remote_ip: IpAddr::from_str("52.1.2.3").unwrap(),
            x_forwarded_for: None,
            user_agent: "test".to_string(),
            accept_language: None,
            timestamp: Utc::now(),
        };
        
        let (signals, _) = service.analyze(&input, None).await;
        
        // With disabled client, falls back to heuristics
        assert_eq!(signals.asn_type, AsnType::Hosting);
        assert_eq!(signals.ip_reputation, IpReputation::Medium);
    }
}
