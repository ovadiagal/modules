//! Thread-safe virtual IP cache for wildcard DNS-based routing.
//!
//! This module provides a thread-safe virtual IP cache that:
//! 1. Allocates virtual IPs for DNS queries (via DnsGateway UDP filter)
//! 2. Looks up policies from virtual IPs (via HostnameLookup network filter)
//! 3. Uses lock-free concurrent data structures (DashMap) for performance
//! 4. Guarantees single allocation per domain via double-checked locking
//!
//! Architecture:
//! ```text
//! DNS Query (port 5353) → DnsGateway → allocate() → Virtual IP
//!                                          ↓
//! TCP Connection (port 17100) → HostnameLookup → lookup() → Policy metadata
//! ```
//!
//! The cache is globally accessible via a static instance initialized by the DNS gateway filter.
//!
//! Configuration:
//! The base IP address is configured in the DNS gateway filter config under the `base_ip` field.

use dashmap::DashMap;
use envoy_proxy_dynamic_modules_rust_sdk::*;
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use std::net::Ipv4Addr;
use std::sync::Arc;

/// Egress policy configuration
#[derive(Clone, Debug)]
pub struct EgressPolicy {
    /// e.g., "*.aws.com" or "s3.aws.com"
    pub domain: String,
    pub metadata: std::collections::HashMap<String, String>,
}

/// Virtual IP cache that provides thread-safe IP allocation and policy lookup.
pub struct VirtualIpCache {
    base_ip: u32,
    alloc_offset: Mutex<u32>,
    ip_to_policy: DashMap<Ipv4Addr, EgressPolicy>,
    domain_to_ip: DashMap<String, Ipv4Addr>,
}

impl VirtualIpCache {
    pub fn new(base_ip: u32) -> Self {
        Self {
            base_ip,
            alloc_offset: Mutex::new(0),
            ip_to_policy: DashMap::new(),
            domain_to_ip: DashMap::new(),
        }
    }

    /// Allocates a virtual IP for the given policy.
    pub fn allocate(&self, policy: EgressPolicy) -> Ipv4Addr {
        if let Some(ip) = self.domain_to_ip.get(&policy.domain) {
            return *ip;
        }

        let ip = {
            let mut offset = self.alloc_offset.lock();

            if let Some(ip) = self.domain_to_ip.get(&policy.domain) {
                return *ip;
            }

            let ip = Ipv4Addr::from(self.base_ip + *offset);
            *offset += 1;

            ip
        };

        self.ip_to_policy.insert(ip, policy.clone());
        self.domain_to_ip.insert(policy.domain.clone(), ip);

        envoy_log_info!("Allocated virtual IP {} for domain {}", ip, policy.domain);

        ip
    }

    pub fn lookup(&self, ip: Ipv4Addr) -> Option<EgressPolicy> {
        self.ip_to_policy.get(&ip).map(|entry| entry.clone())
    }

}

static VIRTUAL_IP_CACHE: OnceCell<Arc<VirtualIpCache>> = OnceCell::new();

/// Initializes the global cache with the given base IP address.
///
/// This should be called by the DNS gateway filter during configuration.
/// Can only be called once - subsequent calls will return an error.
///
/// # Arguments
/// * `base_ip` - The base IP address in network byte order (e.g., 10.10.0.0 = 0x0A0A0000)
///
/// # Returns
/// * `Ok(())` if initialization succeeded
/// * `Err(())` if the cache was already initialized
pub fn init_cache(base_ip: u32) -> Result<(), ()> {
    let cache = Arc::new(VirtualIpCache::new(base_ip));

    VIRTUAL_IP_CACHE.set(cache).map_err(|_| {
        envoy_log_warn!("VirtualIpCache already initialized, ignoring duplicate initialization");
    })?;

    envoy_log_info!(
        "Initialized VirtualIpCache with base IP {}",
        Ipv4Addr::from(base_ip)
    );

    Ok(())
}

/// Gets the global VirtualIpCache instance.
///
/// # Panics
/// Panics if the cache has not been initialized via `init_cache()`.
/// The DNS gateway filter should initialize the cache during configuration.
pub fn get_cache() -> Arc<VirtualIpCache> {
    VIRTUAL_IP_CACHE
        .get()
        .expect("VirtualIpCache not initialized - DNS gateway filter should call init_cache()")
        .clone()
}
