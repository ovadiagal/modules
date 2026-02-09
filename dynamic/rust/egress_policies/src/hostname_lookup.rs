//! Network filter for hostname lookup from virtual IP.
//!
//! This filter:
//! 1. Receives TCP connections on port 17100
//! 2. Extracts destination virtual IP from connection
//! 3. Looks up policy in VirtualIpCache
//! 4. Stores ALL metadata generically as FilterState (envoy.wildcard.metadata.<key>)
//! 5. Stores hostname as FilterState (envoy.wildcard.hostname)
//!
//! The metadata can then be used by other filters:
//! - set_filter_state: Converts upstream_cluster to PerConnectionCluster
//! - tcp_proxy: Uses tunneling_hostname and other metadata via %FILTER_STATE(...)%
//!
//! Configuration: Empty (no config needed)

use envoy_proxy_dynamic_modules_rust_sdk::*;
use std::net::Ipv4Addr;

use super::virtual_ip_cache::get_cache;

pub struct HostnameLookupFilterConfig {}

pub fn new_network_filter_config<EC: EnvoyNetworkFilterConfig, ENF: EnvoyNetworkFilter>(
    _envoy_filter_config: &mut EC,
    _name: &str,
    _config: &[u8],
) -> Option<Box<dyn NetworkFilterConfig<ENF>>> {
    envoy_log_info!("HostnameLookup filter initialized");
    Some(Box::new(HostnameLookupFilterConfig {}))
}

impl<ENF: EnvoyNetworkFilter> NetworkFilterConfig<ENF> for HostnameLookupFilterConfig {
    fn new_network_filter(&self, _envoy: &mut ENF) -> Box<dyn NetworkFilter<ENF>> {
        Box::new(HostnameLookupFilter {})
    }
}

struct HostnameLookupFilter {}

impl<ENF: EnvoyNetworkFilter> NetworkFilter<ENF> for HostnameLookupFilter {
    fn on_new_connection(
        &mut self,
        envoy_filter: &mut ENF,
    ) -> abi::envoy_dynamic_module_type_on_network_filter_data_status {
        let (ip_str, port) = envoy_filter.get_local_address();
        envoy_log_info!("hostname_lookup: new connection, local_address={}:{}", ip_str, port);

        let ip: Ipv4Addr = match ip_str.parse() {
            Ok(ip) => ip,
            Err(_) => {
                envoy_log_warn!("hostname_lookup: failed to parse destination IP: {}", ip_str);
                return abi::envoy_dynamic_module_type_on_network_filter_data_status::Continue;
            }
        };

        let cache = get_cache();
        let policy = match cache.lookup(ip) {
            Some(p) => p,
            None => {
                envoy_log_warn!("hostname_lookup: no policy found for virtual IP: {} (cache miss)", ip);
                return abi::envoy_dynamic_module_type_on_network_filter_data_status::Continue;
            }
        };

        envoy_log_info!(
            "hostname_lookup: cache hit for virtual IP {}: domain={}, metadata keys=[{}]",
            ip,
            policy.domain,
            policy.metadata.keys().cloned().collect::<Vec<_>>().join(", ")
        );

        let hostname_key = "envoy.wildcard.hostname";
        if !envoy_filter.set_filter_state_bytes(
            hostname_key.as_bytes(),
            policy.domain.as_bytes(),
        ) {
            envoy_log_error!("hostname_lookup: failed to set filter state for hostname");
        } else {
            envoy_log_info!("hostname_lookup: set filter state: {} = {}", hostname_key, policy.domain);
        }

        for (key, value) in &policy.metadata {
            let filter_state_key = format!("envoy.wildcard.metadata.{}", key);

            if !envoy_filter.set_filter_state_bytes(
                filter_state_key.as_bytes(),
                value.as_bytes(),
            ) {
                envoy_log_error!("hostname_lookup: failed to set filter state for key: {}", filter_state_key);
            } else {
                envoy_log_info!("hostname_lookup: set filter state: {} = {}", filter_state_key, value);
            }
        }

        abi::envoy_dynamic_module_type_on_network_filter_data_status::Continue
    }

    fn on_read(
        &mut self,
        _envoy_filter: &mut ENF,
        _data_length: usize,
        _end_stream: bool,
    ) -> abi::envoy_dynamic_module_type_on_network_filter_data_status {
        abi::envoy_dynamic_module_type_on_network_filter_data_status::Continue
    }

    fn on_write(
        &mut self,
        _envoy_filter: &mut ENF,
        _data_length: usize,
        _end_stream: bool,
    ) -> abi::envoy_dynamic_module_type_on_network_filter_data_status {
        abi::envoy_dynamic_module_type_on_network_filter_data_status::Continue
    }

    fn on_event(
        &mut self,
        _envoy_filter: &mut ENF,
        event: abi::envoy_dynamic_module_type_network_connection_event,
    ) {
        match event {
            abi::envoy_dynamic_module_type_network_connection_event::RemoteClose
            | abi::envoy_dynamic_module_type_network_connection_event::LocalClose => {
                envoy_log_debug!("Connection closed");
            }
            _ => {}
        }
    }
}
