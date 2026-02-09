use envoy_proxy_dynamic_modules_rust_sdk::*;


pub mod virtual_ip_cache;
pub mod dns_gateway;
pub mod hostname_lookup;

pub use virtual_ip_cache::{EgressPolicy, VirtualIpCache, get_cache, init_cache};
pub use dns_gateway::new_udp_filter_config as new_dns_gateway_config;
pub use hostname_lookup::new_network_filter_config as new_hostname_lookup_config;
