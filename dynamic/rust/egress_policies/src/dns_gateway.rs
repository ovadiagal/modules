//! UDP listener filter for DNS-based routing with virtual IP allocation.
//!
//! This filter:
//! 1. Listens on port 5353 for DNS queries
//! 2. Parses DNS A record queries
//! 3. Matches domains against configured policies
//! 4. Allocates virtual IPs via VirtualIpCache
//! 5. Returns DNS A responses

use envoy_proxy_dynamic_modules_rust_sdk::*;
use std::net::Ipv4Addr;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};

use super::virtual_ip_cache::{get_cache, init_cache, EgressPolicy};

/// DNS Gateway filter configuration.
pub struct DnsGatewayFilterConfig {
    policies: Vec<PolicyMatcher>,
}

/// Policy matcher with domain pattern and metadata.
struct PolicyMatcher {
    domain_pattern: String,
    metadata: std::collections::HashMap<String, String>,
}

impl PolicyMatcher {
    /// Matches a domain against this policy's pattern.
    /// Supports wildcard patterns like "*.aws.com".
    fn matches(&self, domain: &str) -> bool {
        if self.domain_pattern.starts_with("*.") {
            // Wildcard match: *.aws.com matches api.aws.com
            let suffix = &self.domain_pattern[2..];
            domain.ends_with(suffix)
        } else {
            // Exact match
            domain == self.domain_pattern
        }
    }
}

/// Creates a new DNS gateway filter configuration.
pub fn new_udp_filter_config<EC: EnvoyUdpListenerFilterConfig, ELF: EnvoyUdpListenerFilter>(
    _envoy_filter_config: &mut EC,
    _name: &str,
    config: &[u8],
) -> Option<Box<dyn UdpListenerFilterConfig<ELF>>> {
    // Parse config as JSON. The config arrives as a JSON-serialized google.protobuf.Any.
    // Supported wrappers:
    //   - StringValue: {"@type":"...StringValue", "value":"<json string>"}
    //   - Struct:      {"@type":"...Struct", "value":{"base_ip":"...", ...}}
    let config_str = std::str::from_utf8(config).ok()?;
    let outer_json: serde_json::Value = serde_json::from_str(config_str).ok()?;

    let config_json: serde_json::Value = match &outer_json["value"] {
        // StringValue: "value" is a JSON string that we parse again.
        serde_json::Value::String(s) => serde_json::from_str(s).ok()?,
        // Struct: "value" is already an object with our config fields.
        serde_json::Value::Object(_) => outer_json["value"].clone(),
        // Fallback: use the outer object directly.
        _ => outer_json,
    };

    // Parse base_ip from config (default: 10.10.0.0)
    let base_ip_str = config_json["base_ip"]
        .as_str()
        .unwrap_or("10.10.0.0");

    let base_ip: Ipv4Addr = base_ip_str.parse().ok()?;
    let base_ip_u32 = u32::from(base_ip);

    // Initialize the cache (first call wins, subsequent calls are ignored)
    let _ = init_cache(base_ip_u32);

    // Parse policies
    let policies_array = config_json["policies"].as_array()?;
    let mut policies = Vec::new();

    for policy_json in policies_array {
        let domain_pattern = policy_json["domain"].as_str()?.to_string();
        let metadata_obj = policy_json["metadata"].as_object()?;

        let mut metadata = std::collections::HashMap::new();
        for (key, value) in metadata_obj {
            if let Some(value_str) = value.as_str() {
                metadata.insert(key.clone(), value_str.to_string());
            }
        }

        policies.push(PolicyMatcher {
            domain_pattern,
            metadata,
        });
    }

    envoy_log_info!("DnsGateway initialized with {} policies", policies.len());

    Some(Box::new(DnsGatewayFilterConfig { policies }))
}

impl<ELF: EnvoyUdpListenerFilter> UdpListenerFilterConfig<ELF> for DnsGatewayFilterConfig {
    fn new_udp_listener_filter(&self, _envoy: &mut ELF) -> Box<dyn UdpListenerFilter<ELF>> {
        Box::new(DnsGatewayFilter {
            policies: self
                .policies
                .iter()
                .map(|p| PolicyMatcher {
                    domain_pattern: p.domain_pattern.clone(),
                    metadata: p.metadata.clone(),
                })
                .collect(),
        })
    }
}

/// DNS Gateway filter instance.
struct DnsGatewayFilter {
    policies: Vec<PolicyMatcher>,
}

impl<ELF: EnvoyUdpListenerFilter> UdpListenerFilter<ELF> for DnsGatewayFilter {
    fn on_data(
        &mut self,
        envoy_filter: &mut ELF,
    ) -> abi::envoy_dynamic_module_type_on_udp_listener_filter_status {
        // Get datagram data
        let (chunks, total_length) = envoy_filter.get_datagram_data();
        envoy_log_info!("dns_gateway: received UDP datagram, {} bytes, {} chunks", total_length, chunks.len());
        let mut data = Vec::new();
        for chunk in &chunks {
            data.extend_from_slice(chunk.as_slice());
        }

        // Get peer address for sending the response back
        let peer = envoy_filter.get_peer_address();
        envoy_log_info!("dns_gateway: peer address: {:?}", peer);

        // Parse DNS query using hickory-dns
        let mut decoder = BinDecoder::new(&data);
        let query_message = match Message::read(&mut decoder) {
            Ok(msg) => msg,
            Err(e) => {
                envoy_log_warn!("dns_gateway: failed to parse DNS query: {}", e);
                return abi::envoy_dynamic_module_type_on_udp_listener_filter_status::Continue;
            }
        };

        envoy_log_info!("dns_gateway: parsed DNS message id={}, type={:?}, queries={}",
            query_message.id(), query_message.message_type(), query_message.queries().len());

        // Validate it's a query and has at least one question
        if query_message.message_type() != MessageType::Query {
            envoy_log_warn!("dns_gateway: received non-query DNS message");
            return abi::envoy_dynamic_module_type_on_udp_listener_filter_status::Continue;
        }

        let question = match query_message.queries().first() {
            Some(q) => q,
            None => {
                envoy_log_warn!("dns_gateway: DNS query has no questions");
                return abi::envoy_dynamic_module_type_on_udp_listener_filter_status::Continue;
            }
        };

        // Only handle A record queries
        if question.query_type() != RecordType::A {
            envoy_log_info!("dns_gateway: ignoring non-A record query: {:?}", question.query_type());
            return abi::envoy_dynamic_module_type_on_udp_listener_filter_status::Continue;
        }

        let domain_raw = question.name().to_utf8();
        // DNS names are fully qualified with a trailing dot (e.g. "api.aws.com.").
        // Strip it so our wildcard patterns like "*.aws.com" match correctly.
        let domain = domain_raw.strip_suffix('.').unwrap_or(&domain_raw).to_string();
        envoy_log_info!("dns_gateway: A record query for domain: {} (raw: {})", domain, domain_raw);

        // Match against policies
        let matched_policy = self.policies.iter().find(|p| p.matches(&domain));

        if let Some(policy_matcher) = matched_policy {
            envoy_log_info!("dns_gateway: matched policy pattern '{}' for domain '{}'",
                policy_matcher.domain_pattern, domain);

            // Create EgressPolicy from matcher
            let policy = EgressPolicy {
                domain: domain.clone(),
                metadata: policy_matcher.metadata.clone(),
            };

            // Allocate virtual IP via cache
            let cache = get_cache();
            let virtual_ip = cache.allocate(policy);

            envoy_log_info!(
                "dns_gateway: allocated virtual IP {} for domain {}",
                virtual_ip,
                domain
            );

            // Craft DNS A response using hickory-dns
            let response_bytes = match craft_dns_response(&query_message, question.name(), virtual_ip) {
                Ok(bytes) => {
                    envoy_log_info!("dns_gateway: crafted DNS response, {} bytes", bytes.len());
                    bytes
                }
                Err(e) => {
                    envoy_log_error!("dns_gateway: failed to craft DNS response: {}", e);
                    return abi::envoy_dynamic_module_type_on_udp_listener_filter_status::Continue;
                }
            };

            // Send the DNS response back to the peer directly.
            // Note: set_datagram_data() only modifies the buffer in-place but doesn't
            // send it back. We must use send_datagram() to actually reply to the client.
            if let Some((peer_addr, peer_port)) = peer {
                envoy_log_info!("dns_gateway: sending {} byte response to {}:{}", response_bytes.len(), peer_addr, peer_port);
                if !envoy_filter.send_datagram(&response_bytes, &peer_addr, peer_port) {
                    envoy_log_error!("dns_gateway: failed to send datagram to {}:{}", peer_addr, peer_port);
                }
            } else {
                envoy_log_error!("dns_gateway: no peer address available, cannot send response");
            }

            // StopIteration prevents the udp_proxy filter from also forwarding this packet
            return abi::envoy_dynamic_module_type_on_udp_listener_filter_status::StopIteration;
        } else {
            envoy_log_info!("dns_gateway: no policy matched for domain: {}", domain);
        }

        // No match — let the packet continue to the next filter (udp_proxy)
        abi::envoy_dynamic_module_type_on_udp_listener_filter_status::Continue
    }
}

/// Crafts a DNS A response with the given virtual IP using hickory-dns.
///
/// This function creates a proper DNS response message with:
/// - The original query's transaction ID
/// - Standard query response flags
/// - The original question section
/// - An answer section with the allocated virtual IP
///
/// # Arguments
/// * `query_message` - The original DNS query message
/// * `name` - The domain name being queried
/// * `ip` - The virtual IP address to return
///
/// # Returns
/// The serialized DNS response as bytes, or an error if serialization fails
fn craft_dns_response(
    query_message: &Message,
    name: &Name,
    ip: Ipv4Addr,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut response = Message::new();

    // Copy transaction ID from query
    response.set_id(query_message.id());

    // Set response flags
    response.set_message_type(MessageType::Response);
    response.set_response_code(ResponseCode::NoError);
    response.set_recursion_desired(query_message.recursion_desired());
    response.set_recursion_available(true);

    // Add the original question
    if let Some(question) = query_message.queries().first() {
        response.add_query(question.clone());
    }

    // Create answer record
    let mut record = Record::new();
    record.set_name(name.clone());
    record.set_record_type(RecordType::A);
    record.set_ttl(60); // 60 seconds TTL
    record.set_data(Some(RData::A(ip.into())));

    // Add answer to response
    response.add_answer(record);

    // Serialize to bytes
    let bytes = response.to_vec()?;
    Ok(bytes)
}
