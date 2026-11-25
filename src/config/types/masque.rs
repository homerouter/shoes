use std::collections::HashSet;
use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use serde::{Deserialize, Serialize};

use crate::option_util::NoneOrSome;

const DEFAULT_UDP_TEMPLATE: &str = "/.well-known/masque/udp/{target_host}/{target_port}/";
const DEFAULT_IP_TEMPLATE: &str = "/.well-known/masque/ip/{target}/{ipproto}/";
const DEFAULT_MTU: u16 = 1280;
const DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 1024;

pub(crate) fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MasqueUserConfig {
    pub username: String,
    pub password: String,
}

impl fmt::Debug for MasqueUserConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasqueUserConfig")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct MasqueServerConfig {
    #[serde(alias = "user", skip_serializing_if = "NoneOrSome::is_unspecified")]
    pub users: NoneOrSome<MasqueUserConfig>,
    pub udp_enabled: bool,
    pub udp_template: String,
    pub ip_enabled: bool,
    pub ip_template: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tunnel_addresses: Vec<IpNetwork>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub advertise_routes: Vec<IpNetwork>,
    pub mtu: u16,
    pub stealth_404: bool,
    pub max_concurrent_requests: usize,
}

impl Default for MasqueServerConfig {
    fn default() -> Self {
        Self {
            users: NoneOrSome::Unspecified,
            udp_enabled: true,
            udp_template: DEFAULT_UDP_TEMPLATE.to_string(),
            ip_enabled: false,
            ip_template: DEFAULT_IP_TEMPLATE.to_string(),
            tunnel_addresses: Vec::new(),
            advertise_routes: Vec::new(),
            mtu: DEFAULT_MTU,
            stealth_404: true,
            max_concurrent_requests: DEFAULT_MAX_CONCURRENT_REQUESTS,
        }
    }
}

impl MasqueServerConfig {
    pub fn validate(&self) -> io::Result<()> {
        let mut seen_usernames = HashSet::new();
        for user in self.users.iter() {
            if user.username.is_empty() {
                return Err(invalid("MASQUE username must not be empty"));
            }
            if user.password.is_empty() {
                return Err(invalid("MASQUE password must not be empty"));
            }
            if !seen_usernames.insert(user.username.as_str()) {
                return Err(invalid(&format!(
                    "duplicate MASQUE username: {}",
                    user.username
                )));
            }
        }

        crate::masque::wire::UdpUriTemplate::parse(&self.udp_template)?;
        crate::masque::wire::IpUriTemplate::parse(&self.ip_template)?;

        if self.mtu < DEFAULT_MTU {
            return Err(invalid("MASQUE mtu must be at least 1280"));
        }
        if self.max_concurrent_requests == 0 {
            return Err(invalid(
                "MASQUE max_concurrent_requests must be at least 1",
            ));
        }

        if self.ip_enabled && self.tunnel_addresses.is_empty() {
            return Err(invalid(
                "MASQUE tunnel_addresses must not be empty when ip_enabled is true",
            ));
        }

        let mut has_v4 = false;
        let mut has_v6 = false;
        for network in &self.tunnel_addresses {
            match network {
                IpNetwork::V4(v4) => {
                    if has_v4 {
                        return Err(invalid(
                            "MASQUE tunnel_addresses allows at most one IPv4 prefix",
                        ));
                    }
                    has_v4 = true;
                    if v4.prefix() > 30 {
                        return Err(invalid(
                            "MASQUE IPv4 tunnel_addresses prefix must be /30 or shorter to provide usable host addresses",
                        ));
                    }
                }
                IpNetwork::V6(v6) => {
                    if has_v6 {
                        return Err(invalid(
                            "MASQUE tunnel_addresses allows at most one IPv6 prefix",
                        ));
                    }
                    has_v6 = true;
                    if network.ip().to_canonical() != network.ip() {
                        return Err(invalid(
                            "MASQUE IPv6 tunnel_addresses must not be IPv4-mapped",
                        ));
                    }
                    if v6.prefix() > 126 {
                        return Err(invalid(
                            "MASQUE IPv6 tunnel_addresses prefix must be /126 or shorter to provide usable host addresses",
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    pub fn effective_advertise_routes(&self) -> Vec<IpNetwork> {
        if !self.ip_enabled {
            return Vec::new();
        }
        if !self.advertise_routes.is_empty() {
            return self.advertise_routes.clone();
        }
        let mut routes = Vec::new();
        if self
            .tunnel_addresses
            .iter()
            .any(|net| matches!(net, IpNetwork::V4(_)))
        {
            routes.push(IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::UNSPECIFIED, 0).expect("0.0.0.0/0 is valid"),
            ));
        }
        if self
            .tunnel_addresses
            .iter()
            .any(|net| matches!(net, IpNetwork::V6(_)))
        {
            routes.push(IpNetwork::V6(
                Ipv6Network::new(Ipv6Addr::UNSPECIFIED, 0).expect("::/0 is valid"),
            ));
        }
        routes
    }
}
