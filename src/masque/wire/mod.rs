pub mod capsule;
pub mod datagram;
pub mod ip_packet;
pub mod uri;
pub mod varint;

#[cfg(test)]
mod tests;

use std::fmt;

pub use capsule::{
    AddressRange, AssignedAddress, Capsule, CapsuleDecoder, encode_capsule,
};
#[cfg(test)]
pub use capsule::CAPSULE_DATAGRAM;
pub use datagram::{decode_context0_datagram, encode_context0_datagram};
#[cfg(test)]
pub use datagram::decode_datagram_context;
pub use ip_packet::{IcmpErrorKind, build_icmp_error, decrement_hop_limit, inspect_ip_packet};
#[cfg(test)]
pub use ip_packet::IpPacketMeta;
pub use uri::{IpUriTemplate, UdpUriTemplate};
#[cfg(test)]
pub use uri::{IpTunnelTarget, TargetHostPort};
#[cfg(test)]
pub use varint::{MAX_VARINT, decode_varint, encode_varint, varint_len};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    Incomplete,
    TooLarge { length: u64, max: usize },
    Malformed(String),
    InvalidVarint,
    Overflow,
    InvalidSegment(String),
    InvalidPort(String),
    InvalidProtocol(String),
    InvalidTarget,
    InvalidTemplate(String),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::Incomplete => write!(f, "incomplete wire data"),
            WireError::TooLarge { length, max } => {
                write!(f, "capsule value is {length} bytes, limit is {max}")
            }
            WireError::Malformed(msg) => write!(f, "malformed wire frame: {msg}"),
            WireError::InvalidVarint => write!(f, "invalid or truncated QUIC varint"),
            WireError::Overflow => write!(f, "varint value exceeds 2^62 - 1"),
            WireError::InvalidSegment(s) => write!(f, "invalid URI segment: {s}"),
            WireError::InvalidPort(s) => write!(f, "invalid port: {s}"),
            WireError::InvalidProtocol(s) => write!(f, "invalid IP protocol: {s}"),
            WireError::InvalidTarget => write!(f, "invalid target address or prefix"),
            WireError::InvalidTemplate(msg) => write!(f, "invalid URI template: {msg}"),
        }
    }
}

impl std::error::Error for WireError {}

impl From<WireError> for std::io::Error {
    fn from(err: WireError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, err)
    }
}
