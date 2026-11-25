pub mod capsule;
pub mod datagram;
pub mod ip_packet;
pub mod uri;
pub mod varint;

#[cfg(test)]
mod tests;

use std::fmt;

#[allow(unused_imports)] // Re-exported for MASQUE server modules added in Tasks 3-6.
pub use capsule::{
    AddressRange, AssignedAddress, CAPSULE_ADDRESS_ASSIGN, CAPSULE_ADDRESS_REQUEST,
    CAPSULE_DATAGRAM, CAPSULE_ROUTE_ADVERTISEMENT, Capsule, CapsuleDecoder, encode_capsule,
};
#[allow(unused_imports)]
pub use datagram::{
    decode_context0_datagram, decode_datagram_context, encode_context0_datagram,
};
#[allow(unused_imports)]
pub use ip_packet::{
    IcmpErrorKind, IpPacketMeta, build_icmp_error, decrement_hop_limit, inspect_ip_packet,
};
#[allow(unused_imports)]
pub use uri::{IpTunnelTarget, IpUriTemplate, TargetHostPort, UdpUriTemplate};
#[allow(unused_imports)]
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
