use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use super::WireError;
use super::varint::{decode_varint, encode_varint};

pub const CAPSULE_DATAGRAM: u64 = 0x00;
pub const CAPSULE_ADDRESS_ASSIGN: u64 = 0x01;
pub const CAPSULE_ADDRESS_REQUEST: u64 = 0x02;
pub const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x03;

const DEFAULT_MAX_CAPSULE_SIZE: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignedAddress {
    pub request_id: u64,
    pub ip: IpAddr,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRange {
    pub start: IpAddr,
    pub end: IpAddr,
    pub ip_protocol: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capsule {
    Datagram(Bytes),
    AddressAssign(Vec<AssignedAddress>),
    AddressRequest(Vec<AssignedAddress>),
    RouteAdvertisement(Vec<AddressRange>),
    Unknown { capsule_type: u64, payload: Bytes },
}

/// Encode a `Capsule` into RFC 9297 TLV wire bytes (`Type | Length | Value`).
pub fn encode_capsule(capsule: &Capsule) -> Bytes {
    let mut out = BytesMut::new();
    match capsule {
        Capsule::Datagram(payload) => encode_raw(CAPSULE_DATAGRAM, payload, &mut out),
        Capsule::AddressAssign(addrs) => {
            let value = encode_assigned_addresses(addrs);
            encode_raw(CAPSULE_ADDRESS_ASSIGN, &value, &mut out);
        }
        Capsule::AddressRequest(addrs) => {
            let value = encode_assigned_addresses(addrs);
            encode_raw(CAPSULE_ADDRESS_REQUEST, &value, &mut out);
        }
        Capsule::RouteAdvertisement(ranges) => {
            let value = encode_address_ranges(ranges);
            encode_raw(CAPSULE_ROUTE_ADVERTISEMENT, &value, &mut out);
        }
        Capsule::Unknown {
            capsule_type,
            payload,
        } => encode_raw(*capsule_type, payload, &mut out),
    }
    out.freeze()
}

fn encode_raw(capsule_type: u64, value: &[u8], out: &mut BytesMut) {
    encode_varint(capsule_type, out).expect("capsule type fits QUIC varint");
    encode_varint(value.len() as u64, out).expect("capsule length fits QUIC varint");
    out.put_slice(value);
}

fn encode_assigned_addresses(addrs: &[AssignedAddress]) -> BytesMut {
    let mut value = BytesMut::with_capacity(addrs.len() * 19);
    for addr in addrs {
        encode_varint(addr.request_id, &mut value).expect("request_id fits QUIC varint");
        match addr.ip {
            IpAddr::V4(v4) => {
                value.put_u8(4);
                value.put_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                value.put_u8(6);
                value.put_slice(&v6.octets());
            }
        }
        value.put_u8(addr.prefix_len);
    }
    value
}

fn encode_address_ranges(ranges: &[AddressRange]) -> BytesMut {
    let mut value = BytesMut::with_capacity(ranges.len() * 34);
    for range in ranges {
        match (range.start, range.end) {
            (IpAddr::V4(start), IpAddr::V4(end)) => {
                value.put_u8(4);
                value.put_slice(&start.octets());
                value.put_slice(&end.octets());
            }
            (IpAddr::V6(start), IpAddr::V6(end)) => {
                value.put_u8(6);
                value.put_slice(&start.octets());
                value.put_slice(&end.octets());
            }
            _ => panic!("AddressRange start and end IP families must match"),
        }
        value.put_u8(range.ip_protocol);
    }
    value
}

/// Incremental RFC 9297 Capsule Protocol decoder.
pub struct CapsuleDecoder {
    buf: BytesMut,
    max_capsule_size: usize,
}

impl Default for CapsuleDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl CapsuleDecoder {
    pub fn new() -> Self {
        Self::with_max_capsule_size(DEFAULT_MAX_CAPSULE_SIZE)
    }

    pub fn with_max_capsule_size(max_capsule_size: usize) -> Self {
        Self {
            buf: BytesMut::new(),
            max_capsule_size,
        }
    }

    /// Append incoming stream bytes to the decoder buffer.
    pub fn feed(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// Number of unparsed bytes currently buffered.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Decode the next complete capsule from the buffer, if available.
    pub fn next_capsule(&mut self) -> Result<Option<Capsule>, WireError> {
        let (capsule_type, tlen) = match decode_varint(&self.buf) {
            Ok(v) => v,
            Err(WireError::Incomplete) => return Ok(None),
            Err(e) => return Err(e),
        };

        let (length, llen) = match decode_varint(&self.buf[tlen..]) {
            Ok(v) => v,
            Err(WireError::Incomplete) => return Ok(None),
            Err(e) => return Err(e),
        };

        if length > self.max_capsule_size as u64 {
            return Err(WireError::TooLarge {
                length,
                max: self.max_capsule_size,
            });
        }

        let header_len = tlen + llen;
        let payload_len = usize::try_from(length)
            .map_err(|_| WireError::Malformed("capsule length overflows usize".into()))?;
        let total_len = header_len
            .checked_add(payload_len)
            .ok_or_else(|| WireError::Malformed("capsule length overflows usize".into()))?;

        if self.buf.len() < total_len {
            return Ok(None);
        }

        self.buf.advance(header_len);
        let payload = self.buf.split_to(payload_len).freeze();
        let capsule = parse_capsule_value(capsule_type, payload)?;
        Ok(Some(capsule))
    }
}

fn parse_capsule_value(capsule_type: u64, payload: Bytes) -> Result<Capsule, WireError> {
    match capsule_type {
        CAPSULE_DATAGRAM => Ok(Capsule::Datagram(payload)),
        CAPSULE_ADDRESS_ASSIGN => Ok(Capsule::AddressAssign(parse_assigned_addresses(&payload)?)),
        CAPSULE_ADDRESS_REQUEST => Ok(Capsule::AddressRequest(parse_requested_addresses(&payload)?)),
        CAPSULE_ROUTE_ADVERTISEMENT => {
            Ok(Capsule::RouteAdvertisement(parse_address_ranges(&payload)?))
        }
        _ => Ok(Capsule::Unknown {
            capsule_type,
            payload,
        }),
    }
}

fn parse_requested_addresses(buf: &[u8]) -> Result<Vec<AssignedAddress>, WireError> {
    let addrs = parse_assigned_addresses(buf)?;
    if addrs.is_empty() {
        return Err(WireError::Malformed("empty ADDRESS_REQUEST".into()));
    }
    if addrs.iter().any(|a| a.request_id == 0) {
        return Err(WireError::Malformed(
            "zero ADDRESS_REQUEST identifier".into(),
        ));
    }
    Ok(addrs)
}

fn parse_assigned_addresses(mut buf: &[u8]) -> Result<Vec<AssignedAddress>, WireError> {
    let mut addrs = Vec::new();
    while !buf.is_empty() {
        let (request_id, rlen) = decode_varint(buf)
            .map_err(|_| WireError::Malformed("truncated request_id".into()))?;
        buf = &buf[rlen..];

        let (&ip_version, rest) = buf
            .split_first()
            .ok_or_else(|| WireError::Malformed("missing ip_version".into()))?;
        buf = rest;

        let ip = match ip_version {
            4 => {
                if buf.len() < 4 {
                    return Err(WireError::Malformed("truncated IPv4 address".into()));
                }
                let octets: [u8; 4] = buf[..4].try_into().unwrap();
                buf = &buf[4..];
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            6 => {
                if buf.len() < 16 {
                    return Err(WireError::Malformed("truncated IPv6 address".into()));
                }
                let octets: [u8; 16] = buf[..16].try_into().unwrap();
                buf = &buf[16..];
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            v => return Err(WireError::Malformed(format!("invalid ip_version: {v}"))),
        };

        let (&prefix_len, rest) = buf
            .split_first()
            .ok_or_else(|| WireError::Malformed("missing prefix_len".into()))?;
        buf = rest;

        let network = ipnetwork::IpNetwork::new(ip, prefix_len)
            .map_err(|_| WireError::Malformed("invalid prefix length".into()))?;
        if network.network() != ip {
            return Err(WireError::Malformed("non-canonical address prefix".into()));
        }

        addrs.push(AssignedAddress {
            request_id,
            ip,
            prefix_len,
        });
    }
    Ok(addrs)
}

fn parse_address_ranges(mut buf: &[u8]) -> Result<Vec<AddressRange>, WireError> {
    let mut ranges = Vec::new();
    let mut previous: Option<(u8, u8, u128)> = None;

    while !buf.is_empty() {
        let (&ip_version, rest) = buf
            .split_first()
            .ok_or_else(|| WireError::Malformed("missing ip_version".into()))?;
        buf = rest;

        let (start, end, start_u128, end_u128) = match ip_version {
            4 => {
                if buf.len() < 8 {
                    return Err(WireError::Malformed("truncated IPv4 range".into()));
                }
                let s = Ipv4Addr::from(<[u8; 4]>::try_from(&buf[..4]).unwrap());
                let e = Ipv4Addr::from(<[u8; 4]>::try_from(&buf[4..8]).unwrap());
                buf = &buf[8..];
                (
                    IpAddr::V4(s),
                    IpAddr::V4(e),
                    u128::from(u32::from(s)),
                    u128::from(u32::from(e)),
                )
            }
            6 => {
                if buf.len() < 32 {
                    return Err(WireError::Malformed("truncated IPv6 range".into()));
                }
                let s = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[..16]).unwrap());
                let e = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[16..32]).unwrap());
                buf = &buf[32..];
                (IpAddr::V6(s), IpAddr::V6(e), u128::from(s), u128::from(e))
            }
            v => return Err(WireError::Malformed(format!("invalid ip_version: {v}"))),
        };

        let (&ip_protocol, rest) = buf
            .split_first()
            .ok_or_else(|| WireError::Malformed("missing ip_protocol".into()))?;
        buf = rest;

        if start_u128 > end_u128
            || previous.is_some_and(|(prev_ver, prev_proto, prev_end)| {
                (prev_ver, prev_proto) > (ip_version, ip_protocol)
                    || ((prev_ver, prev_proto) == (ip_version, ip_protocol)
                        && prev_end >= start_u128)
            })
        {
            return Err(WireError::Malformed("invalid route range ordering".into()));
        }
        previous = Some((ip_version, ip_protocol, end_u128));

        ranges.push(AddressRange {
            start,
            end,
            ip_protocol,
        });
    }

    Ok(ranges)
}
