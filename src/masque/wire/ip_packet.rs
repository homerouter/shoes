use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, Bytes, BytesMut};

/// Extracted header metadata from a raw IPv4 or IPv6 packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpPacketMeta {
    pub version: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub ttl: u8,
}

/// ICMP error classification for `CONNECT-IP` routing / policy / MTU events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpErrorKind {
    NoRoute,
    SourcePolicy,
    AddressUnreachable,
    HopLimitExceeded,
    PacketTooBig(u16),
}

/// Inspect an IPv4 or IPv6 packet header without heap allocation.
pub fn inspect_ip_packet(pkt: &[u8]) -> Option<IpPacketMeta> {
    let version = *pkt.first()? >> 4;
    match version {
        4 => {
            if pkt.len() < 20 {
                return None;
            }
            let ihl = pkt[0] & 0x0f;
            if ihl < 5 {
                return None;
            }
            let header_len = usize::from(ihl) * 4;
            let total_len = usize::from(u16::from_be_bytes([pkt[2], pkt[3]]));
            if total_len < header_len || pkt.len() < total_len {
                return None;
            }
            Some(IpPacketMeta {
                version: 4,
                src: IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15])),
                dst: IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19])),
                proto: pkt[9],
                ttl: pkt[8],
            })
        }
        6 => {
            if pkt.len() < 40 {
                return None;
            }
            let payload_len = usize::from(u16::from_be_bytes([pkt[4], pkt[5]]));
            if pkt.len() < 40 + payload_len {
                return None;
            }
            let src: [u8; 16] = pkt[8..24].try_into().ok()?;
            let dst: [u8; 16] = pkt[24..40].try_into().ok()?;
            Some(IpPacketMeta {
                version: 6,
                src: IpAddr::V6(Ipv6Addr::from(src)),
                dst: IpAddr::V6(Ipv6Addr::from(dst)),
                proto: pkt[6],
                ttl: pkt[7],
            })
        }
        _ => None,
    }
}

/// Decrement IPv4 TTL (updating header checksum) or IPv6 Hop Limit in place.
///
/// Returns `false` if the packet is malformed or `ttl <= 1` (caller must not
/// forward and should generate `IcmpErrorKind::HopLimitExceeded`).
pub fn decrement_hop_limit(pkt: &mut [u8]) -> bool {
    let Some(meta) = inspect_ip_packet(pkt) else {
        return false;
    };
    if meta.ttl <= 1 {
        return false;
    }
    match meta.version {
        4 => {
            pkt[8] -= 1;
            // RFC 1624 incremental checksum update for byte 8 decreasing by 1 (-0x0100).
            let old_csum = u16::from_be_bytes([pkt[10], pkt[11]]);
            let mut sum = u32::from(!old_csum) + 0xfeff;
            while (sum >> 16) != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            let new_csum = !(sum as u16);
            pkt[10..12].copy_from_slice(&new_csum.to_be_bytes());
            true
        }
        6 => {
            pkt[7] -= 1;
            true
        }
        _ => false,
    }
}

/// Build an ICMPv4 or ICMPv6 error packet addressed back to `orig_pkt`'s source.
pub fn build_icmp_error(
    orig_pkt: &[u8],
    kind: IcmpErrorKind,
    router_v4: Option<Ipv4Addr>,
    router_v6: Option<Ipv6Addr>,
) -> Option<Bytes> {
    let meta = inspect_ip_packet(orig_pkt)?;
    match (meta.src, meta.dst) {
        (IpAddr::V4(orig_src), IpAddr::V4(_)) => {
            let src = router_v4?;
            // Do not send ICMP error in response to an ICMPv4 error message.
            if meta.proto == 1 {
                let ihl = usize::from(orig_pkt[0] & 0x0f) * 4;
                if let Some(&icmp_type) = orig_pkt.get(ihl)
                    && matches!(icmp_type, 3 | 4 | 5 | 11 | 12)
                {
                    return None;
                }
            }
            Some(build_icmpv4_error(orig_pkt, orig_src, src, kind))
        }
        (IpAddr::V6(orig_src), IpAddr::V6(_)) => {
            let src = router_v6?;
            // Do not send ICMPv6 error in response to an ICMPv6 error message (< 128).
            if meta.proto == 58
                && let Some(&icmp_type) = orig_pkt.get(40)
                && icmp_type < 128
            {
                return None;
            }
            Some(build_icmpv6_error(orig_pkt, orig_src, src, kind))
        }
        _ => None,
    }
}

fn build_icmpv4_error(
    orig_pkt: &[u8],
    dst: Ipv4Addr,
    src: Ipv4Addr,
    kind: IcmpErrorKind,
) -> Bytes {
    let (icmp_type, icmp_code, rest_of_header) = match kind {
        IcmpErrorKind::NoRoute => (3u8, 0u8, 0u32),
        IcmpErrorKind::SourcePolicy => (3, 13, 0),
        IcmpErrorKind::AddressUnreachable => (3, 1, 0),
        IcmpErrorKind::HopLimitExceeded => (11, 0, 0),
        IcmpErrorKind::PacketTooBig(mtu) => (3, 4, u32::from(mtu)),
    };

    // RFC 1812 §4.3.2.3: cap total ICMPv4 packet at 576 bytes (20 IP + 8 ICMP + 548 quoted).
    let quoted_len = orig_pkt.len().min(576 - 28);
    let total_len = 20 + 8 + quoted_len;
    let mut pkt = BytesMut::with_capacity(total_len);

    // IPv4 header
    pkt.put_u8(0x45);
    pkt.put_u8(0);
    pkt.put_u16(total_len as u16);
    pkt.put_u16(0); // Identification
    pkt.put_u16(0); // Flags/FragOffset
    pkt.put_u8(64); // TTL
    pkt.put_u8(1); // Protocol: ICMP
    pkt.put_u16(0); // Checksum placeholder
    pkt.put_slice(&src.octets());
    pkt.put_slice(&dst.octets());

    let ip_csum = ones_complement_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // ICMPv4 header + quoted packet
    pkt.put_u8(icmp_type);
    pkt.put_u8(icmp_code);
    pkt.put_u16(0); // Checksum placeholder
    pkt.put_u32(rest_of_header);
    pkt.put_slice(&orig_pkt[..quoted_len]);

    let icmp_csum = ones_complement_checksum(&pkt[20..]);
    pkt[22..24].copy_from_slice(&icmp_csum.to_be_bytes());

    pkt.freeze()
}

fn build_icmpv6_error(
    orig_pkt: &[u8],
    dst: Ipv6Addr,
    src: Ipv6Addr,
    kind: IcmpErrorKind,
) -> Bytes {
    let (icmp_type, icmp_code, rest_of_header) = match kind {
        IcmpErrorKind::NoRoute => (1u8, 0u8, 0u32),
        IcmpErrorKind::SourcePolicy => (1, 1, 0),
        IcmpErrorKind::AddressUnreachable => (1, 3, 0),
        IcmpErrorKind::HopLimitExceeded => (3, 0, 0),
        IcmpErrorKind::PacketTooBig(mtu) => (2, 0, u32::from(mtu)),
    };

    // RFC 4443 §2.4(c): cap total ICMPv6 packet at 1280 bytes (40 IPv6 + 8 ICMPv6 + 1232 quoted).
    let quoted_len = orig_pkt.len().min(1280 - 48);
    let payload_len = 8 + quoted_len;
    let mut pkt = BytesMut::with_capacity(40 + payload_len);

    // IPv6 header
    pkt.put_u32(0x6000_0000);
    pkt.put_u16(payload_len as u16);
    pkt.put_u8(58); // Next Header: ICMPv6
    pkt.put_u8(64); // Hop Limit
    pkt.put_slice(&src.octets());
    pkt.put_slice(&dst.octets());

    // ICMPv6 header + quoted packet
    pkt.put_u8(icmp_type);
    pkt.put_u8(icmp_code);
    pkt.put_u16(0); // Checksum placeholder
    pkt.put_u32(rest_of_header);
    pkt.put_slice(&orig_pkt[..quoted_len]);

    // IPv6 pseudo-header checksum
    let mut sum = sum_16bit(&src.octets(), 0);
    sum = sum_16bit(&dst.octets(), sum);
    sum = sum_16bit(&(payload_len as u32).to_be_bytes(), sum);
    sum = sum_16bit(&[0, 0, 0, 58], sum);
    sum = sum_16bit(&pkt[40..], sum);
    let icmp_csum = fold_and_invert(sum);
    pkt[42..44].copy_from_slice(&icmp_csum.to_be_bytes());

    pkt.freeze()
}

fn sum_16bit(data: &[u8], mut sum: u32) -> u32 {
    let (pairs, rest) = data.as_chunks::<2>();
    for pair in pairs {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    if let Some(&last) = rest.first() {
        sum += u32::from(u16::from_be_bytes([last, 0]));
    }
    sum
}

fn fold_and_invert(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn ones_complement_checksum(data: &[u8]) -> u16 {
    fold_and_invert(sum_16bit(data, 0))
}
