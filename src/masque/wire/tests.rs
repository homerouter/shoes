use super::*;
use bytes::{Buf, Bytes};
use h3::quic::StreamId;
use h3_datagram::datagram::Datagram;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (pairs, rest) = data.as_chunks::<2>();
    for pair in pairs {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    if let Some(&last) = rest.first() {
        sum += u32::from(u16::from_be_bytes([last, 0]));
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn icmpv6_checksum(src: Ipv6Addr, dst: Ipv6Addr, icmp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + icmp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(icmp);
    internet_checksum(&pseudo)
}

fn make_v4_udp(src: Ipv4Addr, dst: Ipv4Addr, ttl: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = (20 + 8 + payload.len()) as u16;
    let mut pkt = vec![0u8; total_len as usize];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&total_len.to_be_bytes());
    pkt[6] = 0x40; // DF
    pkt[8] = ttl;
    pkt[9] = 17; // UDP
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let csum = internet_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());
    pkt[20..22].copy_from_slice(&12345u16.to_be_bytes());
    pkt[22..24].copy_from_slice(&53u16.to_be_bytes());
    pkt[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    pkt
}

fn make_v6_udp(src: Ipv6Addr, dst: Ipv6Addr, hop_limit: u8, payload: &[u8]) -> Vec<u8> {
    let payload_len = (8 + payload.len()) as u16;
    let mut pkt = vec![0u8; 40 + payload_len as usize];
    pkt[0] = 0x60;
    pkt[4..6].copy_from_slice(&payload_len.to_be_bytes());
    pkt[6] = 17;
    pkt[7] = hop_limit;
    pkt[8..24].copy_from_slice(&src.octets());
    pkt[24..40].copy_from_slice(&dst.octets());
    pkt[40..42].copy_from_slice(&12345u16.to_be_bytes());
    pkt[42..44].copy_from_slice(&53u16.to_be_bytes());
    pkt[44..46].copy_from_slice(&payload_len.to_be_bytes());
    pkt[48..].copy_from_slice(payload);
    pkt
}

#[test]
fn varint_roundtrip_and_boundaries() {
    let cases = [
        (0u64, 1usize),
        (37, 1),
        (63, 1),
        (64, 2),
        (15_293, 2),
        (16_383, 2),
        (16_384, 4),
        (494_878_333, 4),
        (1_073_741_823, 4),
        (1_073_741_824, 8),
        (151_288_809_941_952_652, 8),
        (MAX_VARINT, 8),
    ];
    for (val, expected_len) in cases {
        let mut buf = bytes::BytesMut::new();
        let written = encode_varint(val, &mut buf).unwrap();
        assert_eq!(written, expected_len);
        assert_eq!(varint_len(val).unwrap(), expected_len);
        let (decoded, consumed) = decode_varint(&buf).unwrap();
        assert_eq!(decoded, val);
        assert_eq!(consumed, expected_len);
    }

    assert!(decode_varint(&[]).is_err());
    assert!(decode_varint(&[0x40]).is_err());
    assert!(decode_varint(&[0x80, 0x00]).is_err());
    assert!(decode_varint(&[0xc0, 0x00, 0x00, 0x00]).is_err());
    assert!(varint_len(MAX_VARINT + 1).is_err());
}

#[test]
fn context0_datagram_and_h3_datagram_roundtrip() {
    let payload = b"hello udp";
    let encoded = encode_context0_datagram(payload);
    assert_eq!(&encoded[..], b"\x00hello udp");
    assert_eq!(
        decode_context0_datagram(encoded.clone()).unwrap(),
        Some(Bytes::from_static(payload))
    );

    // Empty payload with context ID 0 is valid
    assert_eq!(
        decode_context0_datagram(Bytes::from_static(&[0x00])).unwrap(),
        Some(Bytes::new())
    );

    // Non-zero context IDs are ignored as Ok(None) by decode_context0_datagram
    assert_eq!(
        decode_context0_datagram(Bytes::from_static(&[0x01, 0xaa, 0xbb])).unwrap(),
        None
    );
    assert_eq!(
        decode_context0_datagram(Bytes::from_static(&[0x40, 0x42, 0xff])).unwrap(),
        None
    );
    assert_eq!(
        decode_datagram_context(Bytes::from_static(&[0x40, 0x42, 0xff])).unwrap(),
        (0x42, Bytes::from_static(&[0xff]))
    );

    // Truncated context ID returns Err
    assert!(decode_context0_datagram(Bytes::new()).is_err());
    assert!(decode_context0_datagram(Bytes::from_static(&[0x40])).is_err());

    // End-to-end with h3_datagram::datagram::Datagram (Quarter Stream ID + Context ID 0)
    let stream_id = StreamId::try_from(4).unwrap();
    let mut h3_wire = Datagram::new(stream_id, encoded).encode();
    let h3_bytes = h3_wire.copy_to_bytes(h3_wire.remaining());
    let decoded_h3 = Datagram::decode(h3_bytes).unwrap();
    assert_eq!(decoded_h3.stream_id(), stream_id);
    assert_eq!(
        decode_context0_datagram(decoded_h3.into_payload()).unwrap(),
        Some(Bytes::from_static(payload))
    );
}

#[test]
fn capsule_encode_and_incremental_decode() {
    let capsules = vec![
        Capsule::Datagram(Bytes::from_static(b"\x00packet")),
        Capsule::AddressAssign(vec![
            AssignedAddress {
                request_id: 1,
                ip: IpAddr::V4(Ipv4Addr::new(10, 10, 0, 2)),
                prefix_len: 32,
            },
            AssignedAddress {
                request_id: 2,
                ip: IpAddr::V6("fd00:10::2".parse().unwrap()),
                prefix_len: 128,
            },
        ]),
        Capsule::AddressRequest(vec![AssignedAddress {
            request_id: 42,
            ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            prefix_len: 32,
        }]),
        Capsule::RouteAdvertisement(vec![
            AddressRange {
                start: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                end: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
                ip_protocol: 0,
            },
            AddressRange {
                start: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                end: IpAddr::V6("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()),
                ip_protocol: 0,
            },
        ]),
        Capsule::Unknown {
            capsule_type: 0xff,
            payload: Bytes::from_static(b"\xde\xad"),
        },
    ];

    let mut wire = Vec::new();
    for cap in &capsules {
        wire.extend_from_slice(&encode_capsule(cap));
    }

    // Feed 1 byte at a time
    let mut dec = CapsuleDecoder::new();
    let mut out = Vec::new();
    for &b in &wire {
        dec.feed(&[b]);
        while let Some(c) = dec.next_capsule().unwrap() {
            out.push(c);
        }
    }
    assert_eq!(out, capsules);
    assert_eq!(dec.buffered(), 0);
}

#[test]
fn capsule_decoder_rejects_oversized_and_malformed() {
    // Header declares 65000 bytes, limit is 1200 -> error immediately without payload
    let mut wire = bytes::BytesMut::new();
    encode_varint(CAPSULE_DATAGRAM, &mut wire).unwrap();
    encode_varint(65_000, &mut wire).unwrap();
    let mut dec = CapsuleDecoder::with_max_capsule_size(1_200);
    dec.feed(&wire);
    assert!(matches!(dec.next_capsule(), Err(WireError::TooLarge { .. })));

    // Empty ADDRESS_REQUEST is malformed
    let empty_req = encode_capsule(&Capsule::AddressRequest(vec![]));
    let mut dec = CapsuleDecoder::new();
    dec.feed(&empty_req);
    assert!(matches!(dec.next_capsule(), Err(WireError::Malformed(_))));

    // Zero request_id in ADDRESS_REQUEST is malformed
    let zero_id_req = encode_capsule(&Capsule::AddressRequest(vec![AssignedAddress {
        request_id: 0,
        ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        prefix_len: 32,
    }]));
    let mut dec = CapsuleDecoder::new();
    dec.feed(&zero_id_req);
    assert!(matches!(dec.next_capsule(), Err(WireError::Malformed(_))));

    // Non-canonical prefix in ADDRESS_ASSIGN is malformed
    let non_canon = encode_capsule(&Capsule::AddressAssign(vec![AssignedAddress {
        request_id: 1,
        ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
        prefix_len: 24,
    }]));
    let mut dec = CapsuleDecoder::new();
    dec.feed(&non_canon);
    assert!(matches!(dec.next_capsule(), Err(WireError::Malformed(_))));

    // Out-of-order ROUTE_ADVERTISEMENT is malformed
    let bad_routes = encode_capsule(&Capsule::RouteAdvertisement(vec![
        AddressRange {
            start: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 0)),
            end: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 255)),
            ip_protocol: 0,
        },
        AddressRange {
            start: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            end: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255)),
            ip_protocol: 0,
        },
    ]));
    let mut dec = CapsuleDecoder::new();
    dec.feed(&bad_routes);
    assert!(matches!(dec.next_capsule(), Err(WireError::Malformed(_))));
}

#[test]
fn udp_uri_template_matching() {
    let tpl = UdpUriTemplate::parse("/.well-known/masque/udp/{target_host}/{target_port}/").unwrap();

    assert_eq!(
        tpl.match_path("/.well-known/masque/udp/192.0.2.1/443/").unwrap(),
        Some(TargetHostPort {
            host: "192.0.2.1".into(),
            port: 443,
        })
    );
    assert_eq!(
        tpl.match_path("/.well-known/masque/udp/dns.example.com/53/").unwrap(),
        Some(TargetHostPort {
            host: "dns.example.com".into(),
            port: 53,
        })
    );
    assert_eq!(
        tpl.match_path("/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/").unwrap(),
        Some(TargetHostPort {
            host: "2001:db8::1".into(),
            port: 443,
        })
    );
    assert_eq!(
        tpl.match_path("/.well-known/masque/udp/%5B%3A%3A1%5D/443/").unwrap(),
        Some(TargetHostPort {
            host: "::1".into(),
            port: 443,
        })
    );

    // Path structure mismatches -> Ok(None) (404)
    assert_eq!(tpl.match_path("/other/192.0.2.1/443/").unwrap(), None);
    assert_eq!(tpl.match_path("/.well-known/masque/udp/192.0.2.1/").unwrap(), None);
    assert_eq!(tpl.match_path("/.well-known/masque/udp/192.0.2.1/443").unwrap(), None);

    // Invalid captured variable -> Err (400)
    assert!(tpl.match_path("/.well-known/masque/udp/192.0.2.1/0/").is_err());
    assert!(tpl.match_path("/.well-known/masque/udp/192.0.2.1/99999/").is_err());
    assert!(tpl.match_path("/.well-known/masque/udp/192.0.2.1/abc/").is_err());
    assert!(tpl.match_path("/.well-known/masque/udp//443/").is_err());
    assert!(tpl.match_path("/.well-known/masque/udp/bad%ZZhost/443/").is_err());

    // Invalid templates rejected at parse
    assert!(UdpUriTemplate::parse("/.well-known/masque/udp/{target_host}/").is_err());
    assert!(UdpUriTemplate::parse("https://example.com/{target_host}/{target_port}/").is_err());
}

#[test]
fn ip_uri_template_matching() {
    let tpl = IpUriTemplate::parse("/.well-known/masque/ip/{target}/{ipproto}/").unwrap();

    assert_eq!(
        tpl.match_path("/.well-known/masque/ip/*/*/").unwrap(),
        Some(IpTunnelTarget {
            target: None,
            ipproto: None,
        })
    );
    assert_eq!(
        tpl.match_path("/.well-known/masque/ip/%2A/%2a/").unwrap(),
        Some(IpTunnelTarget {
            target: None,
            ipproto: None,
        })
    );
    assert_eq!(
        tpl.match_path("/.well-known/masque/ip/192.0.2.0%2F24/6/").unwrap(),
        Some(IpTunnelTarget {
            target: Some("192.0.2.0/24".into()),
            ipproto: Some(6),
        })
    );
    assert_eq!(
        tpl.match_path("/.well-known/masque/ip/2001%3Adb8%3A%3A%2F32/*/").unwrap(),
        Some(IpTunnelTarget {
            target: Some("2001:db8::/32".into()),
            ipproto: None,
        })
    );

    // Query expansion template
    let qt = IpUriTemplate::parse("/vpn{?target,ipproto}").unwrap();
    assert_eq!(
        qt.match_path("/vpn").unwrap(),
        Some(IpTunnelTarget {
            target: None,
            ipproto: None,
        })
    );
    assert_eq!(
        qt.match_path("/vpn?ipproto=17").unwrap(),
        Some(IpTunnelTarget {
            target: None,
            ipproto: Some(17),
        })
    );

    // Path structure mismatches -> Ok(None) (404)
    assert_eq!(tpl.match_path("/other/").unwrap(), None);
    assert_eq!(tpl.match_path("/.well-known/masque/ip/*/").unwrap(), None);

    // Invalid variables -> Err (400)
    assert!(tpl.match_path("/.well-known/masque/ip/192.0.2.1%2F24/*/").is_err());
    assert!(tpl.match_path("/.well-known/masque/ip/192.0.2.0%2F33/*/").is_err());
    assert!(tpl.match_path("/.well-known/masque/ip/2001:db8::/*/").is_err());
    assert!(tpl.match_path("/.well-known/masque/ip/*/256/").is_err());
    assert!(tpl.match_path("/.well-known/masque/ip/*/tcp/").is_err());

    // Invalid template rejected at parse
    assert!(IpUriTemplate::parse("/vpn/{target}/{target}").is_err());
    assert!(IpUriTemplate::parse("/vpn/{other}").is_err());
}

#[test]
fn ip_packet_inspect_decrement_and_icmp() {
    let src4 = Ipv4Addr::new(10, 10, 0, 2);
    let dst4 = Ipv4Addr::new(1, 1, 1, 1);
    let router4 = Ipv4Addr::new(10, 10, 0, 1);
    let mut pkt4 = make_v4_udp(src4, dst4, 64, b"ping");

    let meta4 = inspect_ip_packet(&pkt4).unwrap();
    assert_eq!(
        meta4,
        IpPacketMeta {
            version: 4,
            src: IpAddr::V4(src4),
            dst: IpAddr::V4(dst4),
            proto: 17,
            ttl: 64,
        }
    );

    assert!(decrement_hop_limit(&mut pkt4));
    assert_eq!(inspect_ip_packet(&pkt4).unwrap().ttl, 63);
    assert_eq!(internet_checksum(&pkt4[..20]), 0);

    // TTL=1 must not decrement/forward
    let mut pkt4_ttl1 = make_v4_udp(src4, dst4, 1, b"ping");
    assert!(!decrement_hop_limit(&mut pkt4_ttl1));

    let icmp4 = build_icmp_error(
        &pkt4_ttl1,
        IcmpErrorKind::PacketTooBig(1280),
        Some(router4),
        None,
    )
    .unwrap();
    let icmp4_meta = inspect_ip_packet(&icmp4).unwrap();
    assert_eq!(icmp4_meta.version, 4);
    assert_eq!(icmp4_meta.src, IpAddr::V4(router4));
    assert_eq!(icmp4_meta.dst, IpAddr::V4(src4));
    assert_eq!(icmp4_meta.proto, 1);
    assert_eq!(internet_checksum(&icmp4[..20]), 0);
    assert_eq!(internet_checksum(&icmp4[20..]), 0);
    assert_eq!(icmp4[20], 3); // Dest Unreachable
    assert_eq!(icmp4[21], 4); // Frag needed
    assert_eq!(u16::from_be_bytes([icmp4[26], icmp4[27]]), 1280);

    // IPv6 inspection, hop limit decrement, and ICMPv6 PTB
    let src6: Ipv6Addr = "fd00:10::2".parse().unwrap();
    let dst6: Ipv6Addr = "2001:4860:4860::8888".parse().unwrap();
    let router6: Ipv6Addr = "fd00:10::1".parse().unwrap();
    let mut pkt6 = make_v6_udp(src6, dst6, 64, b"ping6");

    let meta6 = inspect_ip_packet(&pkt6).unwrap();
    assert_eq!(
        meta6,
        IpPacketMeta {
            version: 6,
            src: IpAddr::V6(src6),
            dst: IpAddr::V6(dst6),
            proto: 17,
            ttl: 64,
        }
    );

    assert!(decrement_hop_limit(&mut pkt6));
    assert_eq!(inspect_ip_packet(&pkt6).unwrap().ttl, 63);

    let mut pkt6_hl1 = make_v6_udp(src6, dst6, 1, b"ping6");
    assert!(!decrement_hop_limit(&mut pkt6_hl1));

    let icmp6 = build_icmp_error(
        &pkt6_hl1,
        IcmpErrorKind::HopLimitExceeded,
        None,
        Some(router6),
    )
    .unwrap();
    let icmp6_meta = inspect_ip_packet(&icmp6).unwrap();
    assert_eq!(icmp6_meta.version, 6);
    assert_eq!(icmp6_meta.src, IpAddr::V6(router6));
    assert_eq!(icmp6_meta.dst, IpAddr::V6(src6));
    assert_eq!(icmp6_meta.proto, 58);
    assert_eq!(icmp6[40], 3); // Time Exceeded
    assert_eq!(icmp6[41], 0); // Hop limit exceeded
    assert_eq!(icmpv6_checksum(router6, src6, &icmp6[40..]), 0);

    // Missing router addr for family -> None
    assert!(build_icmp_error(&pkt6_hl1, IcmpErrorKind::NoRoute, Some(router4), None).is_none());
    assert!(inspect_ip_packet(&[]).is_none());
    assert!(inspect_ip_packet(&[0x35; 20]).is_none());

    // Remaining ICMPv4/ICMPv6 error kinds + ICMP-over-ICMP suppression
    for (kind, exp_t4, exp_c4, exp_t6, exp_c6) in [
        (IcmpErrorKind::NoRoute, 3, 0, 1, 0),
        (IcmpErrorKind::SourcePolicy, 3, 13, 1, 1),
        (IcmpErrorKind::AddressUnreachable, 3, 1, 1, 3),
        (IcmpErrorKind::HopLimitExceeded, 11, 0, 3, 0),
        (IcmpErrorKind::PacketTooBig(1400), 3, 4, 2, 0),
    ] {
        let e4 = build_icmp_error(&pkt4_ttl1, kind, Some(router4), None).unwrap();
        assert_eq!((e4[20], e4[21]), (exp_t4, exp_c4));
        assert_eq!(internet_checksum(&e4[20..]), 0);
        assert!(build_icmp_error(&e4, IcmpErrorKind::NoRoute, Some(router4), None).is_none());

        let e6 = build_icmp_error(&pkt6_hl1, kind, None, Some(router6)).unwrap();
        assert_eq!((e6[40], e6[41]), (exp_t6, exp_c6));
        assert_eq!(icmpv6_checksum(router6, src6, &e6[40..]), 0);
        assert!(build_icmp_error(&e6, IcmpErrorKind::NoRoute, None, Some(router6)).is_none());
    }
}
