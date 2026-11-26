use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::{Request, Response, StatusCode};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::address::{Address, NetLocation};
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::MasqueServerConfig;
use crate::config::tun::TunResourceLimits;
use crate::ip_stack::driver::PacketStack;
use crate::ip_stack::packet::PacketBuffer;
use crate::ip_stack::wake::Wake;
use crate::masque::h3_server::H3DatagramHub;
use crate::masque::ip_pool::{AddressPool, IpSessionRegistry, routes_contain};
#[cfg(test)]
use crate::masque::ip_pool::networks_to_address_ranges;
use crate::masque::wire::{
    AddressRange, AssignedAddress, Capsule, CapsuleDecoder, IcmpErrorKind, build_icmp_error,
    decode_context0_datagram, decrement_hop_limit, encode_capsule, encode_context0_datagram,
    inspect_ip_packet,
};
use crate::masque::{
    MasqueConnCtx, capsule_ok_response, feed_capsule_buf, feed_h2_capsule_chunk, send_h2_data,
    send_h3_datagram_or_capsule, status_response,
};
use crate::resolver::Resolver;
use crate::tun::udp_handler::UdpHandler;
use crate::tun::udp_manager::TunUdpManager;

const SESSION_OUTBOUND_QUEUE: usize = 256;
const IP_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

fn is_link_local_or_multicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_link_local() || v4.is_multicast(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80 || v6.is_multicast(),
    }
}

/// RAII lease representing a single active `CONNECT-IP` session.
///
/// Dropping the lease deterministically unregisters its routes and returns all
/// allocated tunnel IP addresses to `AddressPool`.
pub struct MasqueIpSessionLease {
    id: u64,
    assigned_ips: Vec<IpAddr>,
    advertised_routes: Vec<AddressRange>,
    tx: mpsc::Sender<Bytes>,
    rx: Option<mpsc::Receiver<Bytes>>,
    pool: Arc<AddressPool>,
    registry: Arc<IpSessionRegistry>,
}

impl MasqueIpSessionLease {
    #[cfg(test)]
    pub fn session_id(&self) -> u64 {
        self.id
    }

    pub fn assigned_ips(&self) -> &[IpAddr] {
        &self.assigned_ips
    }

    pub fn advertised_routes(&self) -> &[AddressRange] {
        &self.advertised_routes
    }

    #[cfg(test)]
    pub fn tx(&self) -> &mpsc::Sender<Bytes> {
        &self.tx
    }

    pub fn take_receiver(&mut self) -> Option<mpsc::Receiver<Bytes>> {
        self.rx.take()
    }

    #[cfg(test)]
    pub async fn recv(&mut self) -> Option<Bytes> {
        self.rx.as_mut()?.recv().await
    }
}

impl Drop for MasqueIpSessionLease {
    fn drop(&mut self) {
        self.registry.unregister(self.id);
        self.pool.release(&self.assigned_ips);
    }
}

/// Shared `CONNECT-IP` L3 router backed by a single `PacketStack` (`smoltcp`) instance.
pub struct MasqueIpEngine {
    pool: Arc<AddressPool>,
    registry: Arc<IpSessionRegistry>,
    #[cfg(test)]
    default_advertised_routes: Vec<AddressRange>,
    mtu: u16,
    next_session_id: AtomicU64,
    stack_input: mpsc::Sender<PacketBuffer>,
    wake: Wake,
    tasks: Mutex<JoinSet<()>>,
    stack: Mutex<Option<PacketStack>>,
}

impl fmt::Debug for MasqueIpEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MasqueIpEngine")
            .field("server_addresses", &self.pool.server_addresses())
            .field("mtu", &self.mtu)
            .finish_non_exhaustive()
    }
}

impl Drop for MasqueIpEngine {
    fn drop(&mut self) {
        self.tasks.get_mut().abort_all();
        self.stack.get_mut().take();
    }
}

impl MasqueIpEngine {
    pub fn new(
        config: &MasqueServerConfig,
        selector: Arc<ClientProxySelector>,
        resolver: Arc<dyn Resolver>,
    ) -> io::Result<Arc<Self>> {
        let pool = Arc::new(AddressPool::new(&config.tunnel_addresses)?);
        let registry = Arc::new(IpSessionRegistry::new());
        #[cfg(test)]
        let default_advertised_routes =
            networks_to_address_ranges(&config.effective_advertise_routes());
        let limits = TunResourceLimits::default();
        let mut stack = PacketStack::new(
            pool.server_addresses(),
            config.mtu,
            true,
            limits.clone(),
        )?;

        let stack_input = stack.input.clone();
        let wake = stack.handle.wake.clone();
        let mut tasks = JoinSet::new();

        // 1. Spawn UDP forwarding through TunUdpManager.
        let udp = stack.udp.take().expect("PacketStack udp receiver");
        let (reader, writer) =
            UdpHandler::new(udp, stack.replies.clone(), wake.clone()).split();
        let manager = TunUdpManager::new(
            reader,
            writer,
            selector.clone(),
            resolver.clone(),
            limits,
        );
        crate::network_tasks::spawn_in(&mut tasks, async move {
            if let Err(error) = manager.run().await {
                log::warn!("MASQUE CONNECT-IP UDP forwarding stopped: {error}");
            }
        });

        // 2. Spawn TCP accept loop calling handle_tcp_connection.
        let mut tcp = stack.tcp.take().expect("PacketStack tcp receiver");
        crate::network_tasks::spawn_in(&mut tasks, async move {
            let mut flows = JoinSet::new();
            loop {
                let connection = tokio::select! {
                    connection = tcp.recv() => match connection {
                        Some(connection) => connection,
                        None => break,
                    },
                    _ = flows.join_next(), if !flows.is_empty() => continue,
                };
                let selector = selector.clone();
                let resolver = resolver.clone();
                crate::network_tasks::spawn_in(&mut flows, async move {
                    log::debug!(
                        "MASQUE CONNECT-IP TCP {} -> {}",
                        connection.source,
                        connection.target
                    );
                    let target = NetLocation::from_ip_addr(
                        connection.target.ip(),
                        connection.target.port(),
                    );
                    let _ = crate::tun::handle_tcp_connection(
                        connection.connection,
                        target,
                        selector,
                        resolver,
                        Some(connection.source),
                    )
                    .await;
                });
            }
        });

        // 3. Spawn stack.output demux loop routing outbound IP packets back to sessions.
        let mut output = stack.output.take().expect("PacketStack output receiver");
        let registry_out = registry.clone();
        let pool_out = pool.clone();
        let stack_input_out = stack_input.clone();
        let wake_out = wake.clone();
        let mtu = config.mtu;
        crate::network_tasks::spawn_in(&mut tasks, async move {
            while let Some(packet) = output.recv().await {
                let raw_pkt: &[u8] = &packet;
                let Some(meta) = inspect_ip_packet(raw_pkt) else {
                    continue;
                };
                if raw_pkt.len() > mtu as usize {
                    if let Some(icmp) = build_icmp_error(
                        raw_pkt,
                        IcmpErrorKind::PacketTooBig(mtu),
                        pool_out.server_v4(),
                        pool_out.server_v6(),
                    ) {
                        if let Some((_, sender_tx)) = registry_out.lookup(meta.src) {
                            let _ = sender_tx.try_send(icmp);
                        } else if stack_input_out
                            .try_send(PacketBuffer::copy_from_slice(&icmp))
                            .is_ok()
                        {
                            wake_out.notify();
                        }
                    }
                    continue;
                }
                if let Some((_, target_tx)) = registry_out.lookup(meta.dst) {
                    let _ = target_tx.try_send(Bytes::copy_from_slice(raw_pkt));
                }
            }
        });

        Ok(Arc::new(Self {
            pool,
            registry,
            #[cfg(test)]
            default_advertised_routes,
            mtu: config.mtu,
            next_session_id: AtomicU64::new(1),
            stack_input,
            wake,
            tasks: Mutex::new(tasks),
            stack: Mutex::new(Some(stack)),
        }))
    }

    pub fn pool(&self) -> &Arc<AddressPool> {
        &self.pool
    }

    #[cfg(test)]
    pub fn registry(&self) -> &Arc<IpSessionRegistry> {
        &self.registry
    }

    #[cfg(test)]
    pub fn default_advertised_routes(&self) -> &[AddressRange] {
        &self.default_advertised_routes
    }

    #[cfg(test)]
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    pub fn open_session(
        self: &Arc<Self>,
        advertised_routes: Vec<AddressRange>,
    ) -> io::Result<MasqueIpSessionLease> {
        let assigned_ips = self.pool.allocate().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "MASQUE CONNECT-IP address pool exhausted",
            )
        })?;
        let id = self.next_session_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = mpsc::channel(SESSION_OUTBOUND_QUEUE);
        self.registry.register(id, assigned_ips.clone(), tx.clone());
        Ok(MasqueIpSessionLease {
            id,
            assigned_ips,
            advertised_routes,
            tx,
            rx: Some(rx),
            pool: self.pool.clone(),
            registry: self.registry.clone(),
        })
    }

    fn send_icmp_to_lease(
        &self,
        lease: &MasqueIpSessionLease,
        raw_pkt: &[u8],
        kind: IcmpErrorKind,
    ) {
        if let Some(icmp) = build_icmp_error(
            raw_pkt,
            kind,
            self.pool.server_v4(),
            self.pool.server_v6(),
        ) {
            let _ = lease.tx.try_send(icmp);
        }
    }

    pub async fn handle_inbound_packet(&self, lease: &MasqueIpSessionLease, raw_pkt: &[u8]) {
        // 1. Parse packet header; drop invalid packets silently.
        let Some(meta) = inspect_ip_packet(raw_pkt) else {
            return;
        };

        // 2. Enforce source IP policy strictly against server-assigned IPs.
        if !lease.assigned_ips.contains(&meta.src) {
            self.send_icmp_to_lease(lease, raw_pkt, IcmpErrorKind::SourcePolicy);
            return;
        }

        // 3. Drop link-local / multicast destinations silently.
        if is_link_local_or_multicast(meta.dst) {
            return;
        }

        // 4. Enforce destination IP + protocol against advertised routes.
        if !routes_contain(&lease.advertised_routes, meta.dst, meta.proto) {
            self.send_icmp_to_lease(lease, raw_pkt, IcmpErrorKind::NoRoute);
            return;
        }

        // 5. Route to peer session, reject unassigned tunnel prefix, or enter PacketStack.
        if let Some((target_id, target_tx)) = self.registry.lookup(meta.dst) {
            if target_id == lease.id {
                return;
            }
            if raw_pkt.len() > self.mtu as usize {
                self.send_icmp_to_lease(lease, raw_pkt, IcmpErrorKind::PacketTooBig(self.mtu));
                return;
            }
            let mut fwd = raw_pkt.to_vec();
            if !decrement_hop_limit(&mut fwd) {
                self.send_icmp_to_lease(lease, raw_pkt, IcmpErrorKind::HopLimitExceeded);
                return;
            }
            let _ = target_tx.try_send(Bytes::from(fwd));
            return;
        }

        if self.pool.contains_prefix(meta.dst) && !self.pool.is_server_address(meta.dst) {
            self.send_icmp_to_lease(lease, raw_pkt, IcmpErrorKind::AddressUnreachable);
            return;
        }

        if raw_pkt.len() > self.mtu as usize {
            self.send_icmp_to_lease(lease, raw_pkt, IcmpErrorKind::PacketTooBig(self.mtu));
            return;
        }

        let pkt = PacketBuffer::copy_from_slice(raw_pkt);
        match self.stack_input.try_send(pkt) {
            Ok(()) => self.wake.notify(),
            Err(mpsc::error::TrySendError::Full(pkt)) => {
                self.wake.notify();
                let _ = self.stack_input.send(pkt).await;
                self.wake.notify();
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }
}

enum ConnectIpPrep {
    Ready {
        engine: Arc<MasqueIpEngine>,
        lease: MasqueIpSessionLease,
    },
    Reject(Response<()>),
}

fn dns_error_response() -> Response<()> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("proxy-status", "shoes; error=dns_error")
        .body(())
        .expect("valid dns error response")
}

fn v4_interval(net: Ipv4Network) -> (u32, u32) {
    let start = u32::from(net.network());
    let host_mask = u32::MAX.checked_shr(u32::from(net.prefix())).unwrap_or(0);
    (start, start | host_mask)
}

fn v6_interval(net: Ipv6Network) -> (u128, u128) {
    let start = u128::from(net.network());
    let host_mask = u128::MAX.checked_shr(u32::from(net.prefix())).unwrap_or(0);
    (start, start | host_mask)
}

fn coalesce_intervals<T: Ord + Copy>(
    mut intervals: Vec<(T, T)>,
    saturating_next: impl Fn(T) -> T,
) -> Vec<(T, T)> {
    if intervals.is_empty() {
        return intervals;
    }
    intervals.sort_unstable();
    let mut merged: Vec<(T, T)> = Vec::with_capacity(intervals.len());
    for (start, end) in intervals {
        if let Some(last) = merged.last_mut()
            && start <= saturating_next(last.1)
        {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    merged
}

fn compute_advertised_routes(
    base: &[IpNetwork],
    target: Option<&[IpNetwork]>,
    ip_protocol: u8,
) -> Vec<AddressRange> {
    let mut base_v4 = Vec::new();
    let mut base_v6 = Vec::new();
    for &net in base {
        match net {
            IpNetwork::V4(v4) => base_v4.push(v4_interval(v4)),
            IpNetwork::V6(v6) => base_v6.push(v6_interval(v6)),
        }
    }

    let (v4_intervals, v6_intervals) = match target {
        None => (
            coalesce_intervals(base_v4, |x| x.saturating_add(1)),
            coalesce_intervals(base_v6, |x| x.saturating_add(1)),
        ),
        Some(target_nets) => {
            let mut iv4 = Vec::new();
            let mut iv6 = Vec::new();
            for &tnet in target_nets {
                match tnet {
                    IpNetwork::V4(tv4) => {
                        let (ts, te) = v4_interval(tv4);
                        for &(bs, be) in &base_v4 {
                            let s = bs.max(ts);
                            let e = be.min(te);
                            if s <= e {
                                iv4.push((s, e));
                            }
                        }
                    }
                    IpNetwork::V6(tv6) => {
                        let (ts, te) = v6_interval(tv6);
                        for &(bs, be) in &base_v6 {
                            let s = bs.max(ts);
                            let e = be.min(te);
                            if s <= e {
                                iv6.push((s, e));
                            }
                        }
                    }
                }
            }
            (
                coalesce_intervals(iv4, |x| x.saturating_add(1)),
                coalesce_intervals(iv6, |x| x.saturating_add(1)),
            )
        }
    };

    let mut out = Vec::with_capacity(v4_intervals.len() + v6_intervals.len());
    for (start, end) in v4_intervals {
        out.push(AddressRange {
            start: IpAddr::V4(Ipv4Addr::from(start)),
            end: IpAddr::V4(Ipv4Addr::from(end)),
            ip_protocol,
        });
    }
    for (start, end) in v6_intervals {
        out.push(AddressRange {
            start: IpAddr::V6(Ipv6Addr::from(start)),
            end: IpAddr::V6(Ipv6Addr::from(end)),
            ip_protocol,
        });
    }
    out
}

async fn prepare_connect_ip(ctx: &MasqueConnCtx, request: &Request<()>) -> ConnectIpPrep {
    let Some(engine) = ctx
        .ip_engine
        .as_ref()
        .filter(|_| ctx.config.ip_enabled)
        .cloned()
    else {
        let status = if ctx.config.stealth_404 {
            StatusCode::NOT_FOUND
        } else {
            StatusCode::FORBIDDEN
        };
        return ConnectIpPrep::Reject(status_response(status));
    };

    let raw_path = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path(), |pq| pq.as_str());
    let parsed = match ctx.ip_template.match_path(raw_path) {
        Ok(Some(target)) => target,
        Ok(None) => return ConnectIpPrep::Reject(status_response(StatusCode::NOT_FOUND)),
        Err(_) => return ConnectIpPrep::Reject(status_response(StatusCode::BAD_REQUEST)),
    };

    let has_v4 = engine.pool().server_v4().is_some();
    let has_v6 = engine.pool().server_v6().is_some();
    let base_networks: Vec<IpNetwork> = ctx
        .config
        .effective_advertise_routes()
        .into_iter()
        .filter(|net| match net {
            IpNetwork::V4(_) => has_v4,
            IpNetwork::V6(_) => has_v6,
        })
        .collect();

    let target_networks = match parsed.target {
        None => None,
        Some(target_str) => {
            if let Ok(ip) = target_str.parse::<IpAddr>() {
                Some(vec![IpNetwork::from(ip.to_canonical())])
            } else if let Ok(net) = target_str.parse::<IpNetwork>() {
                Some(vec![net])
            } else {
                let loc = NetLocation::new(Address::Hostname(target_str), 0);
                match crate::util::timeout_stream_setup(ctx.resolver.resolve_location(&loc)).await {
                    Ok(addrs) if !addrs.is_empty() => Some(
                        addrs
                            .into_iter()
                            .map(|sa| IpNetwork::from(sa.ip().to_canonical()))
                            .collect(),
                    ),
                    _ => return ConnectIpPrep::Reject(dns_error_response()),
                }
            }
        }
    };

    let ip_protocol = parsed.ipproto.unwrap_or(0);
    let advertised_routes =
        compute_advertised_routes(&base_networks, target_networks.as_deref(), ip_protocol);
    if advertised_routes.is_empty() {
        return ConnectIpPrep::Reject(status_response(StatusCode::FORBIDDEN));
    }

    match engine.open_session(advertised_routes) {
        Ok(lease) => ConnectIpPrep::Ready { engine, lease },
        Err(_) => ConnectIpPrep::Reject(status_response(StatusCode::SERVICE_UNAVAILABLE)),
    }
}

fn initial_assigned_addresses(lease: &MasqueIpSessionLease) -> Vec<AssignedAddress> {
    lease
        .assigned_ips()
        .iter()
        .map(|&ip| AssignedAddress {
            request_id: 0,
            ip,
            prefix_len: match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            },
        })
        .collect()
}

fn initial_capsules_bytes(lease: &MasqueIpSessionLease) -> Bytes {
    let assign = encode_capsule(&Capsule::AddressAssign(initial_assigned_addresses(lease)));
    let routes = encode_capsule(&Capsule::RouteAdvertisement(
        lease.advertised_routes().to_vec(),
    ));
    let mut out = BytesMut::with_capacity(assign.len() + routes.len());
    out.extend_from_slice(&assign);
    out.extend_from_slice(&routes);
    out.freeze()
}

fn answer_address_request(
    lease: &MasqueIpSessionLease,
    reqs: &[AssignedAddress],
) -> Vec<AssignedAddress> {
    let assigned_v4 = lease.assigned_ips().iter().find_map(|ip| match ip {
        IpAddr::V4(v4) => Some(*v4),
        IpAddr::V6(_) => None,
    });
    let assigned_v6 = lease.assigned_ips().iter().find_map(|ip| match ip {
        IpAddr::V6(v6) => Some(*v6),
        IpAddr::V4(_) => None,
    });
    let mut used_v4 = false;
    let mut used_v6 = false;
    let mut out = Vec::with_capacity(reqs.len() + 2);

    for req in reqs {
        match req.ip {
            IpAddr::V4(_) => {
                let ip = if !used_v4 && let Some(v4) = assigned_v4 {
                    used_v4 = true;
                    v4
                } else {
                    Ipv4Addr::UNSPECIFIED
                };
                out.push(AssignedAddress {
                    request_id: req.request_id,
                    ip: IpAddr::V4(ip),
                    prefix_len: 32,
                });
            }
            IpAddr::V6(_) => {
                let ip = if !used_v6 && let Some(v6) = assigned_v6 {
                    used_v6 = true;
                    v6
                } else {
                    Ipv6Addr::UNSPECIFIED
                };
                out.push(AssignedAddress {
                    request_id: req.request_id,
                    ip: IpAddr::V6(ip),
                    prefix_len: 128,
                });
            }
        }
    }

    if !used_v4 && let Some(v4) = assigned_v4 {
        out.push(AssignedAddress {
            request_id: 0,
            ip: IpAddr::V4(v4),
            prefix_len: 32,
        });
    }
    if !used_v6 && let Some(v6) = assigned_v6 {
        out.push(AssignedAddress {
            request_id: 0,
            ip: IpAddr::V6(v6),
            prefix_len: 128,
        });
    }
    out
}

async fn drain_ip_capsules(
    decoder: &mut CapsuleDecoder,
    engine: &MasqueIpEngine,
    lease: &MasqueIpSessionLease,
) -> io::Result<Option<Bytes>> {
    let mut replies = BytesMut::new();
    while let Some(capsule) = decoder.next_capsule()? {
        match capsule {
            Capsule::Datagram(payload) => {
                if let Some(pkt) = decode_context0_datagram(payload)? {
                    engine.handle_inbound_packet(lease, &pkt).await;
                }
            }
            Capsule::AddressRequest(reqs) => {
                let assign = encode_capsule(&Capsule::AddressAssign(answer_address_request(
                    lease, &reqs,
                )));
                replies.extend_from_slice(&assign);
            }
            Capsule::RouteAdvertisement(routes) => {
                // Fail closed: do not trust client-supplied routes without an authorized allowlist.
                log::debug!(
                    "ignoring client-supplied MASQUE CONNECT-IP ROUTE_ADVERTISEMENT ({} ranges)",
                    routes.len()
                );
            }
            Capsule::AddressAssign(_) | Capsule::Unknown { .. } => {}
        }
    }
    Ok((!replies.is_empty()).then(|| replies.freeze()))
}

pub(crate) async fn handle_connect_ip_h3(
    ctx: MasqueConnCtx,
    request: Request<()>,
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    hub: H3DatagramHub,
) -> io::Result<()> {
    let (engine, mut lease) = match prepare_connect_ip(&ctx, &request).await {
        ConnectIpPrep::Ready { engine, lease } => (engine, lease),
        ConnectIpPrep::Reject(resp) => {
            stream
                .send_response(resp)
                .await
                .map_err(io::Error::other)?;
            return stream.finish().await.map_err(io::Error::other);
        }
    };

    let stream_id = stream.id();
    let (_rx_guard, mut dgram_rx) = hub.register(stream_id);
    let mut dgram_sender = hub.acquire_sender(stream_id).await?;

    stream
        .send_response(capsule_ok_response())
        .await
        .map_err(io::Error::other)?;

    let (mut send_stream, mut recv_stream) = stream.split();
    send_stream
        .send_data(initial_capsules_bytes(&lease))
        .await
        .map_err(io::Error::other)?;

    let mut outbound_rx = lease
        .take_receiver()
        .expect("fresh CONNECT-IP lease must have outbound receiver");
    let mut decoder = CapsuleDecoder::new();
    let mut datagrams_unavailable = false;
    let idle_sleep = tokio::time::sleep(IP_IDLE_TIMEOUT);
    tokio::pin!(idle_sleep);

    loop {
        tokio::select! {
            () = &mut idle_sleep => {
                let _ = send_stream.finish().await;
                return Ok(());
            }
            maybe_dgram = dgram_rx.recv() => {
                let Some(pkt) = maybe_dgram else {
                    let _ = send_stream.finish().await;
                    return Ok(());
                };
                idle_sleep.as_mut().reset(Instant::now() + IP_IDLE_TIMEOUT);
                engine.handle_inbound_packet(&lease, &pkt).await;
            }
            recv_res = recv_stream.recv_data() => {
                match recv_res {
                    Ok(Some(mut chunk)) => {
                        idle_sleep.as_mut().reset(Instant::now() + IP_IDLE_TIMEOUT);
                        feed_capsule_buf(&mut decoder, &mut chunk);
                        if let Some(reply_bytes) = drain_ip_capsules(&mut decoder, &engine, &lease).await? {
                            send_stream
                                .send_data(reply_bytes)
                                .await
                                .map_err(io::Error::other)?;
                        }
                    }
                    Ok(None) => {
                        let _ = send_stream.finish().await;
                        return Ok(());
                    }
                    Err(err) => return Err(io::Error::other(err)),
                }
            }
            maybe_outbound = outbound_rx.recv() => {
                let Some(pkt) = maybe_outbound else {
                    let _ = send_stream.finish().await;
                    return Ok(());
                };
                idle_sleep.as_mut().reset(Instant::now() + IP_IDLE_TIMEOUT);
                let encoded = encode_context0_datagram(&pkt);
                send_h3_datagram_or_capsule(
                    &mut dgram_sender,
                    &mut send_stream,
                    &mut datagrams_unavailable,
                    encoded,
                    true,
                )
                .await?;
            }
        }
    }
}

pub(crate) async fn handle_connect_ip_h2(
    ctx: MasqueConnCtx,
    request: Request<()>,
    mut respond: h2::server::SendResponse<Bytes>,
    mut recv: h2::RecvStream,
) -> io::Result<()> {
    let (engine, mut lease) = match prepare_connect_ip(&ctx, &request).await {
        ConnectIpPrep::Ready { engine, lease } => (engine, lease),
        ConnectIpPrep::Reject(resp) => {
            return respond
                .send_response(resp, true)
                .map(|_| ())
                .map_err(io::Error::other);
        }
    };

    let mut send = respond
        .send_response(capsule_ok_response(), false)
        .map_err(io::Error::other)?;
    send_h2_data(&mut send, initial_capsules_bytes(&lease)).await?;

    let mut outbound_rx = lease
        .take_receiver()
        .expect("fresh CONNECT-IP lease must have outbound receiver");
    let mut decoder = CapsuleDecoder::new();
    let idle_sleep = tokio::time::sleep(IP_IDLE_TIMEOUT);
    tokio::pin!(idle_sleep);

    loop {
        tokio::select! {
            () = &mut idle_sleep => {
                let _ = send.send_data(Bytes::new(), true);
                return Ok(());
            }
            chunk_opt = recv.data() => {
                match chunk_opt {
                    Some(Ok(chunk)) => {
                        idle_sleep.as_mut().reset(Instant::now() + IP_IDLE_TIMEOUT);
                        feed_h2_capsule_chunk(&mut recv, &mut decoder, &chunk)?;
                        if let Some(reply_bytes) = drain_ip_capsules(&mut decoder, &engine, &lease).await? {
                            send_h2_data(&mut send, reply_bytes).await?;
                        }
                    }
                    Some(Err(err)) => return Err(io::Error::other(err)),
                    None => {
                        let _ = send.send_data(Bytes::new(), true);
                        return Ok(());
                    }
                }
            }
            maybe_outbound = outbound_rx.recv() => {
                let Some(pkt) = maybe_outbound else {
                    let _ = send.send_data(Bytes::new(), true);
                    return Ok(());
                };
                idle_sleep.as_mut().reset(Instant::now() + IP_IDLE_TIMEOUT);
                let frame = encode_capsule(&Capsule::Datagram(encode_context0_datagram(&pkt)));
                send_h2_data(&mut send, frame).await?;
            }
        }
    }
}
