use std::fmt;
use std::io;
use std::net::IpAddr;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use bytes::Bytes;
use parking_lot::{Mutex, RwLock};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::address::NetLocation;
use crate::client_proxy_selector::ClientProxySelector;
use crate::config::MasqueServerConfig;
use crate::config::tun::TunResourceLimits;
use crate::ip_stack::driver::PacketStack;
use crate::ip_stack::packet::PacketBuffer;
use crate::ip_stack::wake::Wake;
use crate::masque::ip_pool::{
    AddressPool, IpSessionRegistry, networks_to_address_ranges, routes_contain,
};
use crate::masque::wire::{
    AddressRange, IcmpErrorKind, build_icmp_error, decrement_hop_limit, inspect_ip_packet,
};
use crate::resolver::Resolver;
use crate::tun::udp_handler::UdpHandler;
use crate::tun::udp_manager::TunUdpManager;

const SESSION_OUTBOUND_QUEUE: usize = 256;

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
    peer_routes: RwLock<Vec<AddressRange>>,
    tx: mpsc::Sender<Bytes>,
    rx: Option<mpsc::Receiver<Bytes>>,
    pool: Arc<AddressPool>,
    registry: Arc<IpSessionRegistry>,
}

impl MasqueIpSessionLease {
    pub fn session_id(&self) -> u64 {
        self.id
    }

    pub fn assigned_ips(&self) -> &[IpAddr] {
        &self.assigned_ips
    }

    pub fn advertised_routes(&self) -> &[AddressRange] {
        &self.advertised_routes
    }

    pub fn set_peer_routes(&self, routes: Vec<AddressRange>) {
        let mut guard = self.peer_routes.write();
        self.registry.set_peer_routes(self.id, routes.clone());
        *guard = routes;
    }

    pub fn peer_routes(&self) -> Vec<AddressRange> {
        self.peer_routes.read().clone()
    }

    pub fn tx(&self) -> &mpsc::Sender<Bytes> {
        &self.tx
    }

    pub fn take_receiver(&mut self) -> Option<mpsc::Receiver<Bytes>> {
        self.rx.take()
    }

    pub async fn recv(&mut self) -> Option<Bytes> {
        self.rx.as_mut()?.recv().await
    }

    pub fn try_recv(&mut self) -> Result<Bytes, mpsc::error::TryRecvError> {
        match self.rx.as_mut() {
            Some(rx) => rx.try_recv(),
            None => Err(mpsc::error::TryRecvError::Disconnected),
        }
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
                        if let Some((_, sender_tx)) = registry_out.lookup(meta.src, meta.proto) {
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
                if let Some((_, target_tx)) = registry_out.lookup(meta.dst, meta.proto) {
                    let _ = target_tx.try_send(Bytes::copy_from_slice(raw_pkt));
                }
            }
        });

        Ok(Arc::new(Self {
            pool,
            registry,
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

    pub fn registry(&self) -> &Arc<IpSessionRegistry> {
        &self.registry
    }

    pub fn default_advertised_routes(&self) -> &[AddressRange] {
        &self.default_advertised_routes
    }

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
            peer_routes: RwLock::new(Vec::new()),
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

        // 2. Enforce source IP policy against assigned IPs and peer advertised routes.
        let src_allowed = lease.assigned_ips.contains(&meta.src)
            || routes_contain(&lease.peer_routes.read(), meta.src, meta.proto);
        if !src_allowed {
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
        if let Some((target_id, target_tx)) = self.registry.lookup(meta.dst, meta.proto) {
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
