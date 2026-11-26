use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::Bytes;
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use parking_lot::Mutex;
use tokio::sync::mpsc;

use crate::masque::wire::AddressRange;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[derive(Debug)]
struct V4Pool {
    gateway: u32,
    start: u32,
    end: u32,
    next: Option<u32>,
    free: VecDeque<u32>,
    allocated: HashSet<u32>,
}

impl V4Pool {
    fn new(net: Ipv4Network) -> io::Result<Self> {
        if net.prefix() > 30 {
            return Err(invalid(
                "IPv4 tunnel prefix must be /30 or shorter to provide usable client addresses",
            ));
        }
        let network = u32::from(net.network());
        let broadcast = u32::from(net.broadcast());
        let gateway = u32::from(net.ip());
        let start = network.saturating_add(1);
        let end = broadcast.saturating_sub(1);
        let pool = Self {
            gateway,
            start,
            end,
            next: (start <= end).then_some(start),
            free: VecDeque::new(),
            allocated: HashSet::new(),
        };
        if !pool.can_allocate() {
            return Err(invalid(
                "IPv4 tunnel prefix has no usable client addresses after reserving network, broadcast, and gateway",
            ));
        }
        Ok(pool)
    }

    fn peek_next_cursor(&self) -> Option<u32> {
        let mut cur = self.next?;
        while cur <= self.end {
            if cur != self.gateway && !self.allocated.contains(&cur) {
                return Some(cur);
            }
            if cur == self.end {
                break;
            }
            cur += 1;
        }
        None
    }

    fn can_allocate(&self) -> bool {
        !self.free.is_empty() || self.peek_next_cursor().is_some()
    }

    fn allocate_one(&mut self) -> Option<Ipv4Addr> {
        while let Some(addr) = self.free.pop_front() {
            if addr != self.gateway
                && addr >= self.start
                && addr <= self.end
                && self.allocated.insert(addr)
            {
                return Some(Ipv4Addr::from(addr));
            }
        }
        while let Some(cur) = self.next {
            self.next = if cur < self.end { Some(cur + 1) } else { None };
            if cur != self.gateway && self.allocated.insert(cur) {
                return Some(Ipv4Addr::from(cur));
            }
        }
        None
    }

    fn release_one(&mut self, addr: Ipv4Addr) {
        let raw = u32::from(addr);
        if self.allocated.remove(&raw) {
            self.free.push_back(raw);
        }
    }
}

#[derive(Debug)]
struct V6Pool {
    gateway: u128,
    start: u128,
    end: u128,
    next: Option<u128>,
    free: VecDeque<u128>,
    allocated: HashSet<u128>,
}

impl V6Pool {
    fn new(net: Ipv6Network) -> io::Result<Self> {
        if net.ip().to_canonical() != net.ip() {
            return Err(invalid("IPv6 tunnel prefix must not be IPv4-mapped"));
        }
        if net.prefix() > 126 {
            return Err(invalid(
                "IPv6 tunnel prefix must be /126 or shorter to provide usable client addresses",
            ));
        }
        let network = u128::from(net.network());
        let host_mask = if net.prefix() == 0 {
            u128::MAX
        } else {
            u128::MAX >> net.prefix()
        };
        let last = network | host_mask;
        let gateway = u128::from(net.ip());
        let start = network.saturating_add(1);
        let pool = Self {
            gateway,
            start,
            end: last,
            next: (start <= last).then_some(start),
            free: VecDeque::new(),
            allocated: HashSet::new(),
        };
        if !pool.can_allocate() {
            return Err(invalid(
                "IPv6 tunnel prefix has no usable client addresses after reserving network and gateway",
            ));
        }
        Ok(pool)
    }

    fn peek_next_cursor(&self) -> Option<u128> {
        let mut cur = self.next?;
        while cur <= self.end {
            if cur != self.gateway && !self.allocated.contains(&cur) {
                return Some(cur);
            }
            if cur == self.end {
                break;
            }
            cur += 1;
        }
        None
    }

    fn can_allocate(&self) -> bool {
        !self.free.is_empty() || self.peek_next_cursor().is_some()
    }

    fn allocate_one(&mut self) -> Option<Ipv6Addr> {
        while let Some(addr) = self.free.pop_front() {
            if addr != self.gateway
                && addr >= self.start
                && addr <= self.end
                && self.allocated.insert(addr)
            {
                return Some(Ipv6Addr::from(addr));
            }
        }
        while let Some(cur) = self.next {
            self.next = if cur < self.end { Some(cur + 1) } else { None };
            if cur != self.gateway && self.allocated.insert(cur) {
                return Some(Ipv6Addr::from(cur));
            }
        }
        None
    }

    fn release_one(&mut self, addr: Ipv6Addr) {
        let raw = u128::from(addr);
        if self.allocated.remove(&raw) {
            self.free.push_back(raw);
        }
    }
}

#[derive(Debug)]
struct PoolState {
    v4: Option<V4Pool>,
    v6: Option<V6Pool>,
}

/// Thread-safe per-family IP address pool for `CONNECT-IP` sessions.
#[derive(Debug)]
pub struct AddressPool {
    prefixes: Vec<IpNetwork>,
    server_addrs: Vec<IpAddr>,
    server_v4: Option<Ipv4Addr>,
    server_v6: Option<Ipv6Addr>,
    state: Mutex<PoolState>,
}

impl AddressPool {
    pub fn new(prefixes: &[IpNetwork]) -> io::Result<Self> {
        if prefixes.is_empty() {
            return Err(invalid("at least one tunnel prefix is required"));
        }

        let mut v4_pool = None;
        let mut v6_pool = None;
        let mut server_addrs = Vec::with_capacity(prefixes.len());
        let mut server_v4 = None;
        let mut server_v6 = None;

        for &prefix in prefixes {
            match prefix {
                IpNetwork::V4(v4) => {
                    if v4_pool.is_some() {
                        return Err(invalid("at most one IPv4 tunnel prefix is supported"));
                    }
                    v4_pool = Some(V4Pool::new(v4)?);
                    server_v4 = Some(v4.ip());
                    server_addrs.push(IpAddr::V4(v4.ip()));
                }
                IpNetwork::V6(v6) => {
                    if v6_pool.is_some() {
                        return Err(invalid("at most one IPv6 tunnel prefix is supported"));
                    }
                    v6_pool = Some(V6Pool::new(v6)?);
                    server_v6 = Some(v6.ip());
                    server_addrs.push(IpAddr::V6(v6.ip()));
                }
            }
        }

        Ok(Self {
            prefixes: prefixes.to_vec(),
            server_addrs,
            server_v4,
            server_v6,
            state: Mutex::new(PoolState {
                v4: v4_pool,
                v6: v6_pool,
            }),
        })
    }

    #[cfg(test)]
    pub fn prefixes(&self) -> &[IpNetwork] {
        &self.prefixes
    }

    pub fn server_addresses(&self) -> Vec<IpAddr> {
        self.server_addrs.clone()
    }

    pub fn server_v4(&self) -> Option<Ipv4Addr> {
        self.server_v4
    }

    pub fn server_v6(&self) -> Option<Ipv6Addr> {
        self.server_v6
    }

    pub fn is_server_address(&self, addr: IpAddr) -> bool {
        self.server_addrs.contains(&addr)
    }

    pub fn contains_prefix(&self, addr: IpAddr) -> bool {
        ip_in_networks(addr, &self.prefixes)
    }

    /// Allocate one address from each configured family pool atomically.
    ///
    /// Returns `None` without leaking partial allocations if any configured pool is exhausted.
    pub fn allocate(&self) -> Option<Vec<IpAddr>> {
        let mut state = self.state.lock();
        if let Some(v4) = &state.v4
            && !v4.can_allocate()
        {
            return None;
        }
        if let Some(v6) = &state.v6
            && !v6.can_allocate()
        {
            return None;
        }

        let mut allocated = Vec::with_capacity(self.prefixes.len());
        for prefix in &self.prefixes {
            match prefix {
                IpNetwork::V4(_) => {
                    let ip = state
                        .v4
                        .as_mut()
                        .and_then(V4Pool::allocate_one)
                        .expect("v4 availability checked under lock");
                    allocated.push(IpAddr::V4(ip));
                }
                IpNetwork::V6(_) => {
                    let ip = state
                        .v6
                        .as_mut()
                        .and_then(V6Pool::allocate_one)
                        .expect("v6 availability checked under lock");
                    allocated.push(IpAddr::V6(ip));
                }
            }
        }
        Some(allocated)
    }

    pub fn release(&self, addrs: &[IpAddr]) {
        let mut state = self.state.lock();
        for &addr in addrs {
            match addr {
                IpAddr::V4(v4) => {
                    if let Some(pool) = &mut state.v4 {
                        pool.release_one(v4);
                    }
                }
                IpAddr::V6(v6) => {
                    if let Some(pool) = &mut state.v6 {
                        pool.release_one(v6);
                    }
                }
            }
        }
    }
}

/// Ordered set of RFC 9484 `AddressRange` route entries.
#[cfg(test)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpRangeSet(Vec<AddressRange>);

#[cfg(test)]
impl IpRangeSet {
    pub fn new(ranges: Vec<AddressRange>) -> Self {
        Self(ranges)
    }

    pub fn from_networks(networks: &[IpNetwork]) -> Self {
        Self(networks_to_address_ranges(networks))
    }

    pub fn contains(&self, addr: IpAddr, proto: u8) -> bool {
        routes_contain(&self.0, addr, proto)
    }

    pub fn as_slice(&self) -> &[AddressRange] {
        &self.0
    }
}

pub fn ip_in_networks(addr: IpAddr, networks: &[IpNetwork]) -> bool {
    networks.iter().any(|net| net.contains(addr))
}

pub fn routes_contain(routes: &[AddressRange], addr: IpAddr, proto: u8) -> bool {
    routes.iter().any(|range| {
        if range.ip_protocol != 0 && range.ip_protocol != proto {
            return false;
        }
        match (range.start, range.end, addr) {
            (IpAddr::V4(start), IpAddr::V4(end), IpAddr::V4(ip)) => start <= ip && ip <= end,
            (IpAddr::V6(start), IpAddr::V6(end), IpAddr::V6(ip)) => start <= ip && ip <= end,
            _ => false,
        }
    })
}

#[cfg(test)]
pub fn networks_to_address_ranges(networks: &[IpNetwork]) -> Vec<AddressRange> {
    networks
        .iter()
        .map(|&net| match net {
            IpNetwork::V4(v4) => AddressRange {
                start: IpAddr::V4(v4.network()),
                end: IpAddr::V4(v4.broadcast()),
                ip_protocol: 0,
            },
            IpNetwork::V6(v6) => {
                let network = u128::from(v6.network());
                let host_mask = u128::MAX.checked_shr(u32::from(v6.prefix())).unwrap_or(0);
                AddressRange {
                    start: IpAddr::V6(v6.network()),
                    end: IpAddr::V6(Ipv6Addr::from(network | host_mask)),
                    ip_protocol: 0,
                }
            }
        })
        .collect()
}

/// Routes outbound IP packets back to active `CONNECT-IP` sessions by assigned IP.
#[derive(Debug, Default)]
struct RegistryState {
    by_ip: HashMap<IpAddr, (u64, mpsc::Sender<Bytes>)>,
    sessions: HashMap<u64, Vec<IpAddr>>,
}

#[derive(Debug, Default)]
pub struct IpSessionRegistry {
    state: Mutex<RegistryState>,
}

impl IpSessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, session_id: u64, assigned: Vec<IpAddr>, tx: mpsc::Sender<Bytes>) {
        let mut state = self.state.lock();
        if let Some(prev_assigned) = state.sessions.remove(&session_id) {
            for ip in prev_assigned {
                if state
                    .by_ip
                    .get(&ip)
                    .is_some_and(|(id, _)| *id == session_id)
                {
                    state.by_ip.remove(&ip);
                }
            }
        }

        for &ip in &assigned {
            state.by_ip.insert(ip, (session_id, tx.clone()));
        }
        state.sessions.insert(session_id, assigned);
    }

    pub fn unregister(&self, session_id: u64) {
        let mut state = self.state.lock();
        if let Some(assigned) = state.sessions.remove(&session_id) {
            for ip in assigned {
                if state
                    .by_ip
                    .get(&ip)
                    .is_some_and(|(id, _)| *id == session_id)
                {
                    state.by_ip.remove(&ip);
                }
            }
        }
    }

    pub fn lookup(&self, dst: IpAddr) -> Option<(u64, mpsc::Sender<Bytes>)> {
        self.state
            .lock()
            .by_ip
            .get(&dst)
            .map(|(session_id, tx)| (*session_id, tx.clone()))
    }
}
