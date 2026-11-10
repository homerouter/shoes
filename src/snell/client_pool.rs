use std::fmt::Debug;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWrite};
use tokio::time::Instant;

use crate::async_stream::AsyncStream;
use crate::snell::snell_handler::SnellFramedStream;
use crate::tcp::carrier_dialer::{CarrierDialer, RouteKey};

pub const POOL_SIZE: usize = 10;
pub const POOL_MAX_AGE: Duration = Duration::from_secs(180);
pub const POOL_SWEEP_INTERVAL: Duration = Duration::from_secs(20);
pub const WAITING_DISCARD_LIMIT: usize = 0x80001;

pub struct SnellClientPool {
    inner: Arc<Mutex<PoolState>>,
}

struct IdleEntry {
    stream: SnellFramedStream<Box<dyn AsyncStream>>,
    idle_since: Instant,
    route: Arc<dyn CarrierDialer>,
}

#[derive(Default)]
struct PoolState {
    entries: Vec<IdleEntry>,
    closed: bool,
    reaper: Option<tokio::task::AbortHandle>,
}

impl Debug for SnellClientPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnellClientPool")
            .field("size", &self.inner.lock().entries.len())
            .finish()
    }
}

impl SnellClientPool {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(Mutex::new(PoolState::default())),
        })
    }

    pub fn take(
        &self,
        route_key: &RouteKey,
    ) -> Option<(SnellFramedStream<Box<dyn AsyncStream>>, Arc<dyn CarrierDialer>)> {
        let mut state = self.inner.lock();
        if state.closed {
            return None;
        }
        let now = Instant::now();
        state
            .entries
            .retain(|e| now.duration_since(e.idle_since) <= POOL_MAX_AGE);
        if let Some(idx) = state
            .entries
            .iter()
            .position(|e| e.route.route_key() == route_key)
        {
            let entry = state.entries.remove(idx);
            return Some((entry.stream, entry.route));
        }
        None
    }

    pub fn put(
        &self,
        route: Arc<dyn CarrierDialer>,
        stream: SnellFramedStream<Box<dyn AsyncStream>>,
    ) {
        let mut state = self.inner.lock();
        if state.closed {
            return;
        }
        let now = Instant::now();
        state
            .entries
            .retain(|e| now.duration_since(e.idle_since) <= POOL_MAX_AGE);
        if state.entries.len() >= POOL_SIZE {
            return;
        }
        state.entries.push(IdleEntry {
            stream,
            idle_since: now,
            route,
        });
        if state.reaper.is_none() {
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                let pool_weak = Arc::downgrade(&self.inner);
                let handle = rt.spawn(async move {
                    let mut interval = tokio::time::interval(POOL_SWEEP_INTERVAL);
                    loop {
                        interval.tick().await;
                        let Some(pool_inner) = pool_weak.upgrade() else {
                            break;
                        };
                        let mut st = pool_inner.lock();
                        if st.closed {
                            break;
                        }
                        let now = Instant::now();
                        st.entries
                            .retain(|e| now.duration_since(e.idle_since) <= POOL_MAX_AGE);
                        if st.entries.is_empty() {
                            st.reaper = None;
                            break;
                        }
                    }
                });
                state.reaper = Some(handle.abort_handle());
            }
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().entries.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn close(&self) {
        let mut state = self.inner.lock();
        state.closed = true;
        state.entries.clear();
        if let Some(h) = state.reaper.take() {
            h.abort();
        }
    }
}

impl Drop for SnellClientPool {
    fn drop(&mut self) {
        self.close();
    }
}

pub async fn write_zero_chunk(
    stream: &mut SnellFramedStream<Box<dyn AsyncStream>>,
) -> io::Result<()> {
    futures::future::poll_fn(|cx| std::pin::Pin::new(&mut *stream).poll_write(cx, &[])).await?;
    futures::future::poll_fn(|cx| std::pin::Pin::new(&mut *stream).poll_flush(cx)).await
}

pub async fn drain_server(
    stream: &mut SnellFramedStream<Box<dyn AsyncStream>>,
) -> io::Result<()> {
    let mut total_drained = 0;
    let mut buf = [0u8; 4096];
    loop {
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }
        total_drained += n;
        if total_drained >= WAITING_DISCARD_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "snell: read too much data after request end",
            ));
        }
    }
}

