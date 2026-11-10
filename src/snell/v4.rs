//! Snell v4 AEAD frame codec.
//!
//! Wraps an `AsyncRead + AsyncWrite` stream with Snell v4 framing:
//! 1. First write emits 16-byte random salt, then frames; reader consumes 16-byte salt first.
//! 2. Each frame is `[AEAD-sealed 7-byte header][padding][AEAD-sealed payload]`.
//! 3. Plaintext header: `[ver=4][0][0][padding_len: u16 BE][payload_len: u16 BE]`.
//! 4. Nonce: 12-byte little-endian counter incremented after every Seal/Open.
//! 5. Zero-chunk half-close: `payload_len == 0 && padding_len == 0`.
//! 6. Interleaving: `swap_padding` swaps even bytes between padding and payload ciphertext.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Instant;

use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, BufReader, ReadBuf};

use super::aead::{snell_kdf, Aead};
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncShutdownMessage,
    AsyncStream, AsyncWriteMessage,
};

pub const V4_SALT_SIZE: usize = 16;
pub const V4_NONCE_SIZE: usize = 12;
pub const V4_HEADER_PLAIN_SIZE: usize = 7;
pub const V4_GCM_TAG: usize = 16;
pub const V4_HEADER_CIPHER_SIZE: usize = V4_HEADER_PLAIN_SIZE + V4_GCM_TAG;

const V4_FRAME_SIZE: usize = 1460;
const V4_INITIAL_PADDING_MIN: u16 = 0x100;
const V4_INITIAL_PADDING_SPAN: u16 = 0x100;
const V4_BURST_RESET_AFTER: std::time::Duration = std::time::Duration::from_secs(30);

/// Largest snell frame payload — matches mihomo's `maxLength` (0x3FFF).
pub const MAX_PAYLOAD_LENGTH: usize = 0x3FFF;

const V4_READ_BUFFER_SIZE: usize = 64 * 1024;

pub fn increment_nonce(nonce: &mut [u8; V4_NONCE_SIZE]) {
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            return;
        }
    }
}

pub fn swap_padding(padding: &mut [u8], payload_cipher: &mut [u8]) {
    let limit = padding.len().min(payload_cipher.len());
    let mut i = 0;
    while i < limit {
        std::mem::swap(&mut padding[i], &mut payload_cipher[i]);
        i += 2;
    }
}

fn make_v4_bit_count_padding(length: usize, one_bits: usize) -> io::Result<Vec<u8>> {
    let total_bits = 8 * length;
    if one_bits > total_bits {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "snell v4 invalid padding bit count",
        ));
    }
    let mut bitset = vec![0u8; total_bits];
    for slot in bitset.iter_mut().take(one_bits) {
        *slot = 1;
    }
    let mut rng = rand::rng();
    for i in (1..total_bits).rev() {
        let j = (rng.next_u64() % (i as u64 + 1)) as usize;
        bitset.swap(i, j);
    }
    let mut padding = vec![0u8; length];
    for (i, bit) in bitset.into_iter().enumerate() {
        if bit == 1 {
            padding[i / 8] |= 1 << (i % 8);
        }
    }
    Ok(padding)
}

fn make_v4_random_padding(length: usize) -> Vec<u8> {
    let mut padding = vec![0u8; length];
    rand::rng().fill_bytes(&mut padding);
    padding
}

fn count_v4_payload_ones(payload_cipher: &[u8]) -> usize {
    let limit = payload_cipher.len() & !3;
    payload_cipher[..limit]
        .iter()
        .map(|b| b.count_ones() as usize)
        .sum()
}

fn random_unit_f64() -> f64 {
    (rand::rng().next_u64() % (1u64 << 53)) as f64 / 2f64.powi(53)
}

fn make_v4_padding(payload_cipher: &[u8], padding_length: usize) -> io::Result<Vec<u8>> {
    if padding_length == 0 {
        return Ok(Vec::new());
    }
    let payload_ones = count_v4_payload_ones(payload_cipher);
    let payload_zeros = 8 * payload_cipher.len() - payload_ones;
    let target_base = match payload_zeros.cmp(&payload_ones) {
        std::cmp::Ordering::Greater => 0.9,
        std::cmp::Ordering::Equal => 0.95,
        std::cmp::Ordering::Less => 1.0,
    };
    let target_ratio = target_base + random_unit_f64() / 10.0;
    let total_bits = 8 * (padding_length + payload_cipher.len());
    let target_ones_f =
        total_bits as f64 * (target_ratio / (target_ratio + 1.0)) - payload_ones as f64;
    if !target_ones_f.is_finite() || target_ones_f < 0.0 {
        return Ok(make_v4_random_padding(padding_length));
    }
    let target_ones = target_ones_f as usize;
    if target_ones > 8 * padding_length {
        return Ok(make_v4_random_padding(padding_length));
    }
    make_v4_bit_count_padding(padding_length, target_ones)
}

// ─── Reader state machine ────────────────────────────────────────────────────

enum ReaderState {
    NeedSalt {
        salt_buf: [u8; V4_SALT_SIZE],
        salt_progress: usize,
    },
    ReadingHeader {
        aead: Arc<Aead>,
        nonce: [u8; V4_NONCE_SIZE],
        header_buf: [u8; V4_HEADER_CIPHER_SIZE],
        header_progress: usize,
    },
    ReadingBody {
        aead: Arc<Aead>,
        nonce: [u8; V4_NONCE_SIZE],
        padding_len: usize,
        payload_len: usize,
        body_buf: Vec<u8>,
        body_progress: usize,
    },
    Drain {
        aead: Arc<Aead>,
        nonce: [u8; V4_NONCE_SIZE],
        payload: Vec<u8>,
        payload_off: usize,
    },
}

// ─── Writer state ────────────────────────────────────────────────────────────

struct Writer {
    aead: Arc<Aead>,
    nonce: [u8; V4_NONCE_SIZE],
    salt: [u8; V4_SALT_SIZE],
    salt_sent: bool,
    initial_padding_length: u16,
    payload_limit: u16,
    last_write: Option<Instant>,
    pending: Vec<u8>,
    pending_off: usize,
    pending_input: usize,
}

impl Writer {
    fn new(psk: &[u8]) -> Self {
        let mut salt = [0u8; V4_SALT_SIZE];
        rand::rng().fill_bytes(&mut salt);
        let aead = Aead::aes_128_gcm(&snell_kdf(psk, &salt, 16));
        let padding_delta = (rand::rng().next_u32() % u32::from(V4_INITIAL_PADDING_SPAN)) as u16;
        Self {
            aead: Arc::new(aead),
            nonce: [0u8; V4_NONCE_SIZE],
            salt,
            salt_sent: false,
            initial_padding_length: V4_INITIAL_PADDING_MIN + padding_delta,
            payload_limit: 0,
            last_write: None,
            pending: Vec::new(),
            pending_off: 0,
            pending_input: 0,
        }
    }

    fn next_payload_limit(&mut self) -> u16 {
        let now = Instant::now();
        let limit = match self.last_write {
            None => V4_FRAME_SIZE as u16 - 55 - self.initial_padding_length,
            Some(t) if now.duration_since(t) > V4_BURST_RESET_AFTER => V4_FRAME_SIZE as u16 - 39,
            Some(_) => self.payload_limit,
        };
        self.last_write = Some(now);
        if limit < MAX_PAYLOAD_LENGTH as u16 {
            let next = limit as usize + V4_FRAME_SIZE - 39;
            self.payload_limit = next.min(MAX_PAYLOAD_LENGTH) as u16;
        } else {
            self.payload_limit = MAX_PAYLOAD_LENGTH as u16;
        }
        limit
    }

    fn next_frame_padding_length(&self, payload_length: usize) -> usize {
        if self.salt_sent || payload_length == 0 {
            0
        } else {
            self.initial_padding_length as usize
        }
    }

    fn stage_frame(&mut self, payload: &[u8], padding_length: usize) -> io::Result<()> {
        if payload.len() > MAX_PAYLOAD_LENGTH || padding_length > MAX_PAYLOAD_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell v4 frame too large",
            ));
        }
        if payload.is_empty() && padding_length != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell v4 zero chunk with padding",
            ));
        }

        let mut header = [0u8; V4_HEADER_PLAIN_SIZE];
        header[0] = 4;
        header[3..5].copy_from_slice(&(padding_length as u16).to_be_bytes());
        header[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());

        let mut header_buf: Vec<u8> = Vec::with_capacity(V4_HEADER_CIPHER_SIZE);
        header_buf.extend_from_slice(&header);
        seal_in_place(&self.aead, &self.nonce, &mut header_buf)?;
        increment_nonce(&mut self.nonce);

        let mut payload_buf: Vec<u8> = Vec::new();
        if !payload.is_empty() {
            payload_buf.extend_from_slice(payload);
            seal_in_place(&self.aead, &self.nonce, &mut payload_buf)?;
            increment_nonce(&mut self.nonce);
        }

        let mut padding = if padding_length > 0 {
            make_v4_padding(&payload_buf, padding_length)?
        } else {
            Vec::new()
        };
        if padding_length > 0 {
            swap_padding(&mut padding, &mut payload_buf);
        }

        let mut frame: Vec<u8> = Vec::with_capacity(
            if self.salt_sent { 0 } else { V4_SALT_SIZE }
                + header_buf.len()
                + padding.len()
                + payload_buf.len(),
        );
        if !self.salt_sent {
            frame.extend_from_slice(&self.salt);
            self.salt_sent = true;
        }
        frame.extend_from_slice(&header_buf);
        frame.extend_from_slice(&padding);
        frame.extend_from_slice(&payload_buf);

        self.pending = frame;
        self.pending_off = 0;
        Ok(())
    }
}

fn seal_in_place(aead: &Aead, nonce: &[u8; V4_NONCE_SIZE], buf: &mut Vec<u8>) -> io::Result<()> {
    aead.seal_append(nonce, &[], buf)
        .map_err(|_| io::Error::other("snell v4 encrypt failed"))
}

fn open_in_place(aead: &Aead, nonce: &[u8; V4_NONCE_SIZE], buf: &mut Vec<u8>) -> io::Result<()> {
    aead.open_trailing(nonce, &[], buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "snell v4 decrypt failed"))
}

// ─── V4Conn ──────────────────────────────────────────────────────────────────

pub struct V4Conn<S> {
    inner: BufReader<S>,
    psk: Arc<[u8]>,
    writer: Writer,
    reader: ReaderState,
}

impl<S: AsyncRead> V4Conn<S> {
    pub fn new(inner: S, psk: Arc<[u8]>) -> Self {
        let writer = Writer::new(&psk);
        Self {
            inner: BufReader::with_capacity(V4_READ_BUFFER_SIZE, inner),
            psk,
            writer,
            reader: ReaderState::NeedSalt {
                salt_buf: [0u8; V4_SALT_SIZE],
                salt_progress: 0,
            },
        }
    }
}

impl<S> V4Conn<S> {
    pub fn stage_packet_frame(&mut self, buf: &[u8]) -> io::Result<()> {
        if buf.len() > MAX_PAYLOAD_LENGTH {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell v4 packet frame too large",
            ));
        }
        let padding_length = self.writer.next_frame_padding_length(buf.len());
        self.writer.pending_input = buf.len();
        self.writer.stage_frame(buf, padding_length)
    }

    #[allow(dead_code)]
    pub fn has_pending_write(&self) -> bool {
        self.writer.pending_off < self.writer.pending.len()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for V4Conn<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        loop {
            match &mut this.reader {
                ReaderState::NeedSalt {
                    salt_buf,
                    salt_progress,
                } => {
                    let mut tmp = [0u8; V4_SALT_SIZE];
                    let need = V4_SALT_SIZE - *salt_progress;
                    let mut rb = ReadBuf::new(&mut tmp[..need]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {}
                    }
                    let n = rb.filled().len();
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "snell v4 EOF before salt",
                        )));
                    }
                    salt_buf[*salt_progress..*salt_progress + n].copy_from_slice(&tmp[..n]);
                    *salt_progress += n;
                    if *salt_progress < V4_SALT_SIZE {
                        continue;
                    }
                    let aead =
                        Arc::new(Aead::aes_128_gcm(&snell_kdf(&this.psk, &salt_buf[..], 16)));
                    this.reader = ReaderState::ReadingHeader {
                        aead,
                        nonce: [0u8; V4_NONCE_SIZE],
                        header_buf: [0u8; V4_HEADER_CIPHER_SIZE],
                        header_progress: 0,
                    };
                }
                ReaderState::Drain {
                    aead,
                    nonce,
                    payload,
                    payload_off,
                } => {
                    let avail = &payload[*payload_off..];
                    if avail.is_empty() {
                        let aead = Arc::clone(aead);
                        let nonce = *nonce;
                        this.reader = ReaderState::ReadingHeader {
                            aead,
                            nonce,
                            header_buf: [0u8; V4_HEADER_CIPHER_SIZE],
                            header_progress: 0,
                        };
                        continue;
                    }
                    let take = avail.len().min(out.remaining());
                    out.put_slice(&avail[..take]);
                    *payload_off += take;
                    return Poll::Ready(Ok(()));
                }
                ReaderState::ReadingHeader {
                    aead,
                    nonce,
                    header_buf,
                    header_progress,
                } => {
                    let need = V4_HEADER_CIPHER_SIZE - *header_progress;
                    let mut tmp = [0u8; V4_HEADER_CIPHER_SIZE];
                    let mut rb = ReadBuf::new(&mut tmp[..need]);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Ready(Ok(())) => {}
                    }
                    let n = rb.filled().len();
                    if n == 0 {
                        if *header_progress == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "snell v4 EOF mid-header",
                        )));
                    }
                    header_buf[*header_progress..*header_progress + n].copy_from_slice(&tmp[..n]);
                    *header_progress += n;
                    if *header_progress < V4_HEADER_CIPHER_SIZE {
                        continue;
                    }
                    let mut sealed = header_buf.to_vec();
                    if let Err(e) = open_in_place(aead, nonce, &mut sealed) {
                        return Poll::Ready(Err(e));
                    }
                    increment_nonce(nonce);
                    if sealed.len() != V4_HEADER_PLAIN_SIZE || sealed[0] != 4 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "snell v4 invalid frame header",
                        )));
                    }
                    let padding_len = u16::from_be_bytes([sealed[3], sealed[4]]) as usize;
                    let payload_len = u16::from_be_bytes([sealed[5], sealed[6]]) as usize;
                    if payload_len == 0 {
                        if padding_len != 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "snell v4 zero chunk with padding",
                            )));
                        }
                        let aead_keep = Arc::clone(aead);
                        let nonce_keep = *nonce;
                        this.reader = ReaderState::ReadingHeader {
                            aead: aead_keep,
                            nonce: nonce_keep,
                            header_buf: [0u8; V4_HEADER_CIPHER_SIZE],
                            header_progress: 0,
                        };
                        // A zero chunk ends the session: report clean EOF, as meow-rs does.
                        return Poll::Ready(Ok(()));
                    }
                    if payload_len > MAX_PAYLOAD_LENGTH || padding_len > MAX_PAYLOAD_LENGTH {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "snell v4 frame too large",
                        )));
                    }
                    let body_size = padding_len + payload_len + V4_GCM_TAG;
                    let aead = Arc::clone(aead);
                    let nonce = *nonce;
                    this.reader = ReaderState::ReadingBody {
                        aead,
                        nonce,
                        padding_len,
                        payload_len,
                        body_buf: vec![0u8; body_size],
                        body_progress: 0,
                    };
                }
                ReaderState::ReadingBody {
                    aead,
                    nonce,
                    padding_len,
                    payload_len,
                    body_buf,
                    body_progress,
                } => {
                    if *body_progress < body_buf.len() {
                        let mut rb = ReadBuf::new(&mut body_buf[*body_progress..]);
                        match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                            Poll::Pending => return Poll::Pending,
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Ready(Ok(())) => {}
                        }
                        let n = rb.filled().len();
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "snell v4 EOF mid-body",
                            )));
                        }
                        *body_progress += n;
                        if *body_progress < body_buf.len() {
                            continue;
                        }
                    }
                    let (padding_part, payload_part) = body_buf.split_at_mut(*padding_len);
                    if *padding_len > 0 {
                        swap_padding(padding_part, payload_part);
                    }
                    let mut payload_cipher = payload_part.to_vec();
                    if let Err(e) = open_in_place(aead, nonce, &mut payload_cipher) {
                        return Poll::Ready(Err(e));
                    }
                    increment_nonce(nonce);
                    debug_assert_eq!(payload_cipher.len(), *payload_len);
                    let aead = Arc::clone(aead);
                    let nonce = *nonce;
                    this.reader = ReaderState::Drain {
                        aead,
                        nonce,
                        payload: payload_cipher,
                        payload_off: 0,
                    };
                }
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for V4Conn<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        if this.writer.pending_off < this.writer.pending.len() {
            match drain_writer(&mut this.writer, &mut this.inner, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let consumed = std::mem::take(&mut this.writer.pending_input);
                    return Poll::Ready(Ok(consumed));
                }
            }
        }

        // A flush may have sent the staged frame; report its count once.
        if this.writer.pending_input > 0 {
            return Poll::Ready(Ok(std::mem::take(&mut this.writer.pending_input)));
        }

        if buf.is_empty() {
            this.writer.pending_input = 0;
            this.writer.stage_frame(&[], 0)?;
            match drain_writer(&mut this.writer, &mut this.inner, cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => Poll::Ready(Ok(0)),
            }
        } else {
            let limit = this.writer.next_payload_limit() as usize;
            let limit = if limit == 0 || limit > MAX_PAYLOAD_LENGTH {
                MAX_PAYLOAD_LENGTH
            } else {
                limit
            };
            let take = buf.len().min(limit);
            let chunk = &buf[..take];
            let padding_length = this.writer.next_frame_padding_length(chunk.len());
            this.writer.pending_input = take;
            this.writer.stage_frame(chunk, padding_length)?;
            match drain_writer(&mut this.writer, &mut this.inner, cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {
                    let consumed = std::mem::take(&mut this.writer.pending_input);
                    Poll::Ready(Ok(consumed))
                }
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.writer.pending_off < this.writer.pending.len() {
            match drain_writer(&mut this.writer, &mut this.inner, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.writer.pending_off < this.writer.pending.len() {
            match drain_writer(&mut this.writer, &mut this.inner, cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(())) => {}
            }
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

fn drain_writer<S: AsyncWrite + Unpin>(
    writer: &mut Writer,
    inner: &mut S,
    cx: &mut Context<'_>,
) -> Poll<io::Result<()>> {
    while writer.pending_off < writer.pending.len() {
        let slice = &writer.pending[writer.pending_off..];
        match Pin::new(&mut *inner).poll_write(cx, slice) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(0)) => {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "snell v4: short write",
                )));
            }
            Poll::Ready(Ok(n)) => writer.pending_off += n,
        }
    }
    writer.pending.clear();
    writer.pending_off = 0;
    Poll::Ready(Ok(()))
}

impl<S> AsyncPing for V4Conn<S> {
    fn supports_ping(&self) -> bool {
        false
    }
    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl<S: AsyncStream> AsyncStream for V4Conn<S> {
    fn local_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.get_ref().local_addr()
    }
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.inner.get_ref().peer_addr()
    }
    fn flow(&self) -> Option<&std::sync::Arc<crate::control::flows::FlowEntry>> {
        self.inner.get_ref().flow()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadMessage for V4Conn<S> {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncWriteMessage for V4Conn<S> {
    fn poll_write_message(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.writer.pending_off < this.writer.pending.len() {
            ready!(drain_writer(&mut this.writer, &mut this.inner, cx))?;
        }
        // A retry after Pending: this packet is already staged (and maybe sent by a flush).
        if std::mem::take(&mut this.writer.pending_input) > 0 {
            return Poll::Ready(Ok(()));
        }
        this.stage_packet_frame(buf)?;
        ready!(drain_writer(&mut this.writer, &mut this.inner, cx))?;
        this.writer.pending_input = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncFlushMessage for V4Conn<S> {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncShutdownMessage for V4Conn<S> {
    fn poll_shutdown_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> AsyncMessageStream for V4Conn<S> {}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn increment_nonce_wraps() {
        let mut n = [0xFFu8; V4_NONCE_SIZE];
        increment_nonce(&mut n);
        assert_eq!(n, [0u8; V4_NONCE_SIZE]);
    }

    #[test]
    fn swap_padding_round_trips() {
        let mut p = vec![1u8, 2, 3, 4, 5, 6];
        let mut c = vec![10u8, 20, 30, 40, 50, 60];
        let (orig_p, orig_c) = (p.clone(), c.clone());
        swap_padding(&mut p, &mut c);
        swap_padding(&mut p, &mut c);
        assert_eq!(p, orig_p);
        assert_eq!(c, orig_c);
    }

    #[test]
    fn bit_count_padding_has_requested_ones() {
        let pad = make_v4_bit_count_padding(16, 40).unwrap();
        let ones: u32 = pad.iter().map(|b| b.count_ones()).sum();
        assert_eq!(ones, 40);
    }

    #[tokio::test]
    async fn v4_round_trip_through_duplex() {
        let (a, b) = tokio::io::duplex(1 << 18);
        let psk: Arc<[u8]> = Arc::from(b"shared-secret".as_slice());
        let mut alice = V4Conn::new(a, Arc::clone(&psk));
        let mut bob = V4Conn::new(b, psk);

        let small = b"hello-world";
        let large: Vec<u8> = (0..32_000u32).map(|i| (i % 251) as u8).collect();

        let writer = tokio::spawn(async move {
            alice.write_all(small).await.unwrap();
            alice.write_all(&large).await.unwrap();
            alice.flush().await.unwrap();
            alice
        });

        let mut got_small = vec![0u8; small.len()];
        bob.read_exact(&mut got_small).await.unwrap();
        assert_eq!(got_small, small);

        let mut got_large = vec![0u8; 32_000];
        bob.read_exact(&mut got_large).await.unwrap();
        let expected: Vec<u8> = (0..32_000u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(got_large, expected);

        drop(writer.await.unwrap());
    }

    #[tokio::test]
    async fn v4_zero_chunk_reads_as_eof() {
        let (a, b) = tokio::io::duplex(8192);
        let psk: Arc<[u8]> = Arc::from(b"k".as_slice());
        let mut alice = V4Conn::new(a, Arc::clone(&psk));
        let mut bob = V4Conn::new(b, psk);

        alice.write_all(b"abc").await.unwrap();
        alice.flush().await.unwrap();
        std::future::poll_fn(|cx| Pin::new(&mut alice).poll_write(cx, &[]))
            .await
            .unwrap();
        alice.flush().await.unwrap();

        let mut buf = [0u8; 3];
        bob.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"abc");

        let mut more = [0u8; 1];
        assert_eq!(bob.read(&mut more).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn v4_poll_write_after_flush_does_not_resend_staged_frame() {
        let (a, b) = tokio::io::duplex(64);
        let psk: Arc<[u8]> = Arc::from(b"shared-psk".as_slice());
        let mut writer = V4Conn::new(a, Arc::clone(&psk));
        let mut reader = V4Conn::new(b, psk);

        let buf: Vec<u8> = (0..4000u32).map(|i| (i % 251) as u8).collect();

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(&waker);
        let poll_res = Pin::new(&mut writer).poll_write(&mut cx, &buf);
        assert!(poll_res.is_pending());

        let staged_input = writer.writer.pending_input;
        assert!(staged_input > 0);

        let reader_task = tokio::spawn(async move {
            let mut received = Vec::new();
            reader.read_to_end(&mut received).await.unwrap();
            received
        });

        writer.flush().await.unwrap();

        let Poll::Ready(Ok(n)) = Pin::new(&mut writer).poll_write(&mut cx, &buf) else {
            panic!("expected Ready(Ok(n)) from follow-up poll_write");
        };
        assert_eq!(n, staged_input);

        writer.write_all(&buf[n..]).await.unwrap();
        writer.shutdown().await.unwrap();

        let received = reader_task.await.unwrap();
        assert_eq!(received.len(), buf.len());
        assert_eq!(received, buf);
    }

    #[tokio::test]
    async fn v4_poll_write_message_retry_after_flush_sends_packet_once() {
        let (a, b) = tokio::io::duplex(64);
        let psk: Arc<[u8]> = Arc::from(b"shared-psk".as_slice());
        let mut writer = V4Conn::new(a, Arc::clone(&psk));
        let mut reader = V4Conn::new(b, psk);
        let packet: Vec<u8> = (0..4000u32).map(|i| (i % 251) as u8).collect();

        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(&waker);
        assert!(Pin::new(&mut writer)
            .poll_write_message(&mut cx, &packet)
            .is_pending());

        let reader_task = tokio::spawn(async move {
            let mut packets = Vec::new();
            loop {
                let mut data = vec![0u8; 8192];
                let mut read_buf = ReadBuf::new(&mut data);
                std::future::poll_fn(|cx| Pin::new(&mut reader).poll_read_message(cx, &mut read_buf))
                    .await
                    .unwrap();
                if read_buf.filled().is_empty() {
                    return packets;
                }
                packets.push(read_buf.filled().to_vec());
            }
        });

        writer.flush().await.unwrap();
        assert!(matches!(
            Pin::new(&mut writer).poll_write_message(&mut cx, &packet),
            Poll::Ready(Ok(()))
        ));
        // The next stream write must not report a stale count.
        writer.write_all(b"tail").await.unwrap();
        writer.shutdown().await.unwrap();

        assert_eq!(reader_task.await.unwrap(), vec![packet, b"tail".to_vec()]);
    }
}
