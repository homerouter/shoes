use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::ReadBuf;

use crate::address::NetLocation;
use crate::async_stream::{
    AsyncFlushMessage, AsyncMessageStream, AsyncPing, AsyncReadMessage, AsyncReadTargetedMessage,
    AsyncShutdownMessage, AsyncStream, AsyncTargetedMessageStream, AsyncWriteMessage,
    AsyncWriteSourcedMessage,
};
use crate::slide_buffer::SlideBuffer;
use crate::uot::socks_addr::{parse_socks_packet_address, write_socks_packet_address};
use crate::util::allocate_vec;

/// Buffer capacity for Trojan UDP frames.
/// Max UDP datagram size (65535) + max SOCKS5 address header (259) + length (2) + CRLF (2) + headroom.
pub const TROJAN_UDP_BUFFER_SIZE: usize = 65535 + 263 + 762;

/// Parse a Trojan UDP packet frame from `data`.
/// Frame layout:
/// `ATYP | DST.ADDR | DST.PORT | LENGTH (u16 BE) | CRLF (0x0D, 0x0A) | PAYLOAD`
///
/// Returns `Ok(Some((location, payload_start, payload_len)))` if a complete frame is available.
/// Returns `Ok(None)` if more data is needed.
/// Returns `Err` if the frame is malformed (invalid ATYP, missing CRLF, etc.).
#[inline]
pub fn parse_trojan_packet_frame(
    data: &[u8],
) -> std::io::Result<Option<(NetLocation, usize, usize)>> {
    let (location, addr_len) = match parse_socks_packet_address(data)? {
        Some(res) => res,
        None => return Ok(None),
    };

    // Need at least address + length(2) + crlf(2)
    if data.len() < addr_len + 4 {
        return Ok(None);
    }

    let payload_len = u16::from_be_bytes([data[addr_len], data[addr_len + 1]]) as usize;
    if data[addr_len + 2] != 0x0d || data[addr_len + 3] != 0x0a {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "trojan udp: expected CRLF after length",
        ));
    }

    let payload_start = addr_len + 4;
    let total_len = payload_start + payload_len;

    if data.len() < total_len {
        return Ok(None);
    }

    Ok(Some((location, payload_start, payload_len)))
}

/// Write a Trojan UDP packet frame into `buf`.
/// Frame layout:
/// `ATYP | DST.ADDR | DST.PORT | LENGTH (u16 BE) | CRLF (0x0D, 0x0A) | PAYLOAD`
///
/// Returns the total number of bytes written into `buf`.
#[inline]
pub fn write_trojan_packet_frame(
    buf: &mut [u8],
    addr: &NetLocation,
    payload: &[u8],
) -> std::io::Result<usize> {
    if payload.len() > u16::MAX as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "trojan udp: packet payload exceeds u16::MAX",
        ));
    }

    let addr_len = write_socks_packet_address(buf, addr)?;
    let total_len = addr_len + 4 + payload.len();

    if buf.len() < total_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "trojan udp: write buffer too small",
        ));
    }

    let length_bytes = (payload.len() as u16).to_be_bytes();
    buf[addr_len..addr_len + 2].copy_from_slice(&length_bytes);
    buf[addr_len + 2] = 0x0d;
    buf[addr_len + 3] = 0x0a;
    buf[addr_len + 4..total_len].copy_from_slice(payload);

    Ok(total_len)
}

/// A multi-directional Trojan UDP stream over an underlying stream (e.g. TLS stream).
/// Reads packets containing target destinations and writes packets stamped with source addresses.
/// Implements `AsyncTargetedMessageStream`.
pub struct TrojanUdpStream<S> {
    stream: S,
    read_buf: SlideBuffer,
    write_buf: Box<[u8]>,
    write_buf_len: usize,
    write_buf_sent: usize,
    is_eof: bool,
}

impl<S: AsyncStream> TrojanUdpStream<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            read_buf: SlideBuffer::new(TROJAN_UDP_BUFFER_SIZE),
            write_buf: allocate_vec(TROJAN_UDP_BUFFER_SIZE).into_boxed_slice(),
            write_buf_len: 0,
            write_buf_sent: 0,
            is_eof: false,
        }
    }

    /// Feed any initial unparsed data read during handshake into the read buffer.
    pub fn feed_initial_data(&mut self, data: &[u8]) {
        if !data.is_empty() {
            let len = data.len().min(self.read_buf.remaining_capacity());
            debug_assert_eq!(len, data.len(), "initial data exceeds buffer capacity");
            self.read_buf.extend_from_slice(&data[..len]);
        }
    }
}

impl<S: AsyncStream> AsyncReadTargetedMessage for TrojanUdpStream<S> {
    fn poll_read_targeted_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<NetLocation>> {
        let this = self.get_mut();

        if this.is_eof && this.read_buf.len() == 0 {
            return Poll::Ready(Ok(NetLocation::UNSPECIFIED));
        }

        loop {
            match parse_trojan_packet_frame(this.read_buf.as_slice())? {
                Some((location, payload_start, payload_len)) => {
                    let data = this.read_buf.as_slice();
                    let payload = &data[payload_start..payload_start + payload_len];

                    let to_copy = payload_len.min(buf.remaining());
                    buf.put_slice(&payload[..to_copy]);

                    let total_consumed = payload_start + payload_len;
                    this.read_buf.consume(total_consumed);

                    return Poll::Ready(Ok(location));
                }
                None => {
                    if this.is_eof {
                        if this.read_buf.len() == 0 {
                            return Poll::Ready(Ok(NetLocation::UNSPECIFIED));
                        }
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "incomplete trojan udp packet at EOF",
                        )));
                    }
                }
            }

            this.read_buf.maybe_compact(4096);
            if this.read_buf.remaining_capacity() == 0 {
                this.read_buf.compact();
            }
            if this.read_buf.remaining_capacity() == 0 {
                return Poll::Ready(Err(std::io::Error::other(
                    "trojan udp read buffer full but no complete packet",
                )));
            }

            let write_slice = this.read_buf.write_slice();
            let mut tmp_read_buf = ReadBuf::new(write_slice);

            match Pin::new(&mut this.stream).poll_read(cx, &mut tmp_read_buf) {
                Poll::Ready(Ok(())) => {
                    let bytes_read = tmp_read_buf.filled().len();
                    if bytes_read == 0 {
                        this.is_eof = true;
                        if this.read_buf.len() == 0 {
                            return Poll::Ready(Ok(NetLocation::UNSPECIFIED));
                        }
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "unexpected EOF in middle of trojan udp packet",
                        )));
                    }
                    this.read_buf.advance_write(bytes_read);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncStream> AsyncWriteSourcedMessage for TrojanUdpStream<S> {
    fn poll_write_sourced_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
        source: &NetLocation,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Flush any previously buffered write data
        while this.write_buf_sent < this.write_buf_len {
            let remaining = &this.write_buf[this.write_buf_sent..this.write_buf_len];
            match Pin::new(&mut this.stream).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                    }
                    this.write_buf_sent += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        this.write_buf_len = 0;
        this.write_buf_sent = 0;

        let total_len = write_trojan_packet_frame(&mut this.write_buf, source, buf)?;
        this.write_buf_len = total_len;

        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncStream> AsyncFlushMessage for TrojanUdpStream<S> {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        while this.write_buf_sent < this.write_buf_len {
            let remaining = &this.write_buf[this.write_buf_sent..this.write_buf_len];
            match Pin::new(&mut this.stream).poll_write(cx, remaining) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                    }
                    this.write_buf_sent += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        this.write_buf_len = 0;
        this.write_buf_sent = 0;
        Pin::new(&mut this.stream).poll_flush(cx)
    }
}

impl<S: AsyncStream> AsyncShutdownMessage for TrojanUdpStream<S> {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.get_mut();
        ready!(Pin::new(&mut this).poll_flush_message(cx))?;
        Pin::new(&mut this.stream).poll_shutdown(cx)
    }
}

impl<S: AsyncStream> AsyncPing for TrojanUdpStream<S> {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl<S: AsyncStream> AsyncTargetedMessageStream for TrojanUdpStream<S> {
    fn peer_addr(&self) -> Option<std::net::SocketAddr> {
        self.stream.peer_addr()
    }
}

/// A single-destination Trojan client UDP message stream.
/// Outgoing packets are stamped with `target`. Incoming packets are stripped of their SOCKS5 address header.
/// Implements `AsyncMessageStream`.
pub struct TrojanClientMessageStream<S> {
    inner: TrojanUdpStream<S>,
    target: NetLocation,
}

impl<S: AsyncStream> TrojanClientMessageStream<S> {
    pub fn new(stream: S, target: NetLocation) -> Self {
        Self {
            inner: TrojanUdpStream::new(stream),
            target,
        }
    }
}

impl<S: AsyncStream> AsyncReadMessage for TrojanClientMessageStream<S> {
    fn poll_read_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_read_targeted_message(cx, buf) {
            Poll::Ready(Ok(_location)) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncStream> AsyncWriteMessage for TrojanClientMessageStream<S> {
    fn poll_write_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let target = &this.target;
        Pin::new(&mut this.inner).poll_write_sourced_message(cx, buf, target)
    }
}

impl<S: AsyncStream> AsyncFlushMessage for TrojanClientMessageStream<S> {
    fn poll_flush_message(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush_message(cx)
    }
}

impl<S: AsyncStream> AsyncShutdownMessage for TrojanClientMessageStream<S> {
    fn poll_shutdown_message(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown_message(cx)
    }
}

impl<S: AsyncStream> AsyncPing for TrojanClientMessageStream<S> {
    fn supports_ping(&self) -> bool {
        false
    }

    fn poll_write_ping(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<bool>> {
        Poll::Ready(Ok(false))
    }
}

impl<S: AsyncStream> AsyncMessageStream for TrojanClientMessageStream<S> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::Address;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_write_and_parse_frame_ipv4() {
        let addr = NetLocation::new(Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let payload = b"hello udp over trojan";
        let mut buf = vec![0u8; 1024];

        let written = write_trojan_packet_frame(&mut buf, &addr, payload).unwrap();
        assert_eq!(written, 7 + 2 + 2 + payload.len());

        let (parsed_addr, start, len) =
            parse_trojan_packet_frame(&buf[..written]).unwrap().unwrap();
        assert_eq!(parsed_addr, addr);
        assert_eq!(&buf[start..start + len], payload);
    }

    #[test]
    fn test_write_and_parse_frame_domain() {
        let addr = NetLocation::new(Address::Hostname("dns.google".to_string()), 853);
        let payload = b"dns query payload";
        let mut buf = vec![0u8; 1024];

        let written = write_trojan_packet_frame(&mut buf, &addr, payload).unwrap();
        let expected_len = 1 + 1 + "dns.google".len() + 2 + 2 + 2 + payload.len();
        assert_eq!(written, expected_len);

        let (parsed_addr, start, len) =
            parse_trojan_packet_frame(&buf[..written]).unwrap().unwrap();
        assert_eq!(parsed_addr, addr);
        assert_eq!(&buf[start..start + len], payload);
    }

    #[test]
    fn test_write_and_parse_frame_ipv6() {
        let addr = NetLocation::new(
            Address::Ipv6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
            53,
        );
        let payload = b"ipv6 payload";
        let mut buf = vec![0u8; 1024];

        let written = write_trojan_packet_frame(&mut buf, &addr, payload).unwrap();
        let expected_len = 19 + 2 + 2 + payload.len();
        assert_eq!(written, expected_len);

        let (parsed_addr, start, len) =
            parse_trojan_packet_frame(&buf[..written]).unwrap().unwrap();
        assert_eq!(parsed_addr, addr);
        assert_eq!(&buf[start..start + len], payload);
    }

    #[test]
    fn test_incomplete_frame_returns_none() {
        let addr = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 1, 1, 1)), 53);
        let payload = b"payload data";
        let mut buf = vec![0u8; 1024];
        let written = write_trojan_packet_frame(&mut buf, &addr, payload).unwrap();

        // Truncate at various points
        assert!(parse_trojan_packet_frame(&buf[..4]).unwrap().is_none());
        assert!(parse_trojan_packet_frame(&buf[..7]).unwrap().is_none());
        assert!(parse_trojan_packet_frame(&buf[..9]).unwrap().is_none());
        assert!(parse_trojan_packet_frame(&buf[..11]).unwrap().is_none());
        assert!(parse_trojan_packet_frame(&buf[..written - 1])
            .unwrap()
            .is_none());
        assert!(parse_trojan_packet_frame(&buf[..written])
            .unwrap()
            .is_some());
    }

    #[test]
    fn test_missing_crlf_errors() {
        let addr = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 1, 1, 1)), 53);
        let payload = b"payload data";
        let mut buf = vec![0u8; 1024];
        let written = write_trojan_packet_frame(&mut buf, &addr, payload).unwrap();

        // Corrupt CRLF (bytes at addr_len + 2 and + 3)
        buf[7 + 2] = 0x00;
        let err = parse_trojan_packet_frame(&buf[..written]).unwrap_err();
        assert!(err.to_string().contains("CRLF"));
    }

    #[tokio::test]
    async fn test_client_and_server_udp_echo() {
        let (client_io, server_io) = tokio::io::duplex(65536);
        let target = NetLocation::new(Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1)), 5353);

        let client_stream = TrojanClientMessageStream::new(client_io, target.clone());
        let server_stream = TrojanUdpStream::new(server_io);

        let mut client_stream = Box::new(client_stream);
        let mut server_stream = Box::new(server_stream);

        // 1. Client sends a UDP packet to target
        let sent_payload = b"ping dns query";
        futures::future::poll_fn(|cx| {
            Pin::new(&mut client_stream).poll_write_message(cx, sent_payload)
        })
        .await
        .unwrap();

        futures::future::poll_fn(|cx| Pin::new(&mut client_stream).poll_flush_message(cx))
            .await
            .unwrap();

        // 2. Server reads the targeted packet
        let mut server_recv_buf = vec![0u8; 1024];
        let mut read_buf = ReadBuf::new(&mut server_recv_buf);
        let received_dest = futures::future::poll_fn(|cx| {
            Pin::new(&mut server_stream).poll_read_targeted_message(cx, &mut read_buf)
        })
        .await
        .unwrap();

        assert_eq!(received_dest, target);
        assert_eq!(read_buf.filled(), sent_payload);

        // 3. Server sends a reply back to client stamped with source = target
        let reply_payload = b"pong dns response";
        futures::future::poll_fn(|cx| {
            Pin::new(&mut server_stream)
                .poll_write_sourced_message(cx, reply_payload, &received_dest)
        })
        .await
        .unwrap();

        futures::future::poll_fn(|cx| Pin::new(&mut server_stream).poll_flush_message(cx))
            .await
            .unwrap();

        // 4. Client reads the response packet
        let mut client_recv_buf = vec![0u8; 1024];
        let mut client_read_buf = ReadBuf::new(&mut client_recv_buf);
        futures::future::poll_fn(|cx| {
            Pin::new(&mut client_stream).poll_read_message(cx, &mut client_read_buf)
        })
        .await
        .unwrap();

        assert_eq!(client_read_buf.filled(), reply_payload);
    }

    #[tokio::test]
    async fn test_trojan_udp_feed_initial_data_pipelined() {
        let (_client_io, server_io) = tokio::io::duplex(1024);
        let target = NetLocation::new(Address::Ipv4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        let payload = b"pipelined dns query";

        let mut initial_bytes = vec![0u8; 1024];
        let written = write_trojan_packet_frame(&mut initial_bytes, &target, payload).unwrap();
        initial_bytes.truncate(written);

        let mut server_stream = TrojanUdpStream::new(server_io);
        server_stream.feed_initial_data(&initial_bytes);

        let mut recv_buf = vec![0u8; 1024];
        let mut read_buf = ReadBuf::new(&mut recv_buf);
        let dest = futures::future::poll_fn(|cx| {
            Pin::new(&mut server_stream).poll_read_targeted_message(cx, &mut read_buf)
        })
        .await
        .unwrap();

        assert_eq!(dest, target);
        assert_eq!(read_buf.filled(), payload);
    }

    #[tokio::test]
    async fn test_trojan_udp_backpressure_does_not_duplicate_packet() {
        use tokio::io::AsyncReadExt;

        // Create a duplex with a tiny 16-byte channel to trigger backpressure
        let (client_io, mut server_raw) = tokio::io::duplex(16);
        let target = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 2, 3, 4)), 1234);
        let payload = b"this is a payload that exceeds the tiny sixteen byte duplex channel";

        let mut server_stream = TrojanUdpStream::new(client_io);

        // 1. Stage the message
        futures::future::poll_fn(|cx| {
            Pin::new(&mut server_stream).poll_write_sourced_message(cx, payload, &target)
        })
        .await
        .unwrap();

        // 2. Poll flush once - it will partially fill the 16-byte buffer and return Pending
        let flush_res = futures::future::poll_fn(|cx| {
            let res = Pin::new(&mut server_stream).poll_flush_message(cx);
            Poll::Ready(res.is_pending())
        })
        .await;
        assert!(flush_res, "Flush should be pending due to backpressure");

        // 3. A retried poll_write_sourced_message while backpressured must return Pending and NOT duplicate
        let retry_pending = futures::future::poll_fn(|cx| {
            let res =
                Pin::new(&mut server_stream).poll_write_sourced_message(cx, payload, &target);
            Poll::Ready(res.is_pending())
        })
        .await;
        assert!(
            retry_pending,
            "Retried write during backpressure must yield Pending"
        );

        // 4. Drain the duplex from the receiver side while driving the flush to completion
        let mut received = Vec::new();
        let drain_task = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            loop {
                let n = server_raw.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                received.extend_from_slice(&buf[..n]);
                if let Ok(Some((_, start, len))) = parse_trojan_packet_frame(&received)
                    && received.len() >= start + len
                {
                    break;
                }
            }
            received
        });

        futures::future::poll_fn(|cx| Pin::new(&mut server_stream).poll_flush_message(cx))
            .await
            .unwrap();

        let received = drain_task.await.unwrap();

        // 5. Verify received data contains exactly one frame with the original payload
        let (dest, start, len) = parse_trojan_packet_frame(&received).unwrap().unwrap();
        assert_eq!(dest, target);
        assert_eq!(&received[start..start + len], payload);
        // Entire buffer should be exactly this single frame (no second duplicate frame trailing)
        assert_eq!(received.len(), start + len);
    }

    #[tokio::test]
    async fn test_trojan_udp_write_zero_error() {
        struct ZeroWriter;
        impl tokio::io::AsyncRead for ZeroWriter {
            fn poll_read(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &mut ReadBuf<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        impl tokio::io::AsyncWrite for ZeroWriter {
            fn poll_write(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
                _buf: &[u8],
            ) -> Poll<std::io::Result<usize>> {
                Poll::Ready(Ok(0))
            }
            fn poll_flush(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        impl AsyncPing for ZeroWriter {
            fn supports_ping(&self) -> bool {
                false
            }
            fn poll_write_ping(
                self: Pin<&mut Self>,
                _cx: &mut Context<'_>,
            ) -> Poll<std::io::Result<bool>> {
                Poll::Ready(Ok(false))
            }
        }
        impl AsyncStream for ZeroWriter {}

        let mut stream = TrojanUdpStream::new(ZeroWriter);
        let target = NetLocation::new(Address::Ipv4(Ipv4Addr::new(1, 1, 1, 1)), 53);
        // Staging the packet succeeds
        futures::future::poll_fn(|cx| {
            Pin::new(&mut stream).poll_write_sourced_message(cx, b"hello", &target)
        })
        .await
        .unwrap();

        // Flushing when underlying writer returns Ok(0) must immediately return WriteZero, never hang
        let err = futures::future::poll_fn(|cx| Pin::new(&mut stream).poll_flush_message(cx))
            .await
            .unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WriteZero);
    }
}
