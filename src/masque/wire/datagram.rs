use bytes::{BufMut, Bytes, BytesMut};

use super::WireError;
use super::varint::decode_varint;

/// Prepend Context ID `0` (`0x00` varint) to an HTTP Datagram payload.
///
/// Used as the payload inside `h3_datagram::datagram::Datagram` (which encodes
/// Quarter Stream ID) or an HTTP/2 `DATAGRAM` capsule.
#[inline]
pub fn encode_context0_datagram(payload: &[u8]) -> Bytes {
    let mut buf = BytesMut::with_capacity(1 + payload.len());
    buf.put_u8(0);
    buf.put_slice(payload);
    buf.freeze()
}

/// Decode the leading Context ID varint from an HTTP Datagram payload.
///
/// Returns `(context_id, remaining_payload)` or `Err(WireError::InvalidVarint)`
/// when empty or truncated.
#[inline]
pub fn decode_datagram_context(buf: Bytes) -> Result<(u64, Bytes), WireError> {
    let (context_id, consumed) = decode_varint(&buf).map_err(|_| WireError::InvalidVarint)?;
    Ok((context_id, buf.slice(consumed..)))
}

/// Decode an HTTP Datagram payload expecting Context ID `0`.
///
/// Returns `Ok(Some(payload))` when Context ID is `0`, `Ok(None)` when a valid
/// non-zero Context ID is present (ignored per RFC 9297/9298), and
/// `Err(WireError::InvalidVarint)` if the Context ID varint is truncated.
#[inline]
pub fn decode_context0_datagram(buf: Bytes) -> Result<Option<Bytes>, WireError> {
    let (context_id, payload) = decode_datagram_context(buf)?;
    if context_id == 0 {
        Ok(Some(payload))
    } else {
        Ok(None)
    }
}
