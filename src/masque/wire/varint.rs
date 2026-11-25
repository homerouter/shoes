use bytes::BufMut;

use super::WireError;

/// Maximum value representable by a QUIC variable-length integer (2^62 - 1).
pub const MAX_VARINT: u64 = (1 << 62) - 1;

/// Decode a QUIC variable-length integer (RFC 9000 Section 16).
///
/// Returns `(value, bytes_consumed)` on success.
#[inline]
pub fn decode_varint(buf: &[u8]) -> Result<(u64, usize), WireError> {
    if buf.is_empty() {
        return Err(WireError::Incomplete);
    }

    let first = buf[0];
    let length = 1usize << (first >> 6);
    if buf.len() < length {
        return Err(WireError::Incomplete);
    }

    let value = match length {
        1 => u64::from(first & 0x3f),
        2 => u64::from(u16::from_be_bytes([first & 0x3f, buf[1]])),
        4 => u64::from(u32::from_be_bytes([
            first & 0x3f,
            buf[1],
            buf[2],
            buf[3],
        ])),
        8 => u64::from_be_bytes([
            first & 0x3f,
            buf[1],
            buf[2],
            buf[3],
            buf[4],
            buf[5],
            buf[6],
            buf[7],
        ]),
        _ => unreachable!(),
    };

    Ok((value, length))
}

/// Return the number of bytes needed to encode `value` as a QUIC varint.
#[inline]
pub fn varint_len(value: u64) -> Result<usize, WireError> {
    if value <= 63 {
        Ok(1)
    } else if value <= 16_383 {
        Ok(2)
    } else if value <= 1_073_741_823 {
        Ok(4)
    } else if value <= MAX_VARINT {
        Ok(8)
    } else {
        Err(WireError::Overflow)
    }
}

/// Encode `value` as a QUIC variable-length integer into `out`.
#[inline]
pub fn encode_varint(value: u64, out: &mut impl BufMut) -> Result<usize, WireError> {
    let len = varint_len(value)?;
    let mut scratch = [0u8; 8];
    match len {
        1 => scratch[0] = value as u8,
        2 => {
            let bytes = (value as u16).to_be_bytes();
            scratch[0] = bytes[0] | 0x40;
            scratch[1] = bytes[1];
        }
        4 => {
            let bytes = (value as u32).to_be_bytes();
            scratch[0] = bytes[0] | 0x80;
            scratch[1] = bytes[1];
            scratch[2] = bytes[2];
            scratch[3] = bytes[3];
        }
        8 => {
            let bytes = value.to_be_bytes();
            scratch[0] = bytes[0] | 0xc0;
            scratch[1..8].copy_from_slice(&bytes[1..8]);
        }
        _ => unreachable!(),
    }
    out.put_slice(&scratch[..len]);
    Ok(len)
}
