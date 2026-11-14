//! First-record salt replay cache for Snell v4/v5, ported from sing-snell
//! `snellv5/server.go` (snell-server v5.0.1: two 500 000-entry Bloom
//! generations at a 1e-10 false-positive rate).

use std::f64::consts::LN_2;
use std::fmt;
use std::sync::Mutex;

const GENERATION_SIZE: usize = 500_000;
const FALSE_POSITIVE_RATE: f64 = 1e-10;
const MURMUR_SEED: u32 = 0x9747_b28c;

/// MurmurHash2 (32-bit), as sing-snell computes it.
fn murmur2(data: &[u8], seed: u32) -> u32 {
    const M: u32 = 0x5bd1_e995;
    let mut hash = seed ^ data.len() as u32;
    let (chunks, tail) = data.as_chunks::<4>();
    for chunk in chunks {
        let mut k = u32::from_le_bytes(*chunk);
        k = k.wrapping_mul(M);
        k ^= k >> 24;
        k = k.wrapping_mul(M);
        hash = hash.wrapping_mul(M);
        hash ^= k;
    }
    if tail.len() >= 3 {
        hash ^= u32::from(tail[2]) << 16;
    }
    if tail.len() >= 2 {
        hash ^= u32::from(tail[1]) << 8;
    }
    if !tail.is_empty() {
        hash ^= u32::from(tail[0]);
        hash = hash.wrapping_mul(M);
    }
    hash ^= hash >> 13;
    hash = hash.wrapping_mul(M);
    hash ^= hash >> 15;
    hash
}

struct Bloom {
    bits: Vec<u8>,
    bit_count: u32,
    hash_count: u32,
}

impl Bloom {
    fn new() -> Self {
        let bits_per_entry = -FALSE_POSITIVE_RATE.ln() / (LN_2 * LN_2);
        let bit_count = (GENERATION_SIZE as f64 * bits_per_entry) as u32;
        let hash_count = (bits_per_entry * LN_2).ceil() as u32;
        Self {
            bits: vec![0; bit_count.div_ceil(8) as usize],
            bit_count,
            hash_count,
        }
    }

    fn positions(&self, data: &[u8]) -> impl Iterator<Item = u32> + use<> {
        let first = murmur2(data, MURMUR_SEED);
        let step = murmur2(data, first);
        let bit_count = self.bit_count;
        (0..self.hash_count).map(move |i| first.wrapping_add(i.wrapping_mul(step)) % bit_count)
    }

    fn contains(&self, data: &[u8]) -> bool {
        self.positions(data)
            .all(|bit| self.bits[(bit >> 3) as usize] & (1 << (bit & 7)) != 0)
    }

    fn add(&mut self, data: &[u8]) {
        for bit in self.positions(data) {
            self.bits[(bit >> 3) as usize] |= 1 << (bit & 7);
        }
    }
}

struct Generations {
    current: usize,
    counts: [usize; 2],
    filters: [Bloom; 2],
}

/// Remembers recent first-record salts; one per Snell listener.
pub struct SaltReplayCache {
    generation_size: usize,
    state: Mutex<Option<Generations>>,
}

impl SaltReplayCache {
    pub fn new() -> Self {
        Self::with_generation_size(GENERATION_SIZE)
    }

    fn with_generation_size(generation_size: usize) -> Self {
        Self {
            generation_size,
            state: Mutex::new(None),
        }
    }

    /// Records `salt`; returns true when it was seen recently (a replay).
    pub fn check_and_add(&self, salt: &[u8]) -> bool {
        let mut state = self.state.lock().unwrap();
        // Allocated on first use, as in sing-snell.
        let state = state.get_or_insert_with(|| Generations {
            current: 0,
            counts: [0; 2],
            filters: [Bloom::new(), Bloom::new()],
        });
        if state.filters.iter().any(|filter| filter.contains(salt)) {
            return true;
        }
        let current = state.current;
        state.filters[current].add(salt);
        state.counts[current] += 1;
        if state.counts[current] >= self.generation_size {
            state.counts[current] = 0;
            state.current ^= 1;
            let next = state.current;
            state.filters[next].bits.fill(0);
        }
        false
    }
}

impl Default for SaltReplayCache {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for SaltReplayCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SaltReplayCache")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counting_salt() -> Vec<u8> {
        (0u8..16).collect()
    }

    /// Golden values from sing-snell@e056cb336137 `saltReplayBloom.MurmurHash`.
    #[test]
    fn murmur2_matches_go() {
        let cases: [(&[u8], u32, u32); 8] = [
            (b"", 0x106e08d9, 0x456d9087),
            (b"a", 0xa2d0b27c, 0x2e36e8b4),
            (b"ab", 0x12d8262a, 0x87ae788a),
            (b"abc", 0x1c94221b, 0x08e2b515),
            (b"abcd", 0xb11ab5f4, 0x7796ea9c),
            (b"abcde", 0x1b897edd, 0x263bdc4f),
            (&[0u8; 16], 0x94f76688, 0x325f87fc),
            (&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], 0xc220d729, 0x1457aacb),
        ];
        for (input, first, step) in cases {
            assert_eq!(murmur2(input, MURMUR_SEED), first, "{input:x?}");
            assert_eq!(murmur2(input, first), step, "{input:x?}");
        }
    }

    /// Golden values from sing-snell `saltReplayBloom.Initialize` and `Add`.
    #[test]
    fn bloom_matches_go() {
        let bloom = Bloom::new();
        assert_eq!(bloom.bit_count, 23_962_645);
        assert_eq!(bloom.hash_count, 34);
        assert_eq!(bloom.bits.len(), 2_995_331);
        let positions: Vec<u32> = bloom.positions(&counting_salt()).collect();
        assert_eq!(
            positions,
            [
                21975062, 3825062, 9637707, 15450352, 15609156, 21421801, 3271801, 9084446,
                14897091, 20709736, 2559736, 8372381, 14185026, 19997671, 1847671, 7660316,
                7819120, 13631765, 19444410, 1294410, 7107055, 12919700, 18732345, 582345,
                6394990, 12207635, 18020280, 23832925, 5682925, 5841729, 11654374, 17467019,
                23279664, 5129664,
            ]
        );
    }

    #[test]
    fn repeated_salt_is_a_replay() {
        let cache = SaltReplayCache::new();
        assert!(!cache.check_and_add(&counting_salt()));
        assert!(cache.check_and_add(&counting_salt()));
        assert!(!cache.check_and_add(&[7u8; 16]));
    }

    #[test]
    fn full_generation_rotates_and_forgets_the_older_one() {
        let cache = SaltReplayCache::with_generation_size(2);
        for salt in [b"salt-a", b"salt-b", b"salt-c", b"salt-d"] {
            assert!(!cache.check_and_add(salt));
        }
        // a and b filled generation 0, which was cleared when c and d filled 1.
        assert!(!cache.check_and_add(b"salt-a"));
        assert!(cache.check_and_add(b"salt-c"));
    }
}
