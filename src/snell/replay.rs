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
    let mut chunks = data.chunks_exact(4);
    for chunk in &mut chunks {
        let mut k = u32::from_le_bytes(chunk.try_into().unwrap());
        k = k.wrapping_mul(M);
        k ^= k >> 24;
        k = k.wrapping_mul(M);
        hash = hash.wrapping_mul(M);
        hash ^= k;
    }
    let tail = chunks.remainder();
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

