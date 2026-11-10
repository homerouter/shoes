//! Traffic shaping for Snell v6 `default` mode.
//!
//! Both peers expand the PSK into a [`ShapeProfile`]. The profile fixes, per
//! record sequence number:
//!
//! * the length of the filler *prefix* that precedes each sealed header,
//! * the length of the filler *padding* between header and payload (records
//!   are padded up towards PSK-chosen target sizes),
//! * the payload budget of each stream record (a ramp that restarts after
//!   an idle period),
//! * the filler bytes themselves (one of four byte "styles"),
//! * where the 16 salt bytes sit inside the salt block that opens the
//!   stream, and
//! * how padding bytes are interleaved with the sealed payload.
//!
//! None of this is negotiated, so every derived value has to match the
//! official implementation exactly — the constants below are part of the
//! wire protocol. The adapter integration tests exercise this module against
//! a real snell-server v6 in `default` mode.
//!
//! All derivations draw from one keyed hash over splitmix64 ([`Keys::hash`]).
//! The key comes from BLAKE2b-256 of a fixed seed and the PSK, spread over
//! seven independent lanes.

use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};

pub const SALT_LEN: usize = 16;

/// Largest record payload or padding length (16-bit length fields).
pub const RECORD_LEN_MAX: usize = 0xffff;

/// Sealed-header and tag sizes, as they enter the padding arithmetic.
const TAG_LEN: usize = 16;
const SEALED_HEADER_LEN: usize = 7 + TAG_LEN;

/// Cap on padding added to reach a target record size.
const TOP_UP_MAX: usize = 0x2da;

/// Records larger than this are left at their natural size.
const TARGET_SIZE_CEILING: usize = 0x5b3;

/// Sequence number used to fill the salt block (never a real record's).
const SALT_BLOCK_SEQ: u32 = u32::MAX;

// ─── Keyed hash ──────────────────────────────────────────────────────────────

/// splitmix64 increment (2^64 / φ).
const SPLITMIX_GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;

/// BLAKE2b input prefix preceding the PSK.
const KEY_SEED: [u8; 24] = [
    0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94, 0x33, 0x18, 0xc0, 0x6e,
    0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac,
];

fn splitmix(mut z: u64) -> u64 {
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// 32-bit keyed hash of `(tag, x, y)` under `key`.
fn hash32(key: u64, tag: u32, x: u64, y: u64) -> u32 {
    let z = splitmix(
        key ^ u64::from(tag).wrapping_mul(SPLITMIX_GAMMA)
            ^ x.wrapping_mul(0xe703_7ed1_a0b4_28db)
                .wrapping_add(0x8f39_07f7_b2b8_0c35)
            ^ y.wrapping_mul(0x5899_65cc_7537_4cc3)
                .wrapping_add(0x33a2_13ec_50ff_e2e9),
    );
    (z ^ (z >> 32)) as u32
}

/// Independent key lanes; each hash tag is bound to one of them.
#[derive(Clone, Copy)]
enum Lane {
    Params,
    Prefix,
    Motif,
    Salt,
    Mix,
    Chunk,
    Write,
}

impl Lane {
    const ALL: [Lane; 7] = [
        Lane::Params,
        Lane::Prefix,
        Lane::Motif,
        Lane::Salt,
        Lane::Mix,
        Lane::Chunk,
        Lane::Write,
    ];

    /// `(tag, seed)` the lane key is expanded from.
    fn seed(self) -> (u64, u64) {
        match self {
            Lane::Params => (5, 0xb46c_2e7d_9a15_38f1),
            Lane::Prefix => (0, 0x5d92_17c0_83e6_4ab9),
            Lane::Motif => (2, 0xa71f_0c54_d839_6e2b),
            Lane::Salt => (3, 0x3e8a_91b5_2740_f6cd),
            Lane::Mix => (16, 0xc9f4_260b_7d1e_835a),
            Lane::Chunk => (21, 0x62d0_b5e1_9c4a_783f),
            Lane::Write => (28, 0x917b_3c48_e6a2_05d4),
        }
    }

    /// Lane a hash tag draws from.
    fn of(tag: u32) -> Lane {
        match tag {
            0 | 1 | 14 | 15 | 33 | 34 => Lane::Prefix,
            2 => Lane::Motif,
            3 | 16..=20 => Lane::Mix,
            21..=26 | 38 | 39 => Lane::Chunk,
            28..=32 | 35..=37 => Lane::Write,
            _ => Lane::Params,
        }
    }
}

// Hash tags.
const T_FILL: u32 = 0;
const T_ROW: u32 = 1;
const T_MOTIF: u32 = 2;
const T_MIX_START: u32 = 3;
const T_STYLE: u32 = 6;
const T_PREFIX: u32 = 33;
const T_PAD: u32 = 34;
const T_TARGET: u32 = 35;
const T_TARGET_JITTER: u32 = 36;
const T_TARGET_STEP: u32 = 37;
const T_CHUNK_BUCKET: u32 = 38;
const T_CHUNK_JITTER: u32 = 39;

/// Domain separating stream-opening (salt block) parameters.
const OPENING: u32 = 0x7053;
/// Domain of the salt-block shuffle and masks.
const SALT_SHUFFLE: u32 = 0x51a7;

struct Keys([u64; 7]);

impl Keys {
    fn new(psk: &[u8]) -> Self {
        let digest: [u8; 32] = Blake2b::<U32>::new()
            .chain_update(KEY_SEED)
            .chain_update(psk)
            .finalize()
            .into();
        let w: [u64; 4] = std::array::from_fn(|i| {
            u64::from_le_bytes(digest[i * 8..i * 8 + 8].try_into().expect("8-byte word"))
        });
        let base =
            w[0] ^ w[1].wrapping_add(SPLITMIX_GAMMA) ^ w[2].rotate_left(17) ^ w[3].rotate_right(11);
        Keys(Lane::ALL.map(|lane| {
            let (tag, seed) = lane.seed();
            splitmix(
                tag.wrapping_mul(0xd6e8_feb8_6659_fd93)
                    ^ seed.wrapping_add(0xa076_1d64_78bd_642f)
                    ^ base,
            )
        }))
    }

    fn lane(&self, lane: Lane) -> u64 {
        self.0[lane as usize]
    }

    fn hash(&self, tag: u32, x: u64, y: u64) -> u32 {
        hash32(self.lane(Lane::of(tag)), tag, x, y)
    }

    /// `lo..=hi` drawn from `hash(tag, x, y)`.
    fn range(&self, tag: u32, x: u64, y: u64, lo: usize, hi: usize) -> usize {
        debug_assert!(lo <= hi);
        lo + (u64::from(self.hash(tag, x, y)) % (hi - lo + 1) as u64) as usize
    }

    /// Static parameter: `lo..=hi` from `(tag, domain)`.
    fn param(&self, tag: u32, domain: u32, lo: usize, hi: usize) -> usize {
        self.range(tag, 0, u64::from(domain), lo, hi)
    }

    /// Symmetric jitter in `-spread..=spread`.
    fn jitter(&self, tag: u32, x: u64, y: u64, spread: usize) -> i64 {
        (u64::from(self.hash(tag, x, y)) % (2 * spread as u64 + 1)) as i64 - spread as i64
    }

    /// Keystream of `out.len()` bytes for `(tag, x)`.
    fn stream(&self, tag: u32, x: u32, out: &mut [u8]) {
        let mut state = self.lane(Lane::of(tag))
            ^ u64::from(x)
                .wrapping_mul(0xd6e8_feb8_6659_fd93)
                .wrapping_add(0xb57d_e1f3_f82c_b33f)
            ^ u64::from(tag).wrapping_mul(0xa24b_aed4_963e_e407)
            ^ (out.len() as u64)
                .wrapping_mul(0x1656_67b1_9e37_79f9)
                .wrapping_add(0x0d4c_d3e7_b14a_36d7);
        for chunk in out.chunks_mut(8) {
            state = state.wrapping_add(SPLITMIX_GAMMA);
            chunk.copy_from_slice(&splitmix(state).to_le_bytes()[..chunk.len()]);
        }
    }
}

// ─── Profile pieces ──────────────────────────────────────────────────────────

/// Byte-at-a-time styles for filler bytes, applied over a keystream.
enum FillStyle {
    /// Bytes with a fixed number of set bits (chosen per record).
    Popcount { lo: usize, hi: usize },
    /// Mix of printable ASCII and UTF-8-shaped continuation/lead bytes.
    Text {
        ascii: usize,
        continuation: usize,
        lead: usize,
    },
    /// Digit-like nibbles.
    Digits { offset: usize },
    /// A repeating motif broken up by digit-like bytes.
    Motif { words: usize, period: usize },
}

/// For `k` set bits (2..=6): 16 bytes with exactly `k` bits set.
const POPCOUNT_BYTES: [[u8; 16]; 5] = [
    [
        0x03, 0x05, 0x09, 0x11, 0x21, 0x41, 0x81, 0x06, 0x0a, 0x12, 0x22, 0x42, 0x82, 0x0c, 0x18,
        0x24,
    ],
    [
        0x07, 0x0b, 0x13, 0x23, 0x43, 0x83, 0x0d, 0x19, 0x31, 0x61, 0xc1, 0x0e, 0x1c, 0x38, 0x70,
        0xe0,
    ],
    [
        0x0f, 0x17, 0x27, 0x47, 0x87, 0x1b, 0x33, 0x63, 0xc3, 0x1d, 0x39, 0x71, 0xe1, 0x3c, 0x78,
        0xf0,
    ],
    [
        0xf8, 0xf4, 0xec, 0xdc, 0xbc, 0x7c, 0xf2, 0xe6, 0xce, 0x9e, 0x3e, 0xf1, 0xe3, 0xc7, 0x8f,
        0x1f,
    ],
    [
        0xfc, 0xfa, 0xf6, 0xee, 0xde, 0xbe, 0x7e, 0xf9, 0xf5, 0xed, 0xdd, 0xbd, 0x7d, 0xf3, 0xe7,
        0xdb,
    ],
];

/// How padding is interleaved with the sealed payload (an involution).
enum Interleave {
    /// Swap every `stride`-th byte from a fixed start.
    Strided { stride: usize, start: usize },
    /// Swap alternating `block`-byte blocks.
    Blocks { block: usize },
    /// Like `Strided`, but the start is re-keyed per record and round.
    Keyed { stride: usize, start: usize },
}

/// Stream-record payload budget.
enum Budget {
    Ramp,
    Buckets([usize; 8]),
    Jitter(usize),
}

/// Per-direction writer state for the budget ramp. `seq` is the record
/// sequence number shared with the reader side's derivations.
#[derive(Debug, Default, Clone, Copy)]
pub struct ShapeState {
    pub seq: u32,
    chunk: usize,
    last_unix: i64,
}

/// PSK-derived shaping profile, shared by all connections of an adapter.
pub struct ShapeProfile {
    keys: Keys,
    style: FillStyle,

    prefix_lo: usize,
    prefix_hi: usize,

    pad_lo: usize,
    pad_hi: usize,
    /// Records `0..always_padded` are always padded, as are small payloads
    /// and every `pad_every`-th record.
    always_padded: u32,
    pad_every: u32,
    small_payload: usize,

    /// Target record sizes: `lead_targets[seq]` for the first
    /// `lead_records` records, then keyed picks from `targets`.
    lead_records: u32,
    lead_targets: [usize; 8],
    targets: [usize; 8],
    target_jitter: Option<usize>,
    target_spread_pct: usize,

    interleave: Interleave,
    interleave_rounds: u32,

    budget: Budget,
    budget_initial: usize,
    budget_first: usize,
    budget_max: usize,
    budget_step: usize,
    idle_reset_secs: i64,

    salt_block_len: usize,
    /// `(position, mask)` of each salt byte inside the salt block.
    salt_slots: [(u8, u8); SALT_LEN],
}

impl std::fmt::Debug for ShapeProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // PSK-derived; keep it out of logs.
        f.debug_struct("ShapeProfile").finish_non_exhaustive()
    }
}

impl ShapeProfile {
    pub fn new(psk: &[u8]) -> Self {
        let k = Keys::new(psk);
        let p = |tag, domain, lo, hi| k.param(tag, domain, lo, hi);
        let p0 = |tag, lo, hi| k.param(tag, 0, lo, hi);
        let pick = |tag, domain: u32, n| k.hash(tag, 0, u64::from(domain)) as usize % n;

        let style = match pick(T_STYLE, 0, 4) {
            0 => FillStyle::Popcount {
                lo: p0(12, 0x18, 0x29),
                hi: p0(13, 0x3a, 0x4c),
            },
            1 => FillStyle::Text {
                ascii: p(T_STYLE, 1, 0x18, 0x80),
                continuation: p(T_STYLE, 2, 0x10, 0x60),
                lead: p(T_STYLE, 3, 0x10, 0x60),
            },
            2 => FillStyle::Digits {
                offset: p(T_STYLE, 4, 0, 9),
            },
            _ => FillStyle::Motif {
                words: p(T_STYLE, 5, 1, 8),
                period: p(T_STYLE, 6, 7, 0x17),
            },
        };

        let (prefix_lo, prefix_hi) = bounded_span(p0(14, 0x08, 0x50), p0(15, 0x10, 0xa0));
        let (open_lo, open_hi) =
            bounded_span(p(14, OPENING, 0x10, 0x60), p(15, OPENING, 0x10, 0xa0));
        let salt_block_len = SALT_LEN + p(T_PREFIX, OPENING, open_lo, open_hi);

        let pad_lo = p0(7, 0x18, 0xa0);
        let pad_hi = (pad_lo + p0(8, 0xa0, 0x3c0)).min(TOP_UP_MAX);

        let targets = std::array::from_fn(|i| p(30, i as u32, 0x140, 0x5b4));
        let lead_targets = std::array::from_fn(|i| p(31, i as u32, 0x168, 0x5b4));
        let target_jitter = (pick(28, 0, 3) == 2).then(|| p0(32, 0x08, 0x60));

        let interleave = match pick(16, 0, 3) {
            0 => Interleave::Strided {
                stride: p0(18, 2, 13),
                start: p0(19, 0, 15),
            },
            1 => Interleave::Blocks {
                block: p0(20, 8, 0x40),
            },
            _ => Interleave::Keyed {
                stride: p0(18, 2, 13),
                start: p0(19, 0, 15),
            },
        };

        let budget_initial = p0(22, 0x200, 0x5b4);
        let budget_max = p0(23, 0x2000, 0x3fff);
        let budget = match pick(21, 0, 3) {
            0 => Budget::Ramp,
            1 => Budget::Buckets(std::array::from_fn(|i| p(26, i as u32, 0x1000, budget_max))),
            _ => Budget::Jitter(p0(25, 0x10, 0xc0).min(0xb6)),
        };

        let shuffle_rounds = p(17, SALT_SHUFFLE, 1, 4);
        let mask_stride = p(18, SALT_SHUFFLE, 0x11, 0xfb) as u8;
        let salt_slots = salt_slots(
            k.lane(Lane::Salt),
            shuffle_rounds,
            mask_stride,
            salt_block_len,
        );

        Self {
            style,
            prefix_lo,
            prefix_hi,
            pad_lo,
            pad_hi,
            always_padded: p0(9, 2, 8) as u32,
            pad_every: p0(10, 2, 0x0b) as u32,
            small_payload: p0(11, 0x60, 0x300),
            lead_records: p0(29, 4, 8) as u32,
            lead_targets,
            targets,
            target_jitter,
            target_spread_pct: p(28, 0x504c, 8, 0x30),
            interleave,
            interleave_rounds: p0(17, 1, 3) as u32,
            budget,
            budget_initial,
            budget_first: p(22, 0xf17c, 0x100, 0x300).min(budget_initial),
            budget_max,
            budget_step: p0(24, 0x400, 0x1000).min(0xb68),
            idle_reset_secs: p0(27, 0x0c, 0x5a) as i64,
            salt_block_len,
            salt_slots,
            keys: k,
        }
    }

    /// Wire length of the salt block that opens each direction.
    pub fn salt_block_len(&self) -> usize {
        self.salt_block_len
    }

    /// Filler prefix length before record `seq`'s sealed header.
    pub fn prefix_len(&self, seq: u32) -> usize {
        self.keys
            .range(T_PREFIX, u64::from(seq), 0, self.prefix_lo, self.prefix_hi)
    }

    /// Padding length of record `seq` carrying `payload_len` bytes after a
    /// `prefix_len`-byte prefix. `opening` marks the record that also
    /// carries the salt block.
    pub fn padding_len(
        &self,
        seq: u32,
        payload_len: usize,
        prefix_len: usize,
        opening: bool,
    ) -> usize {
        let padded = seq < self.always_padded
            || (1..=self.small_payload).contains(&payload_len)
            || seq.is_multiple_of(self.pad_every);
        let mut padding = if padded {
            self.keys.range(
                T_PAD,
                u64::from(seq),
                payload_len as u64,
                self.pad_lo,
                self.pad_hi,
            )
        } else {
            0
        };
        let salt_block = if opening { self.salt_block_len } else { 0 };
        let sealed_payload = if payload_len == 0 {
            0
        } else {
            payload_len + TAG_LEN
        };
        let size = salt_block + prefix_len + SEALED_HEADER_LEN + padding + sealed_payload;
        padding += self
            .target_size(seq, size)
            .saturating_sub(size)
            .min(TOP_UP_MAX);
        if opening {
            padding = self.opening_padding(padding, prefix_len, payload_len);
        }
        padding.min(RECORD_LEN_MAX)
    }

    /// Size record `seq` (currently `size` bytes) is padded towards.
    fn target_size(&self, seq: u32, size: usize) -> usize {
        if size > TARGET_SIZE_CEILING {
            return size.min(RECORD_LEN_MAX);
        }
        let seq64 = u64::from(seq);
        let mut target = if seq < self.lead_records {
            self.lead_targets[seq as usize]
        } else {
            self.targets[self.keys.hash(T_TARGET, seq64, size as u64) as usize % 8]
        };
        if let Some(spread) = self.target_jitter {
            target = (target as i64 + self.keys.jitter(T_TARGET_JITTER, seq64, 0, spread)).max(1)
                as usize;
        }
        let spread = (size * self.target_spread_pct / 100).min(TOP_UP_MAX);
        if self.keys.hash(T_TARGET, seq64, spread as u64) & 1 == 0 {
            target = (target + spread).min(RECORD_LEN_MAX);
        } else if target > spread / 2 {
            target -= spread / 2;
        }
        // Too small for this record: climb to the next keyed target.
        while size > target {
            let next =
                self.targets[self.keys.hash(T_TARGET_STEP, seq64, target as u64) as usize % 8];
            target = if next > target {
                next
            } else if target + self.pad_hi <= RECORD_LEN_MAX {
                target + self.pad_hi
            } else {
                return RECORD_LEN_MAX;
            };
        }
        target
    }

    /// The opening record keeps its filler (salt-block filler + prefix +
    /// padding) at a floor proportional to the payload it carries.
    fn opening_padding(&self, padding: usize, prefix_len: usize, payload_len: usize) -> usize {
        let block_filler = self.salt_block_len - SALT_LEN;
        let base = payload_len + if payload_len == 0 { 0x27 } else { 0x37 };
        let floor = (base * 25).div_ceil(75).max(0xc0);
        if block_filler + prefix_len + padding >= floor {
            return padding;
        }
        (floor - block_filler - prefix_len).min(self.pad_hi + TOP_UP_MAX)
    }

    /// Payload budget for the next stream record. Called once per record —
    /// zero chunks and datagrams included, which advance the ramp even
    /// though they ignore the budget.
    pub fn next_budget(&self, state: &mut ShapeState, now_unix: i64) -> usize {
        if state.last_unix == 0 || now_unix - state.last_unix > self.idle_reset_secs {
            state.chunk = self.budget_initial;
        }
        let seq = u64::from(state.seq);
        let chunk = state.chunk;
        let raw = match &self.budget {
            Budget::Ramp => chunk,
            Budget::Buckets(buckets) => {
                buckets[self.keys.hash(T_CHUNK_BUCKET, seq, chunk as u64) as usize % 8]
            }
            Budget::Jitter(spread) => (chunk as i64
                + self.keys.jitter(T_CHUNK_JITTER, seq, chunk as u64, *spread))
            .max(0) as usize,
        };
        let mut budget = raw.clamp(0x40, self.budget_max);
        if state.seq == 0 {
            budget = budget.min(self.budget_first);
        }
        state.chunk = (chunk + self.budget_step).min(self.budget_max);
        state.last_unix = now_unix;
        budget
    }

    /// Fill `out` with record `seq`'s filler bytes.
    pub fn fill(&self, seq: u32, out: &mut [u8]) {
        self.keys.stream(T_FILL, seq, out);
        match self.style {
            FillStyle::Popcount { lo, hi } => {
                let bits = self.keys.range(T_ROW, u64::from(seq), 0, lo, hi);
                let row = &POPCOUNT_BYTES[(bits * 8 + 50) / 100 - 2];
                for (i, b) in out.iter_mut().enumerate() {
                    let v = *b;
                    let r = v.wrapping_add(i as u8);
                    *b =
                        row[usize::from((r ^ v) & 0x0f)].rotate_left(u32::from((r ^ (v >> 4)) & 7));
                }
            }
            FillStyle::Text {
                ascii,
                continuation,
                lead,
            } => {
                let classes = ascii + continuation + lead;
                for (i, b) in out.iter_mut().enumerate() {
                    let v = *b;
                    let class = usize::from(v) % classes;
                    let (seed, lo) = if class < ascii {
                        (v.wrapping_add(i as u8), 0x20)
                    } else if class < ascii + continuation {
                        (v ^ i as u8, 0x80)
                    } else {
                        (v.wrapping_add((i * 7) as u8), 0xc0)
                    };
                    let span = if lo == 0x20 { 0x5f } else { 0x40 };
                    *b = lo + seed % span;
                }
            }
            FillStyle::Digits { offset } => {
                for (i, b) in out.iter_mut().enumerate() {
                    let v = usize::from(*b);
                    let low = ((v & 0x0f) + offset + (i & 1)) % 10;
                    let high = (v + ((i & 3) << 4) + 0x30) & 0xf0;
                    *b = (high | low) as u8;
                }
            }
            FillStyle::Motif { words, period } => {
                let mut motif = [0u8; 32];
                self.keys.stream(T_MOTIF, seq, &mut motif);
                let motif_len = words * 4;
                let step = (words + 3) as u8;
                for (i, b) in out.iter_mut().enumerate() {
                    let phase = i % period;
                    if phase + 3 < period {
                        *b = step.wrapping_mul(i as u8) ^ motif[i % motif_len];
                    } else if phase + 1 < period {
                        *b = 0x30 | (*b % 10);
                    }
                }
            }
        }
    }

    /// Build the salt block: filler with the salt bytes scattered into it.
    pub fn write_salt_block(&self, salt: &[u8; SALT_LEN], block: &mut [u8]) {
        debug_assert_eq!(block.len(), self.salt_block_len);
        self.fill(SALT_BLOCK_SEQ, block);
        for (&(pos, mask), &s) in self.salt_slots.iter().zip(salt) {
            block[usize::from(pos)] = mask ^ s;
        }
    }

    /// Recover the salt from a salt block.
    pub fn read_salt_block(&self, block: &[u8]) -> [u8; SALT_LEN] {
        debug_assert_eq!(block.len(), self.salt_block_len);
        self.salt_slots
            .map(|(pos, mask)| mask ^ block[usize::from(pos)])
    }

    /// Interleave `padding` with the sealed payload (tag included) of record
    /// `seq`. Applying it twice restores both buffers.
    pub fn interleave(&self, seq: u32, padding: &mut [u8], sealed: &mut [u8]) {
        let n = padding.len().min(sealed.len());
        let (a, b) = (&mut padding[..n], &mut sealed[..n]);
        for round in 0..self.interleave_rounds {
            match self.interleave {
                Interleave::Strided { stride, start } => {
                    let stride = stride + (round % 3) as usize;
                    swap_every(a, b, start % stride, stride);
                }
                Interleave::Keyed { stride, start } => {
                    let stride = stride + (round % 3) as usize;
                    let key = self
                        .keys
                        .hash(T_MIX_START, u64::from(seq), u64::from(round));
                    swap_every(
                        a,
                        b,
                        ((u64::from(key) + start as u64) % stride as u64) as usize,
                        stride,
                    );
                }
                Interleave::Blocks { block } => {
                    let mut at = (round & 1) as usize * block;
                    while at + block <= n {
                        a[at..at + block].swap_with_slice(&mut b[at..at + block]);
                        at += 2 * block;
                    }
                }
            }
        }
    }
}

/// `(lo, lo + span)` capped at 0x80, with `lo` kept at or below the cap.
fn bounded_span(lo: usize, span: usize) -> (usize, usize) {
    let hi = (lo + span).min(0x80);
    (lo.min(hi), hi)
}

fn swap_every(a: &mut [u8], b: &mut [u8], start: usize, stride: usize) {
    for i in (start..a.len()).step_by(stride) {
        std::mem::swap(&mut a[i], &mut b[i]);
    }
}

/// Where each salt byte lands in the salt block, and its mask: a keyed
/// Fisher–Yates shuffle of the block positions (repeated `rounds` times)
/// assigns the first 16 slots to the salt.
fn salt_slots(key: u64, rounds: usize, mask_stride: u8, block_len: usize) -> [(u8, u8); SALT_LEN] {
    // `block_len <= SALT_LEN + 0x80`, so every position fits a byte.
    let mut order: Vec<u8> = (0..block_len as u8).collect();
    for round in 0..rounds as u64 {
        for i in 0..block_len {
            let draw = hash32(
                key ^ 0xdaa6_6d2c_7ddf_743f,
                0,
                u64::from(SALT_SHUFFLE) + round,
                i as u64,
            );
            let j = i + (u64::from(draw) % (block_len - i) as u64) as usize;
            order.swap(i, j);
        }
    }
    std::array::from_fn(|i| {
        let mask = (i as u8).wrapping_mul(mask_stride)
            ^ hash32(key, T_MOTIF, u64::from(SALT_SHUFFLE), i as u64) as u8;
        (order[i], mask)
    })
}

