//! Replicated shares of 16-byte values, bitsliced over lanes.

pub(crate) const BITS: usize = 128;
/// The share carrying public constants.
pub(crate) const PUBLIC: usize = 0;

/// `s[m][bit * words + w]`; share m is unused at party m.
#[derive(Clone)]
pub struct Shares {
    pub words: usize,
    pub s: [Vec<u64>; 4],
}

impl Drop for Shares {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.s);
    }
}

impl Shares {
    pub fn zero(words: usize) -> Shares {
        Shares {
            words,
            s: std::array::from_fn(|_| vec![0u64; BITS * words]),
        }
    }
}

/// For tests.
pub fn reconstruct_lane0(views: &[Shares]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for b in 0..BITS {
        let v = (0..4).fold(0u64, |acc, m| acc ^ views[(m + 1) % 4].s[m][b * views[0].words]);
        out[b / 8] |= ((v & 1) as u8) << (b % 8);
    }
    out
}

/// Lane i takes node `idx[i]`.
pub fn select(nodes: &[Shares], idx: &[usize]) -> Shares {
    let words = nodes[0].words;
    let mut out = Shares::zero(words);
    for (lane, &b) in idx.iter().enumerate() {
        let (w, bit) = (lane / 64, 1u64 << (lane % 64));
        for m in 0..4 {
            for k in 0..BITS {
                let j = k * words + w;
                out.s[m][j] = (out.s[m][j] & !bit) | (nodes[b].s[m][j] & bit);
            }
        }
    }
    out
}

pub fn lanes_of(opened: &[u64], words: usize, n: usize) -> Vec<[u8; 16]> {
    (0..n)
        .map(|lane| {
            let mut o = [0u8; 16];
            for b in 0..BITS {
                o[b / 8] |= (((opened[b * words + lane / 64] >> (lane % 64)) & 1) as u8) << (b % 8);
            }
            o
        })
        .collect()
}

/// Lanes `from..from + n`, moved to lane 0.
pub fn sub_lanes(x: &Shares, from: usize, n: usize) -> Shares {
    let words = n.div_ceil(64);
    let mut out = Shares::zero(words);
    for m in 0..4 {
        for b in 0..BITS {
            for lane in 0..n {
                let src = from + lane;
                let bit = (x.s[m][b * x.words + src / 64] >> (src % 64)) & 1;
                out.s[m][b * words + lane / 64] |= bit << (lane % 64);
            }
        }
    }
    out
}

/// Output lane i is lane `src[i].1` of `src[i].0`.
pub fn gather(src: &[(&Shares, usize)]) -> Shares {
    let words = src.len().div_ceil(64);
    let mut out = Shares::zero(words);
    for (i, &(x, lane)) in src.iter().enumerate() {
        for m in 0..4 {
            for b in 0..BITS {
                let bit = (x.s[m][b * x.words + lane / 64] >> (lane % 64)) & 1;
                out.s[m][b * words + i / 64] |= bit << (i % 64);
            }
        }
    }
    out
}

/// A lane-constant sharing at another width.
pub fn broadcast(x: &Shares, words: usize) -> Shares {
    let mut out = Shares::zero(words);
    for m in 0..4 {
        for b in 0..BITS {
            let v = (x.s[m][b * x.words] & 1).wrapping_neg();
            out.s[m][b * words..(b + 1) * words].fill(v);
        }
    }
    out
}

/// Shares of byte strings across lanes: `s[m][bit * words + w]`, bit `8k + i`
/// is bit i of byte k.
#[derive(Clone)]
pub struct Wide {
    pub bits: usize,
    pub words: usize,
    pub s: [Vec<u64>; 4],
}

impl Drop for Wide {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.s);
    }
}

impl Wide {
    pub fn zero(bits: usize, words: usize) -> Wide {
        Wide {
            bits,
            words,
            s: std::array::from_fn(|_| vec![0u64; bits * words]),
        }
    }

    /// Public bytes, one string per lane.
    pub fn public(me: usize, lanes: &[Vec<u8>]) -> Wide {
        let mut x = Wide::zero(8 * lanes[0].len(), lanes.len().div_ceil(64));
        if me != PUBLIC {
            for (lane, bytes) in lanes.iter().enumerate() {
                for (k, byte) in bytes.iter().enumerate() {
                    for i in 0..8 {
                        x.s[PUBLIC][(8 * k + i) * x.words + lane / 64] |= u64::from((byte >> i) & 1) << (lane % 64);
                    }
                }
            }
        }
        x
    }

    /// XOR a lane-constant 16-byte sharing into the first 16 bytes of every lane.
    pub fn xor_shared_prefix(&mut self, me: usize, x: &Shares) {
        for m in (0..4).filter(|&m| m != me) {
            for b in 0..BITS {
                let v = (x.s[m][b * x.words] & 1).wrapping_neg();
                for w in 0..self.words {
                    self.s[m][b * self.words + w] ^= v;
                }
            }
        }
    }

    /// Overwrite the first `x.bits` bits with `x`.
    pub fn set_prefix(&mut self, x: &Wide) {
        for m in 0..4 {
            self.s[m][..x.bits * self.words].copy_from_slice(&x.s[m]);
        }
    }

    pub fn prefix(&self, bits: usize) -> Wide {
        Wide {
            bits,
            words: self.words,
            s: std::array::from_fn(|m| self.s[m][..bits * self.words].to_vec()),
        }
    }

    /// Lane `l` as a one-lane sharing.
    pub fn lane(&self, l: usize) -> Wide {
        let mut out = Wide::zero(self.bits, 1);
        for m in 0..4 {
            for b in 0..self.bits {
                out.s[m][b] = (self.s[m][b * self.words + l / 64] >> (l % 64)) & 1;
            }
        }
        out
    }
}
