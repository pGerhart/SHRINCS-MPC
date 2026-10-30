//! One Fantastic Four party: evaluation, the hash check, openings.

use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

use rand_chacha::ChaCha12Rng;
use rand_core::{Rng, SeedableRng};
use sha2::{Digest, Sha256 as HashFn};

use crate::circuit::Gate;
use crate::error::Error;
use crate::plan::Plan;
use crate::shares::{Shares, Wide, BITS, PUBLIC};

const SECRET_AT: usize = 22;

/// Cross pair {i, j}. P_a receives, the sender sends, the hasher hashes.
struct Pair {
    i: usize,
    j: usize,
    a: usize,
    b: usize,
    sender: usize,
    hasher: usize,
}

/// No ordered pair of parties carries two streams.
const PAIRS: [Pair; 6] = [
    Pair {
        i: 0,
        j: 1,
        a: 0,
        b: 1,
        sender: 2,
        hasher: 3,
    },
    Pair {
        i: 0,
        j: 2,
        a: 2,
        b: 0,
        sender: 3,
        hasher: 1,
    },
    Pair {
        i: 0,
        j: 3,
        a: 3,
        b: 0,
        sender: 1,
        hasher: 2,
    },
    Pair {
        i: 1,
        j: 2,
        a: 1,
        b: 2,
        sender: 0,
        hasher: 3,
    },
    Pair {
        i: 1,
        j: 3,
        a: 1,
        b: 3,
        sender: 2,
        hasher: 0,
    },
    Pair {
        i: 2,
        j: 3,
        a: 2,
        b: 3,
        sender: 1,
        hasher: 0,
    },
];

pub struct Party {
    pub id: usize,
    streams: [Option<ChaCha12Rng>; 4],
    tx: [Option<Sender<Vec<u64>>>; 4],
    rx: [Option<Receiver<Vec<u64>>>; 4],
    sent_hash: Vec<(usize, HashFn)>,
    recv_hash: Vec<(usize, HashFn)>,
    pub sent_bytes: u64,
    pub rounds: u64,
    pub hashing: Duration,
    /// Receive timeout.
    pub timeout: Duration,
    #[cfg(feature = "adversary")]
    pub cheat: Option<Cheat>,
}

/// Deviations for the tests.
#[cfg(feature = "adversary")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cheat {
    /// Flip a bit of the first joint message.
    FlipJoint,
    /// Send a wrong digest as hasher.
    BadDigest,
    /// Send a joint message one word short.
    ShortJoint,
    /// Send a wrong share copy in the first opening.
    BadCopy,
}

/// Four parties over channels, with stream keys from one test seed.
pub fn parties(seed: [u8; 32]) -> Vec<Party> {
    let mut txs: Vec<Vec<Option<Sender<Vec<u64>>>>> = (0..4).map(|_| vec![None, None, None, None]).collect();
    let mut rxs: Vec<Vec<Option<Receiver<Vec<u64>>>>> = (0..4).map(|_| vec![None, None, None, None]).collect();
    for from in 0..4 {
        for to in 0..4 {
            if from != to {
                let (t, r) = channel();
                txs[from][to] = Some(t);
                rxs[to][from] = Some(r);
            }
        }
    }
    let key = |m: usize| {
        let mut s = seed;
        s[31] ^= m as u8;
        s
    };
    txs.into_iter()
        .zip(rxs)
        .enumerate()
        .map(|(id, (tx, rx))| {
            let keys = std::array::from_fn(|m| (m != id).then(|| key(m)));
            Party::new(id, keys, tx.try_into().unwrap(), rx.try_into().unwrap())
        })
        .collect()
}

fn hash_words(h: &mut HashFn, v: &[u64]) {
    h.update(bytemuck::cast_slice::<u64, u8>(v));
}

impl Party {
    pub fn new(
        id: usize,
        keys: [Option<[u8; 32]>; 4],
        tx: [Option<Sender<Vec<u64>>>; 4],
        rx: [Option<Receiver<Vec<u64>>>; 4],
    ) -> Party {
        Party {
            id,
            streams: keys.map(|k| k.map(ChaCha12Rng::from_seed)),
            tx,
            rx,
            sent_hash: PAIRS
                .iter()
                .enumerate()
                .filter(|(_, p)| p.hasher == id)
                .map(|(k, _)| (k, HashFn::new()))
                .collect(),
            recv_hash: PAIRS
                .iter()
                .enumerate()
                .filter(|(_, p)| p.a == id)
                .map(|(k, _)| (k, HashFn::new()))
                .collect(),
            sent_bytes: 0,
            rounds: 0,
            hashing: Duration::ZERO,
            timeout: Duration::from_secs(600),
            #[cfg(feature = "adversary")]
            cheat: None,
        }
    }

    fn send(&mut self, to: usize, msg: Vec<u64>) -> Result<(), Error> {
        self.sent_bytes += 8 * msg.len() as u64;
        self.tx[to]
            .as_ref()
            .ok_or(Error::PeerGone(to))?
            .send(msg)
            .map_err(|_| Error::PeerGone(to))
    }

    fn recv(&mut self, from: usize) -> Result<Vec<u64>, Error> {
        self.rx[from]
            .as_ref()
            .expect("own index")
            .recv_timeout(self.timeout)
            .map_err(|_| Error::PeerGone(from))
    }

    /// Registers are `t[(reg * 4 + m) * words + w]`.
    pub fn eval(&mut self, plan: &Plan, t: &mut [u64], words: usize) -> Result<(), Error> {
        let r = self.eval_inner(plan, t, words);
        self.hang_up_on(r)
    }

    /// Close the links on abort, so peers fail at once.
    fn hang_up_on<T>(&mut self, r: Result<T, Error>) -> Result<T, Error> {
        if r.is_err() {
            self.tx = Default::default();
        }
        r
    }

    fn eval_inner(&mut self, plan: &Plan, t: &mut [u64], words: usize) -> Result<(), Error> {
        let me = self.id;
        let idx = |reg: u32, m: usize, w: usize| (reg as usize * 4 + m) * words + w;
        for r in 0..=plan.depth {
            for &(gate, [x, y, o]) in &plan.locals[r] {
                for m in (0..4).filter(|&m| m != me) {
                    for w in 0..words {
                        t[idx(o, m, w)] = match gate {
                            Gate::Xor(..) => t[idx(x, m, w)] ^ t[idx(y, m, w)],
                            _ => t[idx(x, m, w)] ^ if m == PUBLIC { !0 } else { 0 },
                        };
                    }
                }
            }
            let ands = &plan.ands[r];
            if ands.is_empty() {
                continue;
            }
            let n = ands.len() * words;
            let mut z: [Vec<u64>; 4] = std::array::from_fn(|m| if m == me { Vec::new() } else { vec![0u64; n] });
            let mut out: Vec<(usize, Vec<u64>)> = Vec::new();
            let mut hashed: Vec<(usize, Vec<u64>)> = Vec::new();
            for (k, p) in PAIRS.iter().enumerate() {
                if p.sender == me {
                    out.push((k, Vec::with_capacity(n)));
                } else if p.hasher == me {
                    hashed.push((k, Vec::with_capacity(n)));
                }
            }
            for (g, &[x, y, _]) in ands.iter().enumerate() {
                for w in 0..words {
                    let j = g * words + w;
                    for m in (0..4).filter(|&m| m != me) {
                        z[m][j] = t[idx(x, m, w)] & t[idx(y, m, w)];
                    }
                    for (k, p) in PAIRS.iter().enumerate() {
                        if p.a == me {
                            continue; // filled in from the message
                        }
                        let r = self.streams[p.a].as_mut().unwrap().next_u64();
                        z[p.a][j] ^= r;
                        if p.sender == me || p.hasher == me {
                            let v =
                                (t[idx(x, p.i, w)] & t[idx(y, p.j, w)]) ^ (t[idx(x, p.j, w)] & t[idx(y, p.i, w)]) ^ r;
                            z[p.b][j] ^= v;
                            let buf = if p.sender == me { &mut out } else { &mut hashed };
                            buf.iter_mut().find(|(kk, _)| *kk == k).unwrap().1.push(v);
                        }
                    }
                }
            }
            let th = Instant::now();
            for (k, v) in &hashed {
                let h = &mut self.sent_hash.iter_mut().find(|(kk, _)| kk == k).unwrap().1;
                hash_words(h, v);
            }
            self.hashing += th.elapsed();
            #[allow(unused_mut)]
            for (k, mut v) in out {
                #[cfg(feature = "adversary")]
                match self.cheat.take() {
                    Some(Cheat::FlipJoint) => v[0] ^= 1,
                    Some(Cheat::ShortJoint) => {
                        v.pop();
                    }
                    other => self.cheat = other,
                }
                self.send(PAIRS[k].a, v)?;
            }
            for (k, p) in PAIRS.iter().enumerate() {
                if p.a == me {
                    let v = self.recv(p.sender)?;
                    if v.len() != n {
                        return Err(Error::MessageLength);
                    }
                    let th = Instant::now();
                    hash_words(&mut self.recv_hash.iter_mut().find(|(kk, _)| *kk == k).unwrap().1, &v);
                    self.hashing += th.elapsed();
                    for j in 0..n {
                        z[p.b][j] ^= v[j];
                    }
                }
            }
            self.rounds += 1;
            for (g, &[_, _, o]) in ands.iter().enumerate() {
                for m in (0..4).filter(|&m| m != me) {
                    t[idx(o, m, 0)..idx(o, m, 0) + words].copy_from_slice(&z[m][g * words..(g + 1) * words]);
                }
            }
        }
        Ok(())
    }

    /// Compare the joint-message hashes, then agree on the outcome. Two rounds.
    pub fn verify(&mut self) -> Result<(), Error> {
        let r = self.verify_inner();
        self.hang_up_on(r)
    }

    fn verify_inner(&mut self) -> Result<(), Error> {
        let me = self.id;
        for (k, p) in PAIRS.iter().enumerate() {
            if p.hasher == me {
                let h = std::mem::take(&mut self.sent_hash.iter_mut().find(|(kk, _)| *kk == k).unwrap().1);
                #[allow(unused_mut)]
                let mut d: [u8; 32] = h.finalize().into();
                #[cfg(feature = "adversary")]
                if self.cheat == Some(Cheat::BadDigest) {
                    self.cheat = None;
                    d[0] ^= 1;
                }
                let words: Vec<u64> = d.chunks(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
                self.send(p.a, words)?;
            }
        }
        let mut ok = true;
        for (k, p) in PAIRS.iter().enumerate() {
            if p.a == me {
                let theirs = self.recv(p.hasher)?;
                let h = std::mem::take(&mut self.recv_hash.iter_mut().find(|(kk, _)| *kk == k).unwrap().1);
                let d: [u8; 32] = h.finalize().into();
                let mine: Vec<u64> = d.chunks(8).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect();
                ok &= mine == theirs;
            }
        }
        self.rounds += 1;
        for to in (0..4).filter(|&p| p != me) {
            self.send(to, vec![u64::from(ok)])?;
        }
        for from in (0..4).filter(|&p| p != me) {
            ok &= self.recv(from)?.first() == Some(&1);
        }
        self.rounds += 1;
        if ok {
            Ok(())
        } else {
            Err(Error::HashMismatch)
        }
    }

    /// Each holder of share m sends it to P_m, who needs three equal copies.
    pub fn open(&mut self, x: &Shares) -> Result<Vec<u64>, Error> {
        let r = self.open_inner(x);
        self.hang_up_on(r)
    }

    fn open_inner(&mut self, x: &Shares) -> Result<Vec<u64>, Error> {
        self.open_raw(&x.s, BITS * x.words)
    }

    /// Lane 0 of a wide sharing, opened as bytes.
    pub fn open_wide(&mut self, x: &Wide) -> Result<Vec<u8>, Error> {
        let r = self.open_raw(&x.s, x.bits * x.words);
        let v = self.hang_up_on(r)?;
        Ok((0..x.bits / 8)
            .map(|k| (0..8).fold(0u8, |b, i| b | (((v[(8 * k + i) * x.words] & 1) as u8) << i)))
            .collect())
    }

    fn open_raw(&mut self, x: &[Vec<u64>; 4], len: usize) -> Result<Vec<u64>, Error> {
        let me = self.id;
        for to in (0..4).filter(|&p| p != me) {
            #[allow(unused_mut)]
            let mut copy = x[to].clone();
            #[cfg(feature = "adversary")]
            if to == (me + 1) % 4 && self.cheat == Some(Cheat::BadCopy) {
                self.cheat = None;
                copy[0] ^= 1;
            }
            self.send(to, copy)?;
        }
        let copies = (0..4)
            .filter(|&p| p != me)
            .map(|from| self.recv(from))
            .collect::<Result<Vec<_>, _>>()?;
        self.rounds += 1;
        if copies.iter().any(|c| c.len() != len) {
            return Err(Error::MessageLength);
        }
        if copies.iter().any(|c| *c != copies[0]) {
            return Err(Error::CopiesDiffer);
        }
        let mut v = copies[0].clone();
        for m in (0..4).filter(|&m| m != me) {
            for (a, b) in v.iter_mut().zip(&x[m]) {
                *a ^= b;
            }
        }
        Ok(v)
    }

    /// [`Party::open`], then all four agree on the outcome.
    pub fn open_agreed(&mut self, x: &Shares) -> Result<Vec<u64>, Error> {
        let r = self.open_agreed_inner(x);
        self.hang_up_on(r)
    }

    fn open_agreed_inner(&mut self, x: &Shares) -> Result<Vec<u64>, Error> {
        let r = self.open_inner(x);
        let me = self.id;
        for to in (0..4).filter(|&p| p != me) {
            self.send(to, vec![u64::from(r.is_ok())])?;
        }
        let mut ok = r.is_ok();
        for from in (0..4).filter(|&p| p != me) {
            ok &= self.recv(from)?.first() == Some(&1);
        }
        self.rounds += 1;
        match r {
            Ok(v) if ok => Ok(v),
            Ok(_) => Err(Error::PeerAborted),
            Err(e) => Err(e),
        }
    }

    /// A joint random value, equal in every lane.
    pub fn random_secret(&mut self, words: usize) -> Shares {
        let mut x = Shares::zero(words);
        for m in (0..4).filter(|&m| m != self.id) {
            let rng = self.streams[m].as_mut().unwrap();
            for b in 0..BITS {
                let v = u64::from(rng.next_u32() & 1).wrapping_neg();
                x.s[m][b * words..(b + 1) * words].fill(v);
            }
        }
        x
    }

    /// SHA-256 compression per lane on a shared state and block.
    pub fn compress(&mut self, plan: &Plan, state: &Wide, block: &Wide) -> Result<Wide, Error> {
        let words = block.words;
        let me = self.id;
        let mut t = vec![0u64; plan.n_regs * 4 * words];
        let idx = |reg: u32, m: usize| (reg as usize * 4 + m) * words;
        let mut load = |input: usize, x: &Wide, bytes: usize| {
            for k in 0..bytes {
                for i in 0..8 {
                    let reg = plan.input_regs[input + 8 * (bytes - 1 - k) + i];
                    for m in (0..4).filter(|&m| m != me) {
                        t[idx(reg, m)..idx(reg, m) + words].copy_from_slice(&x.s[m][(8 * k + i) * words..][..words]);
                    }
                }
            }
        };
        load(0, block, 64);
        load(512, state, 32);
        self.eval(plan, &mut t, words)?;
        let mut out = Wide::zero(256, words);
        for k in 0..32 {
            for i in 0..8 {
                let reg = plan.output_regs[8 * (31 - k) + i];
                for m in (0..4).filter(|&m| m != me) {
                    out.s[m][(8 * k + i) * words..][..words].copy_from_slice(&t[idx(reg, m)..idx(reg, m) + words]);
                }
            }
        }
        Ok(out)
    }

    pub fn tweak_layer(&mut self, plan: &Plan, mid: &[u8; 32], adrs: &[[u8; 22]], x: &Shares) -> Result<Shares, Error> {
        let words = x.words;
        let me = self.id;
        let mut t = vec![0u64; plan.n_regs * 4 * words];
        let idx = |reg: u32, m: usize, w: usize| (reg as usize * 4 + m) * words + w;
        let blocks: Vec<[u8; 64]> = adrs.iter().map(|a| shrincs::tweak_block(a, &[0u8; 16])).collect();
        for kk in 0..64 {
            for bit in 0..8 {
                let reg = plan.input_regs[8 * (63 - kk) + bit];
                if (SECRET_AT..SECRET_AT + 16).contains(&kk) {
                    let b = 8 * (kk - SECRET_AT) + bit;
                    for m in (0..4).filter(|&m| m != me) {
                        t[idx(reg, m, 0)..idx(reg, m, 0) + words].copy_from_slice(&x.s[m][b * words..(b + 1) * words]);
                    }
                } else if me != PUBLIC {
                    for w in 0..words {
                        t[idx(reg, PUBLIC, w)] = blocks
                            .iter()
                            .skip(64 * w)
                            .take(64)
                            .enumerate()
                            .fold(0u64, |v, (lane, b)| v | u64::from((b[kk] >> bit) & 1) << lane);
                    }
                }
            }
        }
        if me != PUBLIC {
            for kk in 0..32 {
                for bit in 0..8 {
                    let reg = plan.input_regs[512 + 8 * (31 - kk) + bit];
                    let v = if (mid[kk] >> bit) & 1 == 1 { !0u64 } else { 0 };
                    t[idx(reg, PUBLIC, 0)..idx(reg, PUBLIC, 0) + words].fill(v);
                }
            }
        }
        self.eval(plan, &mut t, words)?;
        let mut out = Shares::zero(words);
        for b in 0..BITS {
            let reg = plan.output_regs[8 * (31 - b / 8) + b % 8];
            for m in (0..4).filter(|&m| m != me) {
                out.s[m][b * words..(b + 1) * words].copy_from_slice(&t[idx(reg, m, 0)..idx(reg, m, 0) + words]);
            }
        }
        Ok(out)
    }
}
