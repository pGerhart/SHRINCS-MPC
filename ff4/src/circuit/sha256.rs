//! From jesseposner/shachain-mpc, rev 81ca962; MIT, see LICENSE-shachain-mpc.
//! SHA-256 compression at 457 AND levels. Inputs are the block, then the
//! state, as big-endian integers; outputs are the last wires.

use super::builder as arith;
use super::gate::Circuit;

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2,
];

pub use super::builder::Adder;

type Word = Vec<u32>;

struct Builder {
    b: arith::Builder,
}

impl Builder {
    fn new(inputs: &[usize], adder: Adder) -> Builder {
        Builder {
            b: arith::Builder::new(inputs, adder),
        }
    }

    fn constant(&self, k: u32) -> Word {
        self.b.constant(&(0..32).map(|i| (k >> i) & 1 == 1).collect::<Vec<_>>())
    }

    fn rotr(w: &Word, n: usize) -> Word {
        (0..32).map(|i| w[(i + n) % 32]).collect()
    }

    fn shr(&self, w: &Word, n: usize) -> Word {
        (0..32)
            .map(|i| if i + n < 32 { w[i + n] } else { self.b.zero })
            .collect()
    }

    fn xor3(&mut self, a: &Word, b: &Word, c: &Word) -> Word {
        (0..32)
            .map(|i| {
                let t = self.b.xor(a[i], b[i]);
                self.b.xor(t, c[i])
            })
            .collect()
    }

    fn ch(&mut self, e: &Word, f: &Word, g: &Word) -> Word {
        (0..32)
            .map(|i| {
                let t = self.b.xor(f[i], g[i]);
                let u = self.b.and(e[i], t);
                self.b.xor(g[i], u)
            })
            .collect()
    }

    fn maj(&mut self, a: &Word, b: &Word, c: &Word) -> Word {
        (0..32).map(|i| self.b.maj(a[i], b[i], c[i])).collect()
    }

    fn sum(&mut self, terms: &[&Word]) -> Word {
        let slices: Vec<&[u32]> = terms.iter().map(|t| t.as_slice()).collect();
        self.b.sum(&slices, false)
    }

    fn cpa(&mut self, x: &Word, y: &Word) -> Word {
        self.b.cpa(x, y, false)
    }

    fn finish(self, result: &[u32]) -> Circuit {
        self.b.finish(result)
    }
}

/// Round sums start from their earliest operands.
pub fn build_circuit(adder: Adder) -> Circuit {
    let mut b = Builder::new(&[512, 256], adder);
    let msg_word = |i: usize| -> Word { (0..32).map(|k| (480 - 32 * i + k) as u32).collect() };
    let state_word = |j: usize| -> Word { (0..32).map(|k| (512 + 224 - 32 * j + k) as u32).collect() };

    let mut w: Vec<Word> = (0..16).map(msg_word).collect();
    for t in 16..64 {
        let (r7, r18, sh3) = (
            Builder::rotr(&w[t - 15], 7),
            Builder::rotr(&w[t - 15], 18),
            b.shr(&w[t - 15], 3),
        );
        let s0 = b.xor3(&r7, &r18, &sh3);
        let (r17, r19, sh10) = (
            Builder::rotr(&w[t - 2], 17),
            Builder::rotr(&w[t - 2], 19),
            b.shr(&w[t - 2], 10),
        );
        let s1 = b.xor3(&r17, &r19, &sh10);
        let (w16, w7) = (w[t - 16].clone(), w[t - 7].clone());
        w.push(b.sum(&[&w16, &w7, &s0, &s1]));
    }

    let (mut a, mut bb, mut c, mut d) = (state_word(0), state_word(1), state_word(2), state_word(3));
    let (mut e, mut f, mut g, mut h) = (state_word(4), state_word(5), state_word(6), state_word(7));
    for (t, k_t) in K.iter().enumerate() {
        let (r6, r11, r25) = (Builder::rotr(&e, 6), Builder::rotr(&e, 11), Builder::rotr(&e, 25));
        let big1 = b.xor3(&r6, &r11, &r25);
        let (r2, r13, r22) = (Builder::rotr(&a, 2), Builder::rotr(&a, 13), Builder::rotr(&a, 22));
        let big0 = b.xor3(&r2, &r13, &r22);
        let ch = b.ch(&e, &f, &g);
        let mj = b.maj(&a, &bb, &c);
        let k = b.constant(*k_t);
        let e_new = b.sum(&[&d, &h, &k, &w[t], &big1, &ch]);
        let a_new = b.sum(&[&h, &k, &w[t], &big1, &ch, &big0, &mj]);
        h = g;
        g = f;
        f = e;
        e = e_new;
        d = c;
        c = bb;
        bb = a;
        a = a_new;
    }

    let state = [a, bb, c, d, e, f, g, h];
    let mut result = vec![0u32; 256];
    for (j, v) in state.iter().enumerate() {
        let iv = state_word(j);
        let o = b.cpa(v, &iv);
        for (k, wire) in o.iter().enumerate() {
            result[224 - 32 * j + k] = *wire;
        }
    }
    b.finish(&result)
}
