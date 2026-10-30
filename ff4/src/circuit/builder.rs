//! From jesseposner/shachain-mpc, rev 81ca962; MIT, see LICENSE-shachain-mpc.
//! A gate builder with constant folding, carry-save and prefix adders.

use super::gate::{Circuit, Gate};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Adder {
    /// 1 + ceil(log2 n) AND levels.
    Sklansky,
    /// Fewer gates, about twice the levels.
    BrentKung,
    /// n - 1 levels.
    Ripple,
}

pub struct Builder {
    inputs: Vec<usize>,
    gates: Vec<Gate>,
    next: u32,
    pub zero: u32,
    pub one: u32,
    pub adder: Adder,
}

impl Builder {
    pub fn new(inputs: &[usize], adder: Adder) -> Builder {
        let next = inputs.iter().sum::<usize>() as u32;
        let mut b = Builder {
            inputs: inputs.to_vec(),
            gates: Vec::new(),
            next,
            zero: 0,
            one: 0,
            adder,
        };
        b.zero = b.emit(|o| Gate::Xor(0, 0, o));
        let zero = b.zero;
        b.one = b.emit(|o| Gate::Inv(zero, o));
        b
    }

    fn emit(&mut self, gate: impl FnOnce(u32) -> Gate) -> u32 {
        let o = self.next;
        self.next += 1;
        self.gates.push(gate(o));
        o
    }

    pub fn input_offset(&self, k: usize) -> u32 {
        self.inputs[..k].iter().sum::<usize>() as u32
    }

    pub fn input(&self, k: usize) -> Vec<u32> {
        let off = self.input_offset(k);
        (off..off + self.inputs[k] as u32).collect()
    }

    pub fn xor(&mut self, a: u32, b: u32) -> u32 {
        if a == b {
            self.zero
        } else if a == self.zero {
            b
        } else if b == self.zero {
            a
        } else if a == self.one {
            self.inv(b)
        } else if b == self.one {
            self.inv(a)
        } else {
            self.emit(|o| Gate::Xor(a, b, o))
        }
    }

    pub fn and(&mut self, a: u32, b: u32) -> u32 {
        if a == self.zero || b == self.zero {
            self.zero
        } else if a == self.one || a == b {
            b
        } else if b == self.one {
            a
        } else {
            self.emit(|o| Gate::And(a, b, o))
        }
    }

    pub fn inv(&mut self, a: u32) -> u32 {
        if a == self.zero {
            self.one
        } else if a == self.one {
            self.zero
        } else {
            self.emit(|o| Gate::Inv(a, o))
        }
    }

    pub fn constant(&self, bits: &[bool]) -> Vec<u32> {
        bits.iter().map(|&b| if b { self.one } else { self.zero }).collect()
    }

    fn bit(&self, v: &[u32], i: usize) -> u32 {
        if i < v.len() {
            v[i]
        } else {
            self.zero
        }
    }

    pub fn maj(&mut self, a: u32, b: u32, c: u32) -> u32 {
        let ab = self.xor(a, b);
        let bc = self.xor(b, c);
        let t = self.and(ab, bc);
        self.xor(b, t)
    }

    /// x + y + z == s + c in one AND level; `exact` keeps the top carry.
    pub fn csa(&mut self, x: &[u32], y: &[u32], z: &[u32], exact: bool) -> (Vec<u32>, Vec<u32>) {
        let n = x.len().max(y.len()).max(z.len());
        let s: Vec<u32> = (0..n)
            .map(|i| {
                let (xi, yi, zi) = (self.bit(x, i), self.bit(y, i), self.bit(z, i));
                let t = self.xor(xi, yi);
                self.xor(t, zi)
            })
            .collect();
        let mut c = vec![self.zero; if exact { n + 1 } else { n }];
        for i in 0..if exact { n } else { n - 1 } {
            let (xi, yi, zi) = (self.bit(x, i), self.bit(y, i), self.bit(z, i));
            c[i + 1] = self.maj(xi, yi, zi);
        }
        (s, c)
    }

    /// `exact` appends the carry out.
    pub fn cpa(&mut self, x: &[u32], y: &[u32], exact: bool) -> Vec<u32> {
        match self.adder {
            Adder::Ripple => self.cpa_ripple(x, y, exact),
            Adder::Sklansky => self.cpa_sklansky(x, y, exact),
            Adder::BrentKung => self.cpa_brent_kung(x, y, exact),
        }
    }

    fn cpa_ripple(&mut self, x: &[u32], y: &[u32], exact: bool) -> Vec<u32> {
        let n = x.len().max(y.len());
        let mut carry = self.zero;
        let mut s = Vec::with_capacity(n + 1);
        for i in 0..n {
            let (xi, yi) = (self.bit(x, i), self.bit(y, i));
            let axb = self.xor(xi, yi);
            s.push(self.xor(axb, carry));
            if i < n - 1 || exact {
                let xc = self.xor(xi, carry);
                let yc = self.xor(yi, carry);
                let t = self.and(xc, yc);
                carry = self.xor(carry, t);
            }
        }
        if exact {
            s.push(carry);
        }
        s
    }

    fn generate_propagate(&mut self, x: &[u32], y: &[u32]) -> (Vec<u32>, Vec<u32>) {
        let n = x.len().max(y.len());
        let g = (0..n).map(|i| self.and(self.bit(x, i), self.bit(y, i))).collect();
        let p = (0..n).map(|i| self.xor(self.bit(x, i), self.bit(y, i))).collect();
        (g, p)
    }

    /// Sklansky prefix over spans 1, 2, 4, ...; the top prefix is the carry out.
    fn cpa_sklansky(&mut self, x: &[u32], y: &[u32], exact: bool) -> Vec<u32> {
        let (mut g, mut p) = self.generate_propagate(x, y);
        let n = g.len();
        let sum_p = p.clone();
        let mut span = 1;
        while span < n {
            let last = 2 * span >= n;
            let mut j = 0;
            while j < n {
                let mid = j + span - 1;
                for i in (mid + 1)..(j + 2 * span).min(n) {
                    if i == n - 1 && !exact {
                        continue;
                    }
                    let t = self.and(p[i], g[mid]);
                    g[i] = self.xor(g[i], t);
                    if !last {
                        p[i] = self.and(p[i], p[mid]);
                    }
                }
                j += 2 * span;
            }
            span *= 2;
        }
        self.sum_from_carries(&sum_p, &g, exact)
    }

    fn cpa_brent_kung(&mut self, x: &[u32], y: &[u32], exact: bool) -> Vec<u32> {
        assert!(!exact, "Brent-Kung is built for the modular adds of the hash");
        let (mut g, mut p) = self.generate_propagate(x, y);
        let n = g.len();
        let sum_p = p.clone();
        let mut span = 1;
        while 2 * span - 1 < n {
            let mut i = 2 * span - 1;
            while i < n {
                let lo = i - span;
                let t = self.and(p[i], g[lo]);
                g[i] = self.xor(g[i], t);
                p[i] = self.and(p[i], p[lo]);
                i += 2 * span;
            }
            span *= 2;
        }
        let mut span = span / 4;
        while span >= 1 {
            let mut i = 3 * span - 1;
            while i < n {
                let lo = i - span;
                let t = self.and(p[i], g[lo]);
                g[i] = self.xor(g[i], t);
                p[i] = self.and(p[i], p[lo]);
                i += 2 * span;
            }
            span /= 2;
        }
        self.sum_from_carries(&sum_p, &g, false)
    }

    fn sum_from_carries(&mut self, p: &[u32], g: &[u32], exact: bool) -> Vec<u32> {
        let n = p.len();
        let mut s = Vec::with_capacity(n + 1);
        s.push(p[0]);
        for i in 1..n {
            s.push(self.xor(p[i], g[i - 1]));
        }
        if exact {
            s.push(g[n - 1]);
        }
        s
    }

    /// Earliest operands first.
    pub fn sum(&mut self, terms: &[&[u32]], exact: bool) -> Vec<u32> {
        let (mut s, mut c) = self.csa(terms[0], terms[1], terms[2], exact);
        for t in &terms[3..] {
            let r = self.csa(&s, &c, t, exact);
            s = r.0;
            c = r.1;
        }
        self.cpa(&s, &c, exact)
    }

    /// Copies onto final wires, so outputs come last.
    pub fn finish(mut self, result: &[u32]) -> Circuit {
        let zero = self.zero;
        let outs: Vec<u32> = result.iter().map(|&w| self.emit(|o| Gate::Xor(w, zero, o))).collect();
        debug_assert_eq!(*outs.last().unwrap() as usize, self.next as usize - 1);
        let n_and = self.gates.iter().filter(|g| matches!(g, Gate::And(..))).count();
        Circuit {
            n_wires: self.next as usize,
            inputs: self.inputs,
            outputs: vec![result.len()],
            gates: self.gates,
            n_and,
        }
    }
}
