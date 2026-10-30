//! From jesseposner/shachain-mpc, rev 81ca962; MIT, see LICENSE-shachain-mpc.
//! Gates grouped by AND depth, one round per level.

use super::gate::{Circuit, Gate};

pub struct Schedule {
    pub locals: Vec<Vec<usize>>,
    pub ands: Vec<Vec<usize>>,
    pub depth: usize,
}
impl Schedule {
    pub fn new(c: &Circuit) -> Self {
        let mut avail = vec![0usize; c.n_wires];
        let mut depth = 0;
        let mut locals: Vec<Vec<usize>> = Vec::new();
        let mut ands: Vec<Vec<usize>> = Vec::new();
        let slot = |v: &mut Vec<Vec<usize>>, r: usize, g: usize| {
            if v.len() <= r {
                v.resize(r + 1, Vec::new());
            }
            v[r].push(g);
        };
        for (gi, gate) in c.gates.iter().enumerate() {
            match *gate {
                Gate::Xor(x, y, o) => {
                    let r = avail[x as usize].max(avail[y as usize]);
                    slot(&mut locals, r, gi);
                    avail[o as usize] = r;
                }
                Gate::Inv(x, o) => {
                    let r = avail[x as usize];
                    slot(&mut locals, r, gi);
                    avail[o as usize] = r;
                }
                Gate::And(x, y, o) => {
                    let r = avail[x as usize].max(avail[y as usize]);
                    slot(&mut locals, r, gi);
                    avail[o as usize] = r + 1;
                    depth = depth.max(r + 1);
                }
            }
        }
        locals.resize(depth + 1, Vec::new());
        ands.resize(depth + 1, Vec::new());
        for r in 0..=depth {
            let (l, a) = std::mem::take(&mut locals[r])
                .into_iter()
                .partition(|&gi| !matches!(c.gates[gi], Gate::And(..)));
            locals[r] = l;
            ands[r] = a;
        }
        Schedule { locals, ands, depth }
    }
}
