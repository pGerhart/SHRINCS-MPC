//! The circuit on registers, each freed after its wire's last use.

use crate::circuit::{Circuit, Gate, Schedule};

pub struct Plan {
    pub n_regs: usize,
    pub depth: usize,
    pub n_and: usize,
    pub(crate) locals: Vec<Vec<(Gate, [u32; 3])>>,
    pub(crate) ands: Vec<Vec<[u32; 3]>>,
    pub input_regs: Vec<u32>,
    pub output_regs: Vec<u32>,
}

impl Plan {
    pub fn new(c: &Circuit, s: &Schedule) -> Plan {
        let n_in: usize = c.inputs.iter().sum();
        let n_out: usize = c.outputs.iter().sum();
        let out0 = c.n_wires - n_out;
        // An AND level reads all inputs before writing any output.
        let mut last = vec![0usize; c.n_wires];
        let mut pos = 0usize;
        for r in 0..=s.depth {
            for &g in &s.locals[r] {
                pos += 1;
                match c.gates[g] {
                    Gate::Xor(x, y, _) => {
                        last[x as usize] = pos;
                        last[y as usize] = pos;
                    }
                    Gate::Inv(x, _) => last[x as usize] = pos,
                    Gate::And(..) => unreachable!(),
                }
            }
            pos += 1;
            for &g in &s.ands[r] {
                if let Gate::And(x, y, _) = c.gates[g] {
                    last[x as usize] = pos;
                    last[y as usize] = pos;
                }
            }
        }
        for l in last.iter_mut().skip(out0) {
            *l = usize::MAX;
        }

        let mut reg = vec![u32::MAX; c.n_wires];
        let mut free: Vec<u32> = Vec::new();
        let mut n_regs = 0u32;
        let mut alloc = |free: &mut Vec<u32>| {
            free.pop().unwrap_or_else(|| {
                n_regs += 1;
                n_regs - 1
            })
        };
        for w in reg.iter_mut().take(n_in) {
            *w = alloc(&mut free);
        }
        let mut locals = Vec::with_capacity(s.depth + 1);
        let mut ands = Vec::with_capacity(s.depth + 1);
        let mut pos = 0usize;
        for r in 0..=s.depth {
            let mut lv = Vec::with_capacity(s.locals[r].len());
            for &g in &s.locals[r] {
                pos += 1;
                let (ins, o): (Vec<u32>, u32) = match c.gates[g] {
                    Gate::Xor(x, y, o) => (vec![x, y], o),
                    Gate::Inv(x, o) => (vec![x], o),
                    Gate::And(..) => unreachable!(),
                };
                let rx: Vec<u32> = ins.iter().map(|&w| reg[w as usize]).collect();
                for &w in &ins {
                    if last[w as usize] == pos && !free.contains(&reg[w as usize]) {
                        free.push(reg[w as usize]);
                    }
                }
                reg[o as usize] = alloc(&mut free);
                lv.push((c.gates[g], [rx[0], *rx.get(1).unwrap_or(&0), reg[o as usize]]));
            }
            pos += 1;
            let mut av = Vec::with_capacity(s.ands[r].len());
            let mut outs = Vec::with_capacity(s.ands[r].len());
            for &g in &s.ands[r] {
                if let Gate::And(x, y, o) = c.gates[g] {
                    av.push([reg[x as usize], reg[y as usize], 0]);
                    outs.push(o);
                }
            }
            for &g in &s.ands[r] {
                if let Gate::And(x, y, _) = c.gates[g] {
                    for w in [x, y] {
                        if last[w as usize] == pos && !free.contains(&reg[w as usize]) {
                            free.push(reg[w as usize]);
                        }
                    }
                }
            }
            for (k, o) in outs.into_iter().enumerate() {
                reg[o as usize] = alloc(&mut free);
                av[k][2] = reg[o as usize];
            }
            locals.push(lv);
            ands.push(av);
        }
        Plan {
            n_regs: n_regs as usize,
            depth: s.depth,
            n_and: c.n_and,
            locals,
            ands,
            input_regs: reg[..n_in].to_vec(),
            output_regs: reg[out0..].to_vec(),
        }
    }
}
