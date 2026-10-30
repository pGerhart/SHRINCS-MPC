//! From jesseposner/shachain-mpc, rev 81ca962; MIT, see LICENSE-shachain-mpc.
//! Gates in topological order, inputs on the lowest wires, outputs on the highest.

#[derive(Clone, Copy, Debug)]
pub enum Gate {
    Xor(u32, u32, u32),
    And(u32, u32, u32),
    Inv(u32, u32),
}

pub struct Circuit {
    pub n_wires: usize,
    pub inputs: Vec<usize>,
    pub outputs: Vec<usize>,
    pub gates: Vec<Gate>,
    pub n_and: usize,
}

impl Circuit {
    pub fn input_offset(&self, k: usize) -> usize {
        self.inputs[..k].iter().sum()
    }

    pub fn output_offset(&self, k: usize) -> usize {
        self.n_wires - self.outputs.iter().sum::<usize>() + self.outputs[..k].iter().sum::<usize>()
    }
}

/// Plaintext evaluation, for tests.
pub fn eval_clear(c: &Circuit, inputs: &[Vec<bool>]) -> Vec<bool> {
    assert_eq!(inputs.len(), c.inputs.len());
    let mut wires = vec![false; c.n_wires];
    let mut w = 0;
    for (input, size) in inputs.iter().zip(&c.inputs) {
        assert_eq!(input.len(), *size);
        wires[w..w + size].copy_from_slice(input);
        w += size;
    }
    for gate in &c.gates {
        match *gate {
            Gate::Xor(a, b, o) => wires[o as usize] = wires[a as usize] ^ wires[b as usize],
            Gate::And(a, b, o) => wires[o as usize] = wires[a as usize] & wires[b as usize],
            Gate::Inv(a, o) => wires[o as usize] = !wires[a as usize],
        }
    }
    let out0 = c.output_offset(0);
    wires[out0..out0 + c.outputs.iter().sum::<usize>()].to_vec()
}
