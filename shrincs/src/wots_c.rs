//! WOTS+C, the one-time signature at the stateful leaves.

use crate::hash::{base_2b, f, pack, prf, tweaked};
use crate::params::*;

/// A leaf's position in the FXMSS tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Leaf {
    pub height: u8,
    pub index: u64,
    pub tree_balanced: bool,
    pub tree_depth: u8,
}

impl Leaf {
    pub fn adrs_prf(&self, chain: u32) -> [u8; 22] {
        let w1 = u32::from(self.tree_balanced) << 24 | u32::from(self.tree_depth) << 16;
        pack(self.height, self.index, SF_WOTS_C_PRF, w1, chain, 0)
    }
    pub fn adrs_hash(&self, chain: u32, hash_index: u32) -> [u8; 22] {
        pack(self.height, self.index, SF_WOTS_C_HASH, 0, chain, hash_index)
    }
    pub fn adrs_pk(&self) -> [u8; 22] {
        pack(self.height, self.index, SF_WOTS_C_PK, 0, 0, 0)
    }
    pub fn adrs_grind(&self) -> [u8; 22] {
        pack(self.height, self.index, SF_WOTS_C_GRIND, 0, 0, 0)
    }
}

pub fn t_sf(pk_seed: &[u8; 16], leaf: &Leaf, tips: &[[u8; 16]]) -> [u8; 16] {
    tweaked(pk_seed, &leaf.adrs_pk(), &tips.concat())
}

pub fn h_grind(pk_seed: &[u8; 16], leaf: &Leaf, digest: &[u8; 32], counter: u16) -> [u8; 16] {
    let mut m = [0u8; 38];
    m[..32].copy_from_slice(digest);
    m[36..38].copy_from_slice(&counter.to_be_bytes());
    tweaked(pk_seed, &leaf.adrs_grind()[..10], &m)
}

/// The lowest counter whose indexes reach the constant sum.
pub fn grind(pk_seed: &[u8; 16], leaf: &Leaf, digest: &[u8; 32]) -> Option<(u16, Vec<usize>)> {
    (0..=u16::MAX).find_map(|ctr| {
        let idx = base_2b(
            &h_grind(pk_seed, leaf, digest, ctr),
            WOTS_C_CHAIN_BITS,
            WOTS_C_CHAIN_COUNT,
        );
        (idx.iter().sum::<usize>() == WOTS_C_CONSTANT_SUM).then_some((ctr, idx))
    })
}

pub fn chain_iter(
    pk_seed: &[u8; 16],
    leaf: &Leaf,
    chain: u32,
    mut node: [u8; 16],
    start: usize,
    stop: usize,
) -> [u8; 16] {
    for j in start..stop {
        node = f(pk_seed, &leaf.adrs_hash(chain, j as u32), &node);
    }
    node
}

pub fn wots_c_pubkey_gen(sk_seed: &[u8; 16], pk_seed: &[u8; 16], leaf: &Leaf) -> [u8; 16] {
    let tips: Vec<[u8; 16]> = (0..WOTS_C_CHAIN_COUNT as u32)
        .map(|i| chain_iter(pk_seed, leaf, i, prf(pk_seed, sk_seed, &leaf.adrs_prf(i)), 0, W - 1))
        .collect();
    t_sf(pk_seed, leaf, &tips)
}

pub fn wots_c_sign(digest: &[u8; 32], sk_seed: &[u8; 16], pk_seed: &[u8; 16], leaf: &Leaf) -> Option<Vec<u8>> {
    let (ctr, idx) = grind(pk_seed, leaf, digest)?;
    let mut sig = ctr.to_be_bytes().to_vec();
    for (i, &b) in idx.iter().enumerate() {
        let sk = prf(pk_seed, sk_seed, &leaf.adrs_prf(i as u32));
        sig.extend_from_slice(&chain_iter(pk_seed, leaf, i as u32, sk, 0, b));
    }
    Some(sig)
}

pub fn wots_c_pubkey_from_sig(sig: &[u8], digest: &[u8; 32], pk_seed: &[u8; 16], leaf: &Leaf) -> Option<[u8; 16]> {
    if sig.len() != WOTS_C_SIG_SIZE {
        return None;
    }
    let ctr = u16::from_be_bytes([sig[0], sig[1]]);
    let idx = base_2b(
        &h_grind(pk_seed, leaf, digest, ctr),
        WOTS_C_CHAIN_BITS,
        WOTS_C_CHAIN_COUNT,
    );
    if idx.iter().sum::<usize>() != WOTS_C_CONSTANT_SUM {
        return None;
    }
    let tips: Vec<[u8; 16]> = idx
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            let node: [u8; 16] = sig[2 + 16 * i..2 + 16 * (i + 1)].try_into().unwrap();
            chain_iter(pk_seed, leaf, i as u32, node, b, W - 1)
        })
        .collect();
    Some(t_sf(pk_seed, leaf, &tips))
}
