//! The secret chains of key generation, in lane order.

use crate::params::{SPHX_XMSS_HEIGHT, WOTS_C_CHAIN_COUNT, WOTS_TW_CHAIN_COUNT};
use crate::stateless::{t_sl, TwKey};
use crate::wots_c::Leaf;

#[derive(Clone, Copy, Debug)]
pub enum Chain {
    Sf(Leaf, u32),
    Sl(TwKey, u32),
}

impl Chain {
    pub fn adrs_prf(&self) -> [u8; 22] {
        match self {
            Chain::Sf(leaf, i) => leaf.adrs_prf(*i),
            Chain::Sl(key, i) => key.adrs_prf(*i),
        }
    }

    pub fn adrs_hash(&self, j: u32) -> [u8; 22] {
        match self {
            Chain::Sf(leaf, i) => leaf.adrs_hash(*i, j),
            Chain::Sl(key, i) => key.adrs_hash(*i, j),
        }
    }
}

/// WOTS+C leaves, then the top layer.
pub fn keygen_chains(leaves: &[Leaf]) -> Vec<Chain> {
    let mut chains: Vec<Chain> = leaves
        .iter()
        .flat_map(|&leaf| (0..WOTS_C_CHAIN_COUNT as u32).map(move |i| Chain::Sf(leaf, i)))
        .collect();
    chains.extend(
        (0..1u32 << SPHX_XMSS_HEIGHT)
            .flat_map(|k| (0..WOTS_TW_CHAIN_COUNT as u32).map(move |i| Chain::Sl(TwKey::top(k), i))),
    );
    chains
}

pub fn top_pks_from_tips(pk_seed: &[u8; 16], tips: &[[u8; 16]]) -> Vec<[u8; 16]> {
    tips.chunks(WOTS_TW_CHAIN_COUNT)
        .enumerate()
        .map(|(k, t)| t_sl(pk_seed, &TwKey::top(k as u32), t))
        .collect()
}
