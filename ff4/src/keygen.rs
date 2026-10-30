use shrincs::{Chain, W};

use crate::error::Error;
use crate::party::Party;
use crate::plan::Plan;
use crate::shares::{lanes_of, Shares};

pub struct PartyKeys {
    pub sk_seed: Shares,
    pub nodes: Vec<Shares>,
    pub tips: Vec<[u8; 16]>,
}

/// PRF and 15 chain steps on every lane, the hash check, then the tips opened.
pub fn dkg_party(p: &mut Party, plan: &Plan, pk_seed: &[u8; 16], lanes: &[Chain]) -> Result<PartyKeys, Error> {
    let n = lanes.len();
    let words = n.div_ceil(64);
    let mid = shrincs::seed_midstate(pk_seed);
    let sk_seed = p.random_secret(words);
    let prf: Vec<[u8; 22]> = lanes.iter().map(Chain::adrs_prf).collect();
    let mut nodes = vec![p.tweak_layer(plan, &mid, &prf, &sk_seed)?];
    for j in 0..(W - 1) as u32 {
        let adrs: Vec<[u8; 22]> = lanes.iter().map(|l| l.adrs_hash(j)).collect();
        let next = p.tweak_layer(plan, &mid, &adrs, nodes.last().unwrap())?;
        nodes.push(next);
    }
    p.verify()?;
    let opened = p.open_agreed(nodes.last().expect("16 layers"))?;
    let tips = lanes_of(&opened, words, n);
    Ok(PartyKeys { sk_seed, nodes, tips })
}
