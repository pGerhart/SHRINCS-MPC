//! Stateful and stateless signing.

use shrincs::{TwKey, FORS_COUNT, FORS_HEIGHT, SPHX_XMSS_HEIGHT, W, WOTS_C_CHAIN_COUNT, WOTS_TW_CHAIN_COUNT};

use crate::error::Error;
use crate::hmac::PrfKeys;
use crate::party::Party;
use crate::plan::Plan;
use crate::shares::{broadcast, gather, lanes_of, select, sub_lanes, Shares};

/// How R is drawn.
#[derive(Clone, Copy)]
pub enum R<'a> {
    /// A joint random value.
    Fast,
    /// The BIP's `PRF_msg`.
    Exact(&'a PrfKeys),
}

/// Key material for signing. Without `nodes` the chains are recomputed.
pub struct Key<'a> {
    pub sk_seed: &'a Shares,
    pub nodes: Option<&'a [Shares]>,
    pub top_offset: usize,
    pub top_pks: &'a [[u8; 16]],
}

fn coin(p: &mut Party) -> Result<[u8; 16], Error> {
    let c = p.random_secret(1);
    Ok(lanes_of(&p.open(&c)?, 1, 1)[0])
}

/// PRF and chain steps up to `top` on `chains`, from `sk_seed`.
fn chains_to(
    p: &mut Party,
    plan: &Plan,
    sk_seed: &Shares,
    pk_seed: &[u8; 16],
    chains: &[shrincs::Chain],
    top: usize,
) -> Result<Vec<Shares>, Error> {
    let mid = shrincs::seed_midstate(pk_seed);
    let prf: Vec<[u8; 22]> = chains.iter().map(shrincs::Chain::adrs_prf).collect();
    let mut nodes = vec![p.tweak_layer(plan, &mid, &prf, &broadcast(sk_seed, chains.len().div_ceil(64)))?];
    for j in 0..top as u32 {
        let adrs: Vec<[u8; 22]> = chains.iter().map(|c| c.adrs_hash(j)).collect();
        let next = p.tweak_layer(plan, &mid, &adrs, nodes.last().expect("PRF layer"))?;
        nodes.push(next);
    }
    Ok(nodes)
}

/// `leaf_lane` is the leaf's first lane in key generation. Returns R and the
/// WOTS+C signature.
pub fn sign_sf(
    p: &mut Party,
    plan: &Plan,
    key: &Key,
    leaf: &shrincs::Leaf,
    leaf_lane: usize,
    pk_seed: &[u8; 16],
    sf_root: &[u8; 16],
    bound: &[u8],
    r: R,
) -> Result<([u8; 16], Vec<u8>), Error> {
    let r = match r {
        R::Fast => coin(p)?,
        R::Exact(k) => p.hmac_open(plan, &k.sf, &shrincs::prf_msg_sf_input(pk_seed, leaf, bound))?,
    };
    let digest = shrincs::h_msg_sf(&r, pk_seed, sf_root, leaf, bound);
    let (ctr, idx) = shrincs::grind(pk_seed, leaf, &digest).ok_or(Error::Grinding)?;
    let nodes: Vec<Shares> = match key.nodes {
        Some(all) => all
            .iter()
            .map(|n| sub_lanes(n, leaf_lane, WOTS_C_CHAIN_COUNT))
            .collect(),
        None => {
            let chains: Vec<shrincs::Chain> = (0..WOTS_C_CHAIN_COUNT as u32)
                .map(|i| shrincs::Chain::Sf(*leaf, i))
                .collect();
            let top = *idx.iter().max().expect("32 chains");
            let nodes = chains_to(p, plan, key.sk_seed, pk_seed, &chains, top)?;
            p.verify()?;
            nodes
        }
    };
    let vals = lanes_of(&p.open(&select(&nodes, &idx))?, 1, WOTS_C_CHAIN_COUNT);
    let mut sig = ctr.to_be_bytes().to_vec();
    for v in vals {
        sig.extend_from_slice(&v);
    }
    Ok((r, sig))
}

/// Hashes the FORS leaves and the selected lower XMSS trees, opens their
/// public nodes, then the signature values.
pub fn sign_sl(
    p: &mut Party,
    plan: &Plan,
    key: &Key,
    pk_seed: &[u8; 16],
    sl_root: &[u8; 16],
    sf_root: &[u8; 16],
    msg: &[u8],
    ctx: &[u8],
    r: R,
) -> Result<Vec<u8>, Error> {
    let m = shrincs::sl_message(ctx, sf_root, msg).map_err(|_| Error::Context)?;
    let r = match r {
        R::Fast => coin(p)?,
        R::Exact(k) => p.hmac_open(plan, &k.sl, &[&pk_seed[..], &m].concat())?,
    };
    let sl = shrincs::sl_plan(&r, pk_seed, sl_root, &m);

    let per_tree = (1usize << SPHX_XMSS_HEIGHT) * WOTS_TW_CHAIN_COUNT;
    let lower = &sl.layers[..4];
    let mut ht: Vec<shrincs::Chain> = lower
        .iter()
        .flat_map(|k| {
            (0..1u32 << SPHX_XMSS_HEIGHT).flat_map(move |kp| {
                (0..WOTS_TW_CHAIN_COUNT as u32).map(move |c| shrincs::Chain::Sl(TwKey { keypair: kp, ..*k }, c))
            })
        })
        .collect();
    let n_lower = ht.len();
    if key.nodes.is_none() {
        ht.extend((0..WOTS_TW_CHAIN_COUNT as u32).map(|c| shrincs::Chain::Sl(sl.layers[4], c)));
    }
    let n_ht = ht.len();
    let n_fors = FORS_COUNT << FORS_HEIGHT;
    let mid = shrincs::seed_midstate(pk_seed);

    let mut adrs: Vec<[u8; 22]> = ht.iter().map(shrincs::Chain::adrs_prf).collect();
    adrs.extend((0..n_fors as u32).map(|i| sl.fors.adrs_prf(i)));
    let out0 = p.tweak_layer(plan, &mid, &adrs, &broadcast(key.sk_seed, (n_ht + n_fors).div_ceil(64)))?;
    let mut adrs: Vec<[u8; 22]> = ht.iter().map(|c| c.adrs_hash(0)).collect();
    adrs.extend((0..n_fors as u32).map(|i| sl.fors.adrs_tree(0, i)));
    let out1 = p.tweak_layer(plan, &mid, &adrs, &out0)?;
    let fors_pre = sub_lanes(&out0, n_ht, n_fors);
    let fors_leaf = sub_lanes(&out1, n_ht, n_fors);
    let mut nodes = vec![sub_lanes(&out0, 0, n_ht), sub_lanes(&out1, 0, n_ht)];
    drop((out0, out1));
    for j in 1..(W - 1) as u32 {
        let adrs: Vec<[u8; 22]> = ht.iter().map(|c| c.adrs_hash(j)).collect();
        let next = p.tweak_layer(plan, &mid, &adrs, nodes.last().expect("two layers"))?;
        nodes.push(next);
    }
    p.verify()?;

    let fors_leaves = lanes_of(&p.open(&fors_leaf)?, fors_leaf.words, n_fors);
    let tips = lanes_of(
        &p.open(&sub_lanes(nodes.last().expect("16 layers"), 0, n_lower))?,
        n_lower.div_ceil(64),
        n_lower,
    );
    let mut tree_pks: Vec<Vec<[u8; 16]>> = lower
        .iter()
        .enumerate()
        .map(|(j, k)| {
            tips[j * per_tree..(j + 1) * per_tree]
                .chunks(WOTS_TW_CHAIN_COUNT)
                .enumerate()
                .map(|(kp, t)| {
                    shrincs::t_sl(
                        pk_seed,
                        &TwKey {
                            keypair: kp as u32,
                            ..*k
                        },
                        t,
                    )
                })
                .collect()
        })
        .collect();
    tree_pks.push(key.top_pks.to_vec());

    // The layer messages depend only on public trees, so a dry run yields the indexes.
    let mut wanted: Vec<Vec<usize>> = Vec::new();
    let placeholder = vec![[0u8; 16]; FORS_COUNT];
    shrincs::shrincs_sl_signature(&r, pk_seed, &sl, &fors_leaves, &placeholder, &tree_pks, |_, idx| {
        wanted.push(idx.to_vec());
        vec![[0u8; 16]; idx.len()]
    });
    let mut src: Vec<(&Shares, usize)> = shrincs::fors_indexes(&sl.fors_digest)
        .iter()
        .map(|&i| (&fors_pre, i as usize))
        .collect();
    for (j, idx) in wanted.iter().enumerate() {
        let kp = sl.layers[j].keypair as usize;
        for (c, &b) in idx.iter().enumerate() {
            src.push(match (j, key.nodes) {
                (0..4, _) => (&nodes[b], j * per_tree + kp * WOTS_TW_CHAIN_COUNT + c),
                (_, Some(stored)) => (&stored[b], key.top_offset + kp * WOTS_TW_CHAIN_COUNT + c),
                (_, None) => (&nodes[b], n_lower + c),
            });
        }
    }
    let opened = gather(&src);
    let vals = lanes_of(&p.open(&opened)?, opened.words, src.len());
    let (pre, chains) = vals.split_at(FORS_COUNT);
    Ok(shrincs::shrincs_sl_signature(
        &r,
        pk_seed,
        &sl,
        &fors_leaves,
        pre,
        &tree_pks,
        |j, idx| chains[j * WOTS_TW_CHAIN_COUNT..j * WOTS_TW_CHAIN_COUNT + idx.len()].to_vec(),
    ))
}
