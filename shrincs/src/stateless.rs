//! The stateless path: FORS and a hypertree of WOTS-TW keys. Key generation
//! needs only the top layer.

use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::hash::{base_2b, f, h, pack, prf, tweaked};
use crate::params::*;

#[derive(Clone, Copy, Debug)]
pub struct TwKey {
    pub layer: u8,
    pub tree: u64,
    pub keypair: u32,
}

impl TwKey {
    /// Keypair of the top tree.
    pub fn top(keypair: u32) -> TwKey {
        TwKey {
            layer: SPHX_TOP_LAYER,
            tree: 0,
            keypair,
        }
    }
    pub fn adrs_prf(&self, chain: u32) -> [u8; 22] {
        pack(self.layer, self.tree, SL_WOTS_TW_PRF, self.keypair, chain, 0)
    }
    pub fn adrs_hash(&self, chain: u32, hash_index: u32) -> [u8; 22] {
        pack(self.layer, self.tree, SL_WOTS_TW_HASH, self.keypair, chain, hash_index)
    }
    pub fn adrs_pk(&self) -> [u8; 22] {
        pack(self.layer, self.tree, SL_WOTS_TW_PK, self.keypair, 0, 0)
    }
}

pub fn t_sl(pk_seed: &[u8; 16], key: &TwKey, tips: &[[u8; 16]]) -> [u8; 16] {
    tweaked(pk_seed, &key.adrs_pk(), &tips.concat())
}

pub fn sl_root_from_leaves(pk_seed: &[u8; 16], leaves: &[[u8; 16]]) -> [u8; 16] {
    xmss_levels(pk_seed, SPHX_TOP_LAYER, 0, leaves).last().unwrap()[0]
}

/// Leaves first.
pub fn xmss_levels(pk_seed: &[u8; 16], layer: u8, tree: u64, leaves: &[[u8; 16]]) -> Vec<Vec<[u8; 16]>> {
    let mut levels = vec![leaves.to_vec()];
    for height in 1..=SPHX_XMSS_HEIGHT {
        let next = levels
            .last()
            .unwrap()
            .chunks(2)
            .enumerate()
            .map(|(i, p)| {
                h(
                    pk_seed,
                    &pack(layer, tree, SL_XMSS_TREE, 0, height, i as u32),
                    &p[0],
                    &p[1],
                )
            })
            .collect();
        levels.push(next);
    }
    levels
}

pub fn wots_tw_pubkey_gen(sk_seed: &[u8; 16], pk_seed: &[u8; 16], key: &TwKey) -> [u8; 16] {
    let tips: Vec<[u8; 16]> = (0..WOTS_TW_CHAIN_COUNT as u32)
        .map(|i| {
            let mut node = prf(pk_seed, sk_seed, &key.adrs_prf(i));
            for j in 0..(W - 1) as u32 {
                node = f(pk_seed, &key.adrs_hash(i, j), &node);
            }
            node
        })
        .collect();
    t_sl(pk_seed, key, &tips)
}

pub fn sl_root(sk_seed: &[u8; 16], pk_seed: &[u8; 16]) -> [u8; 16] {
    let leaves: Vec<[u8; 16]> = (0..1u32 << SPHX_XMSS_HEIGHT)
        .map(|k| wots_tw_pubkey_gen(sk_seed, pk_seed, &TwKey::top(k)))
        .collect();
    sl_root_from_leaves(pk_seed, &leaves)
}

#[derive(Clone, Copy, Debug)]
pub struct Fors {
    pub tree: u64,
    pub keypair: u32,
}

impl Fors {
    pub fn adrs_prf(&self, index: u32) -> [u8; 22] {
        pack(0, self.tree, SL_FORS_PRF, self.keypair, 0, index)
    }
    pub fn adrs_tree(&self, height: u32, index: u32) -> [u8; 22] {
        pack(0, self.tree, SL_FORS_TREE, self.keypair, height, index)
    }
    fn adrs_roots(&self) -> [u8; 22] {
        pack(0, self.tree, SL_FORS_ROOTS, self.keypair, 0, 0)
    }

    /// Leaves first.
    pub fn tree_levels(&self, pk_seed: &[u8; 16], t: usize, leaves: &[[u8; 16]]) -> Vec<Vec<[u8; 16]>> {
        let mut levels = vec![leaves.to_vec()];
        for height in 1..=FORS_HEIGHT {
            let base = (t as u32) << (FORS_HEIGHT - height);
            let next = levels
                .last()
                .unwrap()
                .chunks(2)
                .enumerate()
                .map(|(i, p)| h(pk_seed, &self.adrs_tree(height, base + i as u32), &p[0], &p[1]))
                .collect();
            levels.push(next);
        }
        levels
    }
}

/// `H_msg_sl` split into FORS digest, tree index and keypair index.
pub fn slh_digest(
    r: &[u8; 16],
    pk_seed: &[u8; 16],
    sl_root: &[u8; 16],
    msg: &[u8],
) -> ([u8; FORS_DIGEST_SIZE], u64, u32) {
    let mut inner = Sha256::new();
    inner.update(r);
    inner.update(pk_seed);
    inner.update(sl_root);
    inner.update(msg);
    let inner: [u8; 32] = inner.finalize().into();
    let mut outer = Sha256::new();
    outer.update(r);
    outer.update(pk_seed);
    outer.update(inner);
    outer.update([0u8; 4]);
    let d: [u8; 32] = outer.finalize().into();
    let mut tree = [0u8; 8];
    tree[3..].copy_from_slice(&d[17..22]);
    let tree_index = u64::from_be_bytes(tree) % (1 << (SPHX_XMSS_HEIGHT * 4));
    let leaf_index = u32::from(u16::from_be_bytes([d[22], d[23]])) % (1 << SPHX_XMSS_HEIGHT);
    (d[..FORS_DIGEST_SIZE].try_into().unwrap(), tree_index, leaf_index)
}

/// Version, `ctx`, `sf_root` and message.
pub fn sl_message(ctx: &[u8], sf_root: &[u8; 16], msg: &[u8]) -> Result<Vec<u8>, Error> {
    let mut m = vec![0u8, u8::try_from(ctx.len()).map_err(|_| Error::Context)?];
    m.extend_from_slice(ctx);
    m.extend_from_slice(sf_root);
    m.extend_from_slice(msg);
    Ok(m)
}

/// With a 3-digit checksum.
pub fn wots_tw_indexes(msg: &[u8; 16]) -> Vec<usize> {
    let mut idx = base_2b(msg, WOTS_C_CHAIN_BITS, 32);
    let checksum = 32 * (W - 1) - idx.iter().sum::<usize>();
    for i in (0..3).rev() {
        idx.push((checksum >> (4 * i)) & 15);
    }
    idx
}

pub fn fors_indexes(digest: &[u8; FORS_DIGEST_SIZE]) -> Vec<u32> {
    base_2b(digest, FORS_HEIGHT as usize, FORS_COUNT)
        .into_iter()
        .enumerate()
        .map(|(i, x)| ((i as u32) << FORS_HEIGHT) + x as u32)
        .collect()
}

pub struct SlPlan {
    pub fors: Fors,
    pub fors_digest: [u8; FORS_DIGEST_SIZE],
    pub layers: Vec<TwKey>,
}

pub fn sl_plan(r: &[u8; 16], pk_seed: &[u8; 16], sl_root: &[u8; 16], sl_msg: &[u8]) -> SlPlan {
    let (fors_digest, tree_index, leaf_index) = slh_digest(r, pk_seed, sl_root, sl_msg);
    let mut layers = Vec::with_capacity(SPHX_LAYER_COUNT);
    let (mut tree, mut leaf) = (tree_index, leaf_index);
    for layer in 0..SPHX_LAYER_COUNT as u8 {
        layers.push(TwKey {
            layer,
            tree,
            keypair: leaf,
        });
        leaf = (tree % (1 << SPHX_XMSS_HEIGHT)) as u32;
        tree >>= SPHX_XMSS_HEIGHT;
    }
    SlPlan {
        fors: Fors {
            tree: tree_index,
            keypair: leaf_index,
        },
        fors_digest,
        layers,
    }
}

/// `chain_values(layer, indexes)` supplies the signing key's chain values once
/// that layer's message is known.
pub fn shrincs_sl_signature(
    r: &[u8; 16],
    pk_seed: &[u8; 16],
    plan: &SlPlan,
    fors_leaves: &[[u8; 16]],
    fors_preimages: &[[u8; 16]],
    tree_pks: &[Vec<[u8; 16]>],
    mut chain_values: impl FnMut(usize, &[usize]) -> Vec<[u8; 16]>,
) -> Vec<u8> {
    let mut sig = vec![FXMSS_HEIGHT];
    sig.extend_from_slice(r);
    let leaves_per_tree = 1usize << FORS_HEIGHT;
    let mut roots = Vec::with_capacity(16 * FORS_COUNT);
    for (t, &index) in fors_indexes(&plan.fors_digest).iter().enumerate() {
        let levels = plan
            .fors
            .tree_levels(pk_seed, t, &fors_leaves[t * leaves_per_tree..(t + 1) * leaves_per_tree]);
        sig.extend_from_slice(&fors_preimages[t]);
        let local = index as usize - t * leaves_per_tree;
        for (j, level) in levels.iter().take(FORS_HEIGHT as usize).enumerate() {
            sig.extend_from_slice(&level[(local >> j) ^ 1]);
        }
        roots.extend_from_slice(&levels.last().unwrap()[0]);
    }
    let mut message = tweaked(pk_seed, &plan.fors.adrs_roots(), &roots);
    for (j, key) in plan.layers.iter().enumerate() {
        let idx = wots_tw_indexes(&message);
        for v in chain_values(j, &idx) {
            sig.extend_from_slice(&v);
        }
        let levels = xmss_levels(pk_seed, key.layer, key.tree, &tree_pks[j]);
        for (k, level) in levels.iter().take(SPHX_XMSS_HEIGHT as usize).enumerate() {
            sig.extend_from_slice(&level[((key.keypair as usize) >> k) ^ 1]);
        }
        message = levels.last().unwrap()[0];
    }
    sig
}

/// Plaintext reference for the MPC.
pub fn shrincs_sign_sl(
    msg: &[u8],
    ctx: &[u8],
    r: &[u8; 16],
    sk_seed: &[u8; 16],
    pk_seed: &[u8; 16],
    sl_root: &[u8; 16],
    sf_root: &[u8; 16],
) -> Result<Vec<u8>, Error> {
    let plan = sl_plan(r, pk_seed, sl_root, &sl_message(ctx, sf_root, msg)?);
    let fors_leaves: Vec<[u8; 16]> = (0..(FORS_COUNT << FORS_HEIGHT) as u32)
        .map(|i| {
            f(
                pk_seed,
                &plan.fors.adrs_tree(0, i),
                &prf(pk_seed, sk_seed, &plan.fors.adrs_prf(i)),
            )
        })
        .collect();
    let pre: Vec<[u8; 16]> = fors_indexes(&plan.fors_digest)
        .iter()
        .map(|&i| prf(pk_seed, sk_seed, &plan.fors.adrs_prf(i)))
        .collect();
    let tree_pks: Vec<Vec<[u8; 16]>> = plan
        .layers
        .iter()
        .map(|key| {
            (0..1u32 << SPHX_XMSS_HEIGHT)
                .map(|k| wots_tw_pubkey_gen(sk_seed, pk_seed, &TwKey { keypair: k, ..*key }))
                .collect()
        })
        .collect();
    Ok(shrincs_sl_signature(
        r,
        pk_seed,
        &plan,
        &fors_leaves,
        &pre,
        &tree_pks,
        |j, idx| {
            let key = plan.layers[j];
            idx.iter()
                .enumerate()
                .map(|(i, &b)| {
                    let mut node = prf(pk_seed, sk_seed, &key.adrs_prf(i as u32));
                    for s in 0..b as u32 {
                        node = f(pk_seed, &key.adrs_hash(i as u32, s), &node);
                    }
                    node
                })
                .collect()
        },
    ))
}

pub fn shrincs_verify_sl(msg: &[u8], sig: &[u8], ctx: &[u8], pk: &[u8; 48]) -> Result<(), Error> {
    let pk_seed: [u8; 16] = pk[..16].try_into().unwrap();
    let sl_root: [u8; 16] = pk[16..32].try_into().unwrap();
    let sf_root: [u8; 16] = pk[32..].try_into().unwrap();
    let fors_size = 16 * FORS_COUNT * (FORS_HEIGHT as usize + 1);
    let layer_size = 16 * (WOTS_TW_CHAIN_COUNT + SPHX_XMSS_HEIGHT as usize);
    if sig.first() != Some(&FXMSS_HEIGHT) {
        return Err(Error::Indicator);
    }
    if sig.len() != 1 + 16 + fors_size + SPHX_LAYER_COUNT * layer_size {
        return Err(Error::Length);
    }
    let r: [u8; 16] = sig[1..17].try_into().unwrap();
    let plan = sl_plan(&r, &pk_seed, &sl_root, &sl_message(ctx, &sf_root, msg)?);
    let node16 = |at: usize| -> [u8; 16] { sig[at..at + 16].try_into().unwrap() };
    let mut roots = Vec::with_capacity(16 * FORS_COUNT);
    for (t, &index) in fors_indexes(&plan.fors_digest).iter().enumerate() {
        let off = 17 + t * 16 * (FORS_HEIGHT as usize + 1);
        let mut node = f(&pk_seed, &plan.fors.adrs_tree(0, index), &node16(off));
        for j in 0..FORS_HEIGHT {
            let parent = plan.fors.adrs_tree(j + 1, index >> (j + 1));
            let sib = node16(off + 16 * (j as usize + 1));
            node = if (index >> j) & 1 == 1 {
                h(&pk_seed, &parent, &sib, &node)
            } else {
                h(&pk_seed, &parent, &node, &sib)
            };
        }
        roots.extend_from_slice(&node);
    }
    let mut message = tweaked(&pk_seed, &plan.fors.adrs_roots(), &roots);
    for (j, key) in plan.layers.iter().enumerate() {
        let off = 17 + fors_size + j * layer_size;
        let tips: Vec<[u8; 16]> = wots_tw_indexes(&message)
            .iter()
            .enumerate()
            .map(|(c, &b)| {
                let mut v = node16(off + 16 * c);
                for s in b as u32..(W - 1) as u32 {
                    v = f(&pk_seed, &key.adrs_hash(c as u32, s), &v);
                }
                v
            })
            .collect();
        let mut node = t_sl(&pk_seed, key, &tips);
        for k in 0..SPHX_XMSS_HEIGHT {
            let parent = pack(key.layer, key.tree, SL_XMSS_TREE, 0, k + 1, key.keypair >> (k + 1));
            let sib = node16(off + 16 * (WOTS_TW_CHAIN_COUNT + k as usize));
            node = if (key.keypair >> k) & 1 == 1 {
                h(&pk_seed, &parent, &sib, &node)
            } else {
                h(&pk_seed, &parent, &node, &sib)
            };
        }
        message = node;
    }
    if message == sl_root {
        Ok(())
    } else {
        Err(Error::Root)
    }
}
