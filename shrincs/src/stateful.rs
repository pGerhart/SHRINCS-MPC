//! The stateful path: an FXMSS tree of WOTS+C leaves.

use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::hash::{h, pack};
use crate::params::*;
use crate::wots_c::{wots_c_pubkey_from_sig, Leaf};

/// Shape and depth of the FXMSS tree, the BIP's `sf_structure`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Structure {
    pub balanced: bool,
    pub depth: u8,
}

impl Structure {
    pub fn balanced(depth: u8) -> Structure {
        Structure { balanced: true, depth }
    }

    pub fn unbalanced(depth: u8) -> Structure {
        Structure { balanced: false, depth }
    }

    /// `shrincs_sf_leaf_select`.
    pub fn leaf(&self, state: u64) -> Option<Leaf> {
        let d = self.depth;
        let leaf = |height: u8, index: u64| Leaf {
            height,
            index,
            tree_balanced: self.balanced,
            tree_depth: d,
        };
        match (self.balanced, d) {
            (_, 0) => None,
            (true, _) => (state.checked_shr(d.into()).unwrap_or(0) == 0).then(|| leaf(FXMSS_HEIGHT - d, state)),
            (false, _) if state < u64::from(d) => Some(leaf(FXMSS_HEIGHT - 1 - state as u8, 1)),
            (false, _) if state == u64::from(d) => Some(leaf(FXMSS_HEIGHT - d, 0)),
            _ => None,
        }
    }

    /// Every leaf, in signing order.
    pub fn leaves(&self) -> Vec<Leaf> {
        (0..).map_while(|i| self.leaf(i)).collect()
    }
}

/// The FXMSS tree built from its leaves' public keys.
pub struct Fxmss {
    nodes: std::collections::HashMap<(u8, u64), [u8; 16]>,
}

impl Fxmss {
    /// `leaf_pks` in the order of [`Structure::leaves`].
    pub fn new(pk_seed: &[u8; 16], structure: Structure, leaf_pks: &[[u8; 16]]) -> Fxmss {
        let leaves = structure.leaves();
        assert_eq!(leaves.len(), leaf_pks.len(), "one public key per leaf");
        let mut nodes: std::collections::HashMap<(u8, u64), [u8; 16]> = leaves
            .iter()
            .zip(leaf_pks)
            .map(|(l, pk)| ((l.height, l.index), *pk))
            .collect();
        fn node(
            pk_seed: &[u8; 16],
            nodes: &mut std::collections::HashMap<(u8, u64), [u8; 16]>,
            height: u8,
            index: u64,
        ) -> [u8; 16] {
            if let Some(n) = nodes.get(&(height, index)) {
                return *n;
            }
            let l = node(pk_seed, nodes, height - 1, 2 * index);
            let r = node(pk_seed, nodes, height - 1, 2 * index + 1);
            let n = h(pk_seed, &pack(height, index, SF_FXMSS_TREE, 0, 0, 0), &l, &r);
            nodes.insert((height, index), n);
            n
        }
        node(pk_seed, &mut nodes, FXMSS_HEIGHT, 0);
        Fxmss { nodes }
    }

    /// Number of nodes, leaves included.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn root(&self) -> [u8; 16] {
        self.nodes[&(FXMSS_HEIGHT, 0)]
    }

    pub fn auth_path(&self, leaf: &Leaf) -> Vec<[u8; 16]> {
        (0..FXMSS_HEIGHT - leaf.height)
            .map(|j| self.nodes[&(leaf.height + j, leaf.index.checked_shr(u32::from(j)).unwrap_or(0) ^ 1)])
            .collect()
    }
}

pub fn shrincs_pubkey(pk_seed: &[u8; 16], sl_root: &[u8; 16], sf_root: &[u8; 16]) -> [u8; 48] {
    let mut pk = [0u8; 48];
    pk[..16].copy_from_slice(pk_seed);
    pk[16..32].copy_from_slice(sl_root);
    pk[32..].copy_from_slice(sf_root);
    pk
}

pub fn h_msg_sf(r: &[u8; 16], pk_seed: &[u8; 16], sf_root: &[u8; 16], leaf: &Leaf, msg: &[u8]) -> [u8; 32] {
    let mut pos = vec![leaf.height];
    pos.extend_from_slice(&leaf.index.to_be_bytes());
    let mut inner = Sha256::new();
    inner.update(r);
    inner.update(pk_seed);
    inner.update(sf_root);
    inner.update(&pos);
    inner.update(msg);
    let inner: [u8; 32] = inner.finalize().into();
    let mut outer = Sha256::new();
    outer.update(r);
    outer.update(pk_seed);
    outer.update(inner);
    outer.update(&pos);
    outer.finalize().into()
}

/// The HMAC input of `PRF_msg_sf`, keyed by [`crate::sf_prf_key`].
pub fn prf_msg_sf_input(pk_seed: &[u8; 16], leaf: &Leaf, bound: &[u8]) -> Vec<u8> {
    let mut m = pk_seed.to_vec();
    m.push(leaf.height);
    m.extend_from_slice(&leaf.index.to_be_bytes());
    m.extend_from_slice(bound);
    m
}

/// Version, `ctx`, `sl_root` and message.
pub fn bound_message(ctx: &[u8], sl_root: &[u8; 16], msg: &[u8]) -> Result<Vec<u8>, Error> {
    let mut m = vec![0u8, u8::try_from(ctx.len()).map_err(|_| Error::Context)?];
    m.extend_from_slice(ctx);
    m.extend_from_slice(sl_root);
    m.extend_from_slice(msg);
    Ok(m)
}

pub fn shrincs_sf_signature(r: &[u8; 16], leaf: &Leaf, wots_sig: &[u8], auth_path: &[[u8; 16]]) -> Vec<u8> {
    let depth = usize::from(FXMSS_HEIGHT - leaf.height);
    let mut sig = vec![leaf.height];
    sig.extend_from_slice(r);
    let index_bytes = depth.min(64).div_ceil(8);
    sig.extend_from_slice(&leaf.index.to_be_bytes()[8 - index_bytes..]);
    sig.extend_from_slice(wots_sig);
    for n in auth_path {
        sig.extend_from_slice(n);
    }
    sig
}

pub fn shrincs_verify_sf(msg: &[u8], sig: &[u8], ctx: &[u8], pk: &[u8; 48]) -> Result<(), Error> {
    let pk_seed: [u8; 16] = pk[..16].try_into().unwrap();
    let sl_root: [u8; 16] = pk[16..32].try_into().unwrap();
    let sf_root: [u8; 16] = pk[32..].try_into().unwrap();
    if sig.is_empty() || sig[0] == FXMSS_HEIGHT {
        return Err(Error::Indicator);
    }
    let height = sig[0];
    let depth = (FXMSS_HEIGHT - height) as usize;
    let index_size = depth.min(64).div_ceil(8);
    if sig.len() != 1 + 16 + index_size + WOTS_C_SIG_SIZE + 16 * depth {
        return Err(Error::Length);
    }
    let r: [u8; 16] = sig[1..17].try_into().unwrap();
    let mut idx = [0u8; 8];
    idx[8 - index_size..].copy_from_slice(&sig[17..17 + index_size]);
    let index = u64::from_be_bytes(idx);
    if depth < 64 && index >> depth != 0 {
        return Err(Error::LeafIndex);
    }
    let leaf = Leaf {
        height,
        index,
        tree_balanced: false,
        tree_depth: 0,
    };
    let body = &sig[17 + index_size..];
    let digest = h_msg_sf(&r, &pk_seed, &sf_root, &leaf, &bound_message(ctx, &sl_root, msg)?);
    let mut node = wots_c_pubkey_from_sig(&body[..WOTS_C_SIG_SIZE], &digest, &pk_seed, &leaf).ok_or(Error::Grinding)?;
    for k in 0..depth {
        let sib: [u8; 16] = body[WOTS_C_SIG_SIZE + 16 * k..WOTS_C_SIG_SIZE + 16 * (k + 1)]
            .try_into()
            .unwrap();
        let parent = pack(
            height + k as u8 + 1,
            index.checked_shr(k as u32 + 1).unwrap_or(0),
            SF_FXMSS_TREE,
            0,
            0,
            0,
        );
        node = if index.checked_shr(k as u32).unwrap_or(0) & 1 == 1 {
            h(&pk_seed, &parent, &sib, &node)
        } else {
            h(&pk_seed, &parent, &node, &sib)
        };
    }
    if node == sf_root {
        Ok(())
    } else {
        Err(Error::Root)
    }
}
