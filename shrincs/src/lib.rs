//! SHRINCS in plaintext, byte-compatible with the BIP reference.
//!
//! ```
//! use shrincs::*;
//!
//! let seed = [7u8; 48];
//! let st = Structure::balanced(1);
//! let (pk, _) = shrincs_keygen(&seed, st);
//! let sig = shrincs_sign(b"hello", b"", &seed, st, Some(0)).unwrap();
//! assert_eq!(verify(b"hello", &sig, b"", &pk), Ok(()));
//! ```

#![forbid(unsafe_code)]

pub mod chains;
pub mod error;
pub mod hash;
pub mod params;
pub mod stateful;
pub mod stateless;
pub mod wots_c;

pub use chains::*;
pub use error::Error;
pub use hash::{base_2b, f, hmac_sha256, prf, seed_midstate, sf_prf_key, sha256, sl_prf_key, tweak_block};
pub use params::*;
pub use stateful::*;
pub use stateless::*;
pub use wots_c::*;

/// `shrincs_verify` with the reason.
pub fn verify(msg: &[u8], sig: &[u8], ctx: &[u8], pk: &[u8; 48]) -> Result<(), Error> {
    match sig.first() {
        Some(&FXMSS_HEIGHT) => shrincs_verify_sl(msg, sig, ctx, pk),
        Some(_) => shrincs_verify_sf(msg, sig, ctx, pk),
        None => Err(Error::Indicator),
    }
}

/// `shrincs_verify` as the BIP states it.
pub fn shrincs_verify(msg: &[u8], sig: &[u8], ctx: &[u8], pk: &[u8; 48]) -> bool {
    verify(msg, sig, ctx, pk).is_ok()
}

/// [`verify`] on a public key of any length.
pub fn verify_bytes(msg: &[u8], sig: &[u8], ctx: &[u8], pk: &[u8]) -> Result<(), Error> {
    verify(msg, sig, ctx, pk.try_into().map_err(|_| Error::PublicKey)?)
}

/// `shrincs_keygen` from a 48-byte seed `sk_seed || sk_prf || pk_seed`.
pub fn shrincs_keygen(seed: &[u8; 48], structure: Structure) -> ([u8; 48], Fxmss) {
    let (sk_seed, pk_seed) = (seed[..16].try_into().unwrap(), seed[32..].try_into().unwrap());
    let pks: Vec<[u8; 16]> = structure
        .leaves()
        .iter()
        .map(|l| wots_c_pubkey_gen(&sk_seed, &pk_seed, l))
        .collect();
    let tree = Fxmss::new(&pk_seed, structure, &pks);
    (
        shrincs_pubkey(&pk_seed, &sl_root(&sk_seed, &pk_seed), &tree.root()),
        tree,
    )
}

/// `shrincs_sign`, deterministic: stateful with the leaf of `state`, stateless
/// with `opt_rand = pk_seed` when `state` names no leaf.
pub fn shrincs_sign(
    msg: &[u8],
    ctx: &[u8],
    seed: &[u8; 48],
    structure: Structure,
    state: Option<u64>,
) -> Result<Vec<u8>, Error> {
    let sk_seed: [u8; 16] = seed[..16].try_into().unwrap();
    let sk_prf: [u8; 16] = seed[16..32].try_into().unwrap();
    let pk_seed: [u8; 16] = seed[32..].try_into().unwrap();
    let (pk, tree) = shrincs_keygen(seed, structure);
    let (sl_root, sf_root): ([u8; 16], [u8; 16]) = (pk[16..32].try_into().unwrap(), pk[32..].try_into().unwrap());
    match state.and_then(|s| structure.leaf(s)) {
        Some(leaf) => {
            let bound = bound_message(ctx, &sl_root, msg)?;
            let mac = hmac_sha256(&sf_prf_key(&sk_prf), &prf_msg_sf_input(&pk_seed, &leaf, &bound));
            let r: [u8; 16] = mac[..16].try_into().unwrap();
            let digest = h_msg_sf(&r, &pk_seed, &sf_root, &leaf, &bound);
            let wots = wots_c_sign(&digest, &sk_seed, &pk_seed, &leaf).ok_or(Error::Grinding)?;
            Ok(shrincs_sf_signature(&r, &leaf, &wots, &tree.auth_path(&leaf)))
        }
        None => {
            let m = sl_message(ctx, &sf_root, msg)?;
            let mac = hmac_sha256(&sl_prf_key(&sk_prf), &[&pk_seed[..], &m].concat());
            shrincs_sign_sl(
                msg,
                ctx,
                &mac[..16].try_into().unwrap(),
                &sk_seed,
                &pk_seed,
                &sl_root,
                &sf_root,
            )
        }
    }
}
