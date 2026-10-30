//! The tweakable hash `SHA-256(pk_seed || 0^48 || ADRS || M)[..16]`.

use sha2::{Digest, Sha256};

pub(crate) fn pack(height: u8, index: u64, ty: u8, w1: u32, w2: u32, w3: u32) -> [u8; 22] {
    let mut a = [0u8; 22];
    a[0] = height;
    a[1..9].copy_from_slice(&index.to_be_bytes());
    a[9] = ty;
    a[10..14].copy_from_slice(&w1.to_be_bytes());
    a[14..18].copy_from_slice(&w2.to_be_bytes());
    a[18..22].copy_from_slice(&w3.to_be_bytes());
    a
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Chaining value after the public first block, as the circuit reads it.
pub fn seed_midstate(pk_seed: &[u8; 16]) -> [u8; 32] {
    let mut block = [0u8; 64];
    block[..16].copy_from_slice(pk_seed);
    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    sha2::block_api::compress256(&mut state, &[block]);
    let mut out = [0u8; 32];
    for (i, s) in state.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&s.to_be_bytes());
    }
    out
}

/// Second block of F and PRF. Bytes 22..38 carry the input.
pub fn tweak_block(adrs: &[u8; 22], m: &[u8; 16]) -> [u8; 64] {
    let mut b = [0u8; 64];
    b[..22].copy_from_slice(adrs);
    b[22..38].copy_from_slice(m);
    b[38] = 0x80;
    b[62..64].copy_from_slice(&(102u16 * 8).to_be_bytes());
    b
}

pub(crate) fn tweaked(pk_seed: &[u8; 16], adrs: &[u8], m: &[u8]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(pk_seed);
    h.update([0u8; 48]);
    h.update(adrs);
    h.update(m);
    let d: [u8; 32] = h.finalize().into();
    d[..16].try_into().unwrap()
}

pub fn f(pk_seed: &[u8; 16], adrs: &[u8; 22], m: &[u8; 16]) -> [u8; 16] {
    tweaked(pk_seed, adrs, m)
}

pub fn prf(pk_seed: &[u8; 16], sk_seed: &[u8; 16], adrs: &[u8; 22]) -> [u8; 16] {
    tweaked(pk_seed, adrs, sk_seed)
}

pub(crate) fn h(pk_seed: &[u8; 16], adrs: &[u8; 22], l: &[u8; 16], r: &[u8; 16]) -> [u8; 16] {
    let mut m = [0u8; 32];
    m[..16].copy_from_slice(l);
    m[16..].copy_from_slice(r);
    tweaked(pk_seed, adrs, &m)
}

pub fn base_2b(x: &[u8], b: usize, outlen: usize) -> Vec<usize> {
    let (mut acc, mut bits, mut j) = (0u64, 0usize, 0usize);
    let mut out = Vec::with_capacity(outlen);
    for _ in 0..outlen {
        while bits < b {
            acc = (acc << 8) + u64::from(x[j]);
            j += 1;
            bits += 8;
        }
        bits -= b;
        out.push(((acc >> bits) % (1 << b)) as usize);
        acc %= 1 << bits;
    }
    out
}

pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    k[..key.len()].copy_from_slice(key);
    let pad = |b: u8| k.map(|x| x ^ b);
    let inner: [u8; 32] = Sha256::new()
        .chain_update(pad(0x36))
        .chain_update(msg)
        .finalize()
        .into();
    Sha256::new()
        .chain_update(pad(0x5c))
        .chain_update(inner)
        .finalize()
        .into()
}

/// HMAC key of `PRF_msg_sf`.
pub fn sf_prf_key(sk_prf: &[u8; 16]) -> [u8; 64] {
    let mut k = [0xffu8; 64];
    k[..16].copy_from_slice(sk_prf);
    k
}

/// HMAC key of `PRF_msg_sl`.
pub fn sl_prf_key(sk_prf: &[u8; 16]) -> [u8; 64] {
    let mut k = [0u8; 64];
    k[..16].copy_from_slice(sk_prf);
    k
}
