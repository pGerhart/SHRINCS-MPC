//! Parameters and address types fixed by the BIP.

pub const WOTS_C_CHAIN_BITS: usize = 4;
pub const W: usize = 1 << WOTS_C_CHAIN_BITS;
pub const WOTS_C_CHAIN_COUNT: usize = 128usize.div_ceil(WOTS_C_CHAIN_BITS);
pub const WOTS_C_CONSTANT_SUM: usize = (WOTS_C_CHAIN_COUNT * (W - 1)).div_ceil(2);
pub const WOTS_C_SIG_SIZE: usize = 2 + 16 * WOTS_C_CHAIN_COUNT;

pub const WOTS_TW_CHAIN_COUNT: usize = 35;
pub const SPHX_XMSS_HEIGHT: u32 = 9;
pub const SPHX_TOP_LAYER: u8 = 4;
pub const SPHX_LAYER_COUNT: usize = 5;
pub const FORS_HEIGHT: u32 = 13;
pub const FORS_COUNT: usize = 10;
pub const FORS_DIGEST_SIZE: usize = 17;
pub const FXMSS_HEIGHT: u8 = 255;

pub(crate) const SL_WOTS_TW_HASH: u8 = 0;
pub(crate) const SL_WOTS_TW_PK: u8 = 1;
pub(crate) const SL_XMSS_TREE: u8 = 2;
pub(crate) const SL_WOTS_TW_PRF: u8 = 5;
pub(crate) const SL_FORS_TREE: u8 = 3;
pub(crate) const SL_FORS_ROOTS: u8 = 4;
pub(crate) const SL_FORS_PRF: u8 = 6;
pub(crate) const SF_FXMSS_TREE: u8 = 18;
pub(crate) const SF_WOTS_C_HASH: u8 = 16;
pub(crate) const SF_WOTS_C_PK: u8 = 17;
pub(crate) const SF_WOTS_C_PRF: u8 = 21;
pub(crate) const SF_WOTS_C_GRIND: u8 = 22;
