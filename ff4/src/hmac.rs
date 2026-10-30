//! HMAC-SHA256 on a shared key, the BIP's `PRF_msg`.

use crate::error::Error;
use crate::party::Party;
use crate::plan::Plan;
use crate::shares::{Shares, Wide};

const IV: [u8; 32] = [
    0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a, 0x51, 0x0e, 0x52,
    0x7f, 0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19,
];

/// Chaining values after the inner and outer key blocks, for both keys.
#[derive(Clone)]
pub struct PrfKeys {
    pub sf: [Wide; 2],
    pub sl: [Wide; 2],
}

impl Party {
    /// Hashes the four key blocks in one compression.
    pub fn prf_keys(&mut self, plan: &Plan, sk_prf: &Shares) -> Result<PrfKeys, Error> {
        let lanes: Vec<[u8; 64]> = [(0xffu8, 0x36u8), (0xff, 0x5c), (0x00, 0x36), (0x00, 0x5c)]
            .iter()
            .map(|&(fill, pad)| {
                let mut b = [fill ^ pad; 64];
                b[..16].fill(pad);
                b
            })
            .collect();
        let mut block = Wide::public(self.id, &lanes.iter().map(|b| b.to_vec()).collect::<Vec<_>>());
        block.xor_shared_prefix(self.id, sk_prf);
        let state = Wide::public(self.id, &vec![IV.to_vec(); 4]);
        let out = self.compress(plan, &state, &block)?;
        let lane = |l| out.lane(l);
        Ok(PrfKeys {
            sf: [lane(0), lane(1)],
            sl: [lane(2), lane(3)],
        })
    }

    /// Opens `HMAC(key, data)[..16]` after the hash check.
    pub fn hmac_open(&mut self, plan: &Plan, key: &[Wide; 2], data: &[u8]) -> Result<[u8; 16], Error> {
        let mut padded = data.to_vec();
        padded.push(0x80);
        while (64 + padded.len()) % 64 != 56 {
            padded.push(0);
        }
        padded.extend_from_slice(&((64 + data.len()) as u64 * 8).to_be_bytes());
        let mut state = key[0].clone();
        for block in padded.chunks(64) {
            state = self.compress(plan, &state, &Wide::public(self.id, &[block.to_vec()]))?;
        }
        let mut tail = vec![0u8; 32];
        tail.push(0x80);
        tail.resize(62, 0);
        tail.extend_from_slice(&(96u16 * 8).to_be_bytes());
        let mut block = Wide::public(self.id, &[tail]);
        block.set_prefix(&state);
        let digest = self.compress(plan, &key[1], &block)?;
        self.verify()?;
        let bytes = self.open_wide(&digest.prefix(128))?;
        Ok(bytes[..16].try_into().expect("16 bytes"))
    }
}
