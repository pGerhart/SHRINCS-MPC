#![allow(dead_code)]

use ff4::{dkg_party, parties, Party, PartyKeys, Plan, PrfKeys, Shares};
use shrincs::{Structure, WOTS_C_CHAIN_COUNT};

pub fn all<T: Send>(ps: &mut [Party], f: impl Fn(&mut Party, usize) -> T + Sync) -> Vec<T> {
    std::thread::scope(|s| {
        let f = &f;
        let hs: Vec<_> = ps
            .iter_mut()
            .enumerate()
            .map(|(i, p)| s.spawn(move || f(p, i)))
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    })
}

fn open(xs: Vec<Shares>) -> [u8; 16] {
    ff4::shares::reconstruct_lane0(&xs)
}

pub struct Fixture {
    pub plan: Plan,
    pub ks: Vec<PartyKeys>,
    pub sk_prf: Vec<Shares>,
    pub prf: Vec<PrfKeys>,
    pub structure: Structure,
    pub pk_seed: [u8; 16],
    pub tree: shrincs::Fxmss,
    pub top_pks: Vec<[u8; 16]>,
    pub sl_root: [u8; 16],
    pub sf_root: [u8; 16],
    pub pk: [u8; 48],
}

impl Fixture {
    /// `sk_seed || sk_prf || pk_seed`, opened for the comparison.
    pub fn seed(&self) -> [u8; 48] {
        let sk_seed = open(self.ks.iter().map(|k| k.sk_seed.clone()).collect());
        let sk_prf = open(self.sk_prf.clone());
        [&sk_seed[..], &sk_prf[..], &self.pk_seed[..]]
            .concat()
            .try_into()
            .unwrap()
    }
}

pub fn keygen(structure: Structure, seed: u8) -> (Vec<Party>, Fixture) {
    let mut ps = parties([seed; 32]);
    let plan = ff4::sha256_plan();
    let pk_seed = [seed ^ 0x5a; 16];
    let leaves = structure.leaves();
    let chains = shrincs::keygen_chains(&leaves);
    let out = all(&mut ps, |p, _| {
        let k = dkg_party(p, &plan, &pk_seed, &chains).unwrap();
        let sk_prf = p.random_secret(1);
        let prf = p.prf_keys(&plan, &sk_prf).unwrap();
        (k, sk_prf, prf)
    });
    let (mut ks, mut sk_prf, mut prf) = (vec![], vec![], vec![]);
    for (k, s, f) in out {
        ks.push(k);
        sk_prf.push(s);
        prf.push(f);
    }
    assert!(ks.iter().all(|k| k.tips == ks[0].tips));
    let tips = &ks[0].tips;
    let n_sf = leaves.len() * WOTS_C_CHAIN_COUNT;
    let leaf_pks: Vec<[u8; 16]> = leaves
        .iter()
        .zip(tips.chunks(WOTS_C_CHAIN_COUNT))
        .map(|(l, t)| shrincs::t_sf(&pk_seed, l, t))
        .collect();
    let tree = shrincs::Fxmss::new(&pk_seed, structure, &leaf_pks);
    let sf_root = tree.root();
    let top_pks = shrincs::top_pks_from_tips(&pk_seed, &tips[n_sf..]);
    let sl_root = shrincs::sl_root_from_leaves(&pk_seed, &top_pks);
    let pk = shrincs::shrincs_pubkey(&pk_seed, &sl_root, &sf_root);
    (
        ps,
        Fixture {
            plan,
            ks,
            sk_prf,
            prf,
            structure,
            pk_seed,
            tree,
            top_pks,
            sl_root,
            sf_root,
            pk,
        },
    )
}
