//! Every signing mode verifies; with the BIP's R the signature is the one
//! `shrincs_sign` gives for the shared seed, byte for byte.

mod common;

use ff4::{Key, R};
use shrincs::{Structure, WOTS_C_CHAIN_COUNT};

fn key<'a>(f: &'a common::Fixture, j: usize, cache: bool) -> Key<'a> {
    Key {
        sk_seed: &f.ks[j].sk_seed,
        nodes: cache.then_some(&f.ks[j].nodes[..]),
        top_offset: f.structure.leaves().len() * WOTS_C_CHAIN_COUNT,
        top_pks: &f.top_pks,
    }
}

#[test]
fn stateful_all_modes() {
    for st in [Structure::balanced(2), Structure::unbalanced(3)] {
        let (mut ps, f) = common::keygen(st, 2);
        let seed = f.seed();
        for (state, (exact, cache)) in [(false, true), (true, true), (false, false), (true, false)]
            .into_iter()
            .enumerate()
        {
            let leaf = st.leaf(state as u64).unwrap();
            let msg = format!("message {state}").into_bytes();
            let bound = shrincs::bound_message(b"ctx", &f.sl_root, &msg).unwrap();
            let fr = &f;
            let plan = &f.plan;
            let out = common::all(&mut ps, |p, j| {
                let r = if exact { R::Exact(&fr.prf[j]) } else { R::Fast };
                ff4::sign_sf(
                    p,
                    plan,
                    &key(fr, j, cache),
                    &leaf,
                    state * WOTS_C_CHAIN_COUNT,
                    &fr.pk_seed,
                    &fr.sf_root,
                    &bound,
                    r,
                )
                .unwrap()
            });
            assert!(out.iter().all(|o| o == &out[0]));
            let sig = shrincs::shrincs_sf_signature(&out[0].0, &leaf, &out[0].1, &f.tree.auth_path(&leaf));
            assert_eq!(
                shrincs::verify(&msg, &sig, b"ctx", &f.pk),
                Ok(()),
                "{st:?} exact {exact} cache {cache}"
            );
            if exact {
                assert_eq!(
                    sig,
                    shrincs::shrincs_sign(&msg, b"ctx", &seed, st, Some(state as u64)).unwrap()
                );
            }
        }
    }
}

#[test]
fn stateless_both_r_and_cache() {
    let (mut ps, f) = common::keygen(Structure::balanced(1), 3);
    let seed = f.seed();
    for (exact, cache) in [(true, true), (false, false)] {
        let msg = b"stateless".to_vec();
        let fr = &f;
        let plan = &f.plan;
        let sigs = common::all(&mut ps, |p, j| {
            let r = if exact { R::Exact(&fr.prf[j]) } else { R::Fast };
            ff4::sign_sl(
                p,
                plan,
                &key(fr, j, cache),
                &fr.pk_seed,
                &fr.sl_root,
                &fr.sf_root,
                &msg,
                b"ctx",
                r,
            )
            .unwrap()
        });
        assert!(sigs.iter().all(|s| s == &sigs[0]));
        assert_eq!(
            shrincs::verify(&msg, &sigs[0], b"ctx", &f.pk),
            Ok(()),
            "exact {exact} cache {cache}"
        );
        if exact {
            assert_eq!(
                sigs[0],
                shrincs::shrincs_sign(&msg, b"ctx", &seed, f.structure, None).unwrap()
            );
        }
    }
}
