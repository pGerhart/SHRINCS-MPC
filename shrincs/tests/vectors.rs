//! Vectors from the BIP's Python reference (scripts/gen_vectors.py).

use shrincs::*;

fn arr<const N: usize>(s: &str) -> [u8; N] {
    hex::decode(s).unwrap().try_into().unwrap()
}

#[test]
fn wots_c_matches_reference() {
    let text = include_str!("vectors/wots_c.txt");
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        let (sk, pk_seed) = (arr::<16>(f[0]), arr::<16>(f[1]));
        let leaf = Leaf {
            height: f[2].parse().unwrap(),
            index: f[3].parse().unwrap(),
            tree_balanced: f[4] == "1",
            tree_depth: f[5].parse().unwrap(),
        };
        let digest = arr::<32>(f[6]);
        assert_eq!(hex::encode(wots_c_pubkey_gen(&sk, &pk_seed, &leaf)), f[7]);
        let sig = wots_c_sign(&digest, &sk, &pk_seed, &leaf).unwrap();
        assert_eq!(hex::encode(&sig), f[8]);
        assert_eq!(
            wots_c_pubkey_from_sig(&sig, &digest, &pk_seed, &leaf)
                .map(hex::encode)
                .as_deref(),
            Some(f[7])
        );
    }
}

/// `shrincs_keygen` and `shrincs_sign` byte for byte, R included.
fn reference(file: &str, structure: fn(u8) -> Structure) {
    let mut lines = file.lines();
    let head: Vec<&str> = lines.next().unwrap().split(' ').collect();
    let seed: [u8; 48] = hex::decode(head[0]).unwrap().try_into().unwrap();
    let st = structure(head[1].parse().unwrap());
    let (pk, _) = shrincs_keygen(&seed, st);
    assert_eq!(hex::encode(pk), head[2]);
    for line in lines {
        let f: Vec<&str> = line.split(' ').collect();
        let msg = hex::decode(f[1]).unwrap();
        let ctx = if f[2] == "-" {
            vec![]
        } else {
            hex::decode(f[2]).unwrap()
        };
        let state = f[0].parse::<u64>().ok();
        assert_eq!(
            hex::encode(shrincs_sign(&msg, &ctx, &seed, st, state).unwrap()),
            f[3],
            "state {}",
            f[0]
        );
        assert_eq!(verify(&msg, &hex::decode(f[3]).unwrap(), &ctx, &pk), Ok(()));
        assert!(verify(b"other", &hex::decode(f[3]).unwrap(), &ctx, &pk).is_err());
    }
}

#[test]
fn balanced_matches_reference() {
    reference(include_str!("vectors/shrincs.txt"), Structure::balanced);
}

#[test]
fn unbalanced_matches_reference() {
    reference(include_str!("vectors/uxmss.txt"), Structure::unbalanced);
}

#[test]
fn leaf_selection_matches_the_bip() {
    let u = Structure::unbalanced(3);
    let picks: Vec<(u8, u64)> = u.leaves().iter().map(|l| (l.height, l.index)).collect();
    assert_eq!(picks, [(254, 1), (253, 1), (252, 1), (252, 0)]);
    assert_eq!(Structure::balanced(2).leaves().len(), 4);
    assert!(Structure::balanced(0).leaf(0).is_none());
}
