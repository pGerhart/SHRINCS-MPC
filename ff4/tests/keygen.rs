//! Distributed key generation gives the BIP key of the shared seed, for both tree shapes.

mod common;

use shrincs::Structure;

#[test]
fn keygen_is_the_bip_keygen() {
    for st in [Structure::balanced(2), Structure::unbalanced(3)] {
        let (_, f) = common::keygen(st, 1);
        assert_eq!(f.pk, shrincs::shrincs_keygen(&f.seed(), st).0, "{st:?}");
    }
}
