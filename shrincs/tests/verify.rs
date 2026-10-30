use shrincs::*;

struct Case {
    pk: [u8; 48],
    msg: Vec<u8>,
    sf: Vec<u8>,
    sl: Vec<u8>,
}

fn case() -> Case {
    let mut lines = include_str!("vectors/shrincs.txt").lines();
    let pk = hex::decode(lines.next().unwrap().split(' ').nth(2).unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let sigs: Vec<Vec<&str>> = lines.map(|l| l.split(' ').collect()).collect();
    Case {
        pk,
        msg: hex::decode(sigs[0][1]).unwrap(),
        sf: hex::decode(sigs[0][3]).unwrap(),
        sl: hex::decode(sigs[2][3]).unwrap(),
    }
}

#[test]
fn rejects_each_way() {
    let c = case();
    let ctx_sl = b"ctx";
    let msg_sl = b"stateless";
    assert_eq!(verify(&c.msg, &c.sf, b"", &c.pk), Ok(()));
    assert_eq!(verify(msg_sl, &c.sl, ctx_sl, &c.pk), Ok(()));

    assert_eq!(verify(&c.msg, &[], b"", &c.pk), Err(Error::Indicator));
    assert_eq!(verify(&c.msg, &c.sf[..c.sf.len() - 1], b"", &c.pk), Err(Error::Length));
    assert_eq!(
        verify(msg_sl, &c.sl[..c.sl.len() - 1], ctx_sl, &c.pk),
        Err(Error::Length)
    );

    let mut far = c.sf.clone();
    far[17] = 0xff; // leaf index 255 in a tree of depth 2
    assert_eq!(verify(&c.msg, &far, b"", &c.pk), Err(Error::LeafIndex));

    let mut counter = c.sf.clone();
    counter[18] ^= 1;
    counter[19] ^= 1;
    let r = verify(&c.msg, &counter, b"", &c.pk);
    assert!(r == Err(Error::Grinding) || r == Err(Error::Root));

    let mut chain = c.sf.clone();
    chain[40] ^= 1;
    assert_eq!(verify(&c.msg, &chain, b"", &c.pk), Err(Error::Root));
    let mut chain = c.sl.clone();
    chain[100] ^= 1;
    assert_eq!(verify(msg_sl, &chain, ctx_sl, &c.pk), Err(Error::Root));
    assert_eq!(verify(b"other", &c.sl, ctx_sl, &c.pk), Err(Error::Root));

    assert_eq!(verify_bytes(&c.msg, &c.sf, b"", &c.pk[..47]), Err(Error::PublicKey));
    assert_eq!(verify(&c.msg, &c.sf, &[0; 256], &c.pk), Err(Error::Context));
    assert_eq!(verify(msg_sl, &c.sl, &[0; 256], &c.pk), Err(Error::Context));
}

#[test]
fn grinding_failure_is_reported() {
    let c = case();
    let hit = (0u32..1000).find(|i| verify(&i.to_le_bytes(), &c.sf, b"", &c.pk) == Err(Error::Grinding));
    assert!(hit.is_some());
}
