//! Each deviation of one party makes all four abort.

use std::time::Duration;

use ff4::{dkg_party, parties, Cheat, Error, Party};

fn run<T: Send>(ps: &mut [Party], f: impl Fn(&mut Party) -> T + Sync) -> Vec<T> {
    std::thread::scope(|s| {
        let f = &f;
        let hs: Vec<_> = ps.iter_mut().map(|p| s.spawn(move || f(p))).collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    })
}

fn keygen_with(cheater: usize, cheat: Cheat) -> Vec<Result<ff4::PartyKeys, Error>> {
    let plan = ff4::sha256_plan();
    let chains = shrincs::keygen_chains(&shrincs::Structure::balanced(1).leaves())[..64].to_vec();
    let mut ps = parties([cheater as u8; 32]);
    ps[cheater].cheat = Some(cheat);
    run(&mut ps, |p| dkg_party(p, &plan, &[1; 16], &chains))
}

#[test]
fn tampered_joint_message_aborts_everyone() {
    for cheater in 0..4 {
        for cheat in [Cheat::FlipJoint, Cheat::BadDigest] {
            let rs = keygen_with(cheater, cheat);
            assert!(
                rs.iter().all(|r| matches!(r, Err(Error::HashMismatch))),
                "{cheat:?} by {cheater}"
            );
        }
    }
}

#[test]
fn short_joint_message_aborts_everyone() {
    for cheater in 0..4 {
        let rs = keygen_with(cheater, Cheat::ShortJoint);
        assert!(rs.iter().all(Result::is_err), "party {cheater}");
        assert!(rs.iter().any(|r| matches!(r, Err(Error::MessageLength))));
    }
}

#[test]
fn wrong_copy_in_an_agreed_opening_aborts_everyone() {
    for cheater in 0..4 {
        let mut ps = parties([9; 32]);
        ps[cheater].cheat = Some(Cheat::BadCopy);
        let rs = run(&mut ps, |p| {
            let x = p.random_secret(1);
            p.open_agreed(&x)
        });
        let victim = (cheater + 1) % 4;
        assert_eq!(rs[victim], Err(Error::CopiesDiffer));
        for (i, r) in rs.iter().enumerate().filter(|&(i, _)| i != victim) {
            assert_eq!(*r, Err(Error::PeerAborted), "party {i}");
        }
    }
}

#[test]
fn silent_party_times_out() {
    let mut ps = parties([10; 32]);
    let gone = ps.pop().unwrap();
    drop(gone);
    for p in ps.iter_mut() {
        p.timeout = Duration::from_millis(200);
    }
    let rs = run(&mut ps, |p| {
        let x = p.random_secret(1);
        p.open(&x)
    });
    assert!(rs.iter().all(|r| matches!(r, Err(Error::PeerGone(3)))));
}
