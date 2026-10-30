//! HMAC in MPC equals HMAC on the opened key, for both message PRF keys.

use ff4::{parties, Party};

#[test]
fn hmac_matches_plaintext() {
    let plan = ff4::sha256_plan();
    let mut ps = parties([3; 32]);
    let datas: Vec<Vec<u8>> = [0usize, 55, 56, 120].iter().map(|&n| (0..n as u8).collect()).collect();
    let outs: Vec<(Vec<[u8; 16]>, ff4::Shares)> = std::thread::scope(|s| {
        let hs: Vec<_> = ps
            .iter_mut()
            .map(|p: &mut Party| {
                let (plan, datas) = (&plan, &datas);
                s.spawn(move || {
                    let sk_prf = p.random_secret(1);
                    let keys = p.prf_keys(plan, &sk_prf).unwrap();
                    let mut rs = Vec::new();
                    for d in datas {
                        rs.push(p.hmac_open(plan, &keys.sf, d).unwrap());
                        rs.push(p.hmac_open(plan, &keys.sl, d).unwrap());
                    }
                    (rs, sk_prf)
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let sk_prf = ff4::shares::reconstruct_lane0(&outs.iter().map(|o| o.1.clone()).collect::<Vec<_>>());
    for (i, d) in datas.iter().enumerate() {
        let sf = shrincs::hmac_sha256(&shrincs::sf_prf_key(&sk_prf), d);
        let sl = shrincs::hmac_sha256(&shrincs::sl_prf_key(&sk_prf), d);
        for o in &outs {
            assert_eq!(o.0[2 * i][..], sf[..16], "sf, {} bytes", d.len());
            assert_eq!(o.0[2 * i + 1][..], sl[..16], "sl, {} bytes", d.len());
        }
    }
}
