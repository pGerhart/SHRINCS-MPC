//! Four nodes on loopback, requests at all of them at once.

use std::io::{Read, Write};
use std::net::TcpStream;

fn request(addr: &str, path: &str) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    write!(s, "POST {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
    let mut r = String::new();
    s.read_to_string(&mut r).unwrap();
    r.split_once("\r\n\r\n").unwrap().1.to_string()
}

fn request_raw(addr: &str, raw: &str) -> String {
    let mut s = TcpStream::connect(addr).unwrap();
    s.write_all(raw.as_bytes()).unwrap();
    let mut r = String::new();
    let _ = s.read_to_string(&mut r);
    r
}

fn field(json: &str, name: &str) -> String {
    let k = format!("\"{name}\":");
    let rest =
        json[json.find(&k).unwrap_or_else(|| panic!("{name} missing in {json}")) + k.len()..].trim_start_matches('"');
    rest[..rest.find(['"', ',', '}']).unwrap()].to_string()
}

#[test]
fn four_nodes_without_coordinator() {
    let peers: Vec<String> = (0..4).map(|i| format!("127.0.0.1:{}", 18080 + i)).collect();
    let dir = std::env::temp_dir().join(format!("shrincs-cluster-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for id in 0..4 {
        let cfg = node::Config {
            id,
            peers: peers.clone(),
            listen: peers[id].clone(),
            streams: 2,
            journal: dir.join(format!("{id}.journal")).to_string_lossy().into(),
        };
        std::thread::spawn(move || node::run(cfg));
    }
    std::thread::sleep(std::time::Duration::from_millis(500));

    for bad in ["/keygen?depth=0", "/keygen?depth=17", "/keygen"] {
        assert_eq!(field(&request(&peers[1], bad), "ok"), "false", "{bad}");
    }
    let keygen = request(&peers[0], "/keygen?depth=3");
    assert_eq!(field(&keygen, "ok"), "true", "{keygen}");
    let pk: [u8; 48] = hex::decode(field(&keygen, "pk")).unwrap().try_into().unwrap();

    let answers: Vec<(Vec<u8>, String)> = std::thread::scope(|s| {
        let hs: Vec<_> = (0..4)
            .map(|i| {
                let addr = peers[i].clone();
                s.spawn(move || {
                    let msg = format!("from node {i}").into_bytes();
                    let path = format!("/sign?msg={}&ctx=", hex::encode(&msg));
                    (msg, request(&addr, &path))
                })
            })
            .collect();
        hs.into_iter().map(|h| h.join().unwrap()).collect()
    });
    let mut leaves: Vec<String> = Vec::new();
    for (msg, a) in &answers {
        assert_eq!(field(a, "ok"), "true", "{a}");
        let sig = hex::decode(field(a, "sig")).unwrap();
        assert_eq!(shrincs::verify(msg, &sig, b"", &pk), Ok(()));
        leaves.push(field(a, "leaf"));
    }
    leaves.sort();
    assert_eq!(leaves, ["0", "1", "2", "3"]);

    assert_eq!(field(&request(&peers[3], "/keygen?depth=3"), "ok"), "false");
    let long_ctx = format!("/sign?msg=00&ctx={}", "00".repeat(256));
    assert_eq!(field(&request(&peers[3], &long_ctx), "ok"), "false");
    let mut raw = TcpStream::connect(&peers[0]).unwrap();
    raw.write_all(b"garbage\r\n\r\n").unwrap();
    let mut r = String::new();
    raw.read_to_string(&mut r).unwrap();
    assert!(r.contains("400"));

    let huge = format!("/sign?ctx=&msg={}", "ab".repeat(70_000));
    assert!(request_raw(&peers[1], &format!("POST {huge} HTTP/1.1\r\n\r\n")).starts_with("HTTP/1.1 400"));
    assert!(request_raw(&peers[1], "POST /sign?msg=00&ctx=\r\n\r\n").starts_with("HTTP/1.1 400"));
    let status = request_raw(&peers[1], "GET /status HTTP/1.1\r\n\r\n");
    assert_eq!(field(&status, "used_leaves"), "4");
    assert!(field(&status, "secret_bytes_cache").parse::<u64>().unwrap() > 0);

    for (i, mode) in ["&exact=1", "&cache=0", "&exact=1&cache=0"].iter().enumerate() {
        let msg = format!("mode {i}");
        let a = request(&peers[i % 4], &format!("/sign?msg={}&ctx={mode}", hex::encode(&msg)));
        assert_eq!(field(&a, "ok"), "true", "{a}");
        assert_eq!(
            shrincs::verify(msg.as_bytes(), &hex::decode(field(&a, "sig")).unwrap(), b"", &pk),
            Ok(())
        );
    }
    assert_eq!(field(&request(&peers[3], "/sign?msg=01&ctx="), "ok"), "true");
    let full = request(&peers[2], "/sign?msg=00&ctx=");
    assert_eq!(field(&full, "ok"), "false");
    let bad = request(&peers[1], "/nothing");
    assert_eq!(field(&bad, "ok"), "false");
}
