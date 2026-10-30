//! A node that dies stops the others instead of leaving them hanging.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// The answer, or empty when the node refuses or drops the connection.
fn request(addr: &str, path: &str) -> String {
    let Ok(mut s) = TcpStream::connect(addr) else {
        return String::new();
    };
    s.set_read_timeout(Some(Duration::from_secs(120))).unwrap();
    if write!(s, "POST {path} HTTP/1.1\r\nHost: x\r\n\r\n").is_err() {
        return String::new();
    }
    let mut r = String::new();
    let _ = s.read_to_string(&mut r);
    r
}

#[test]
fn dead_peer_stops_the_others() {
    let dir = std::env::temp_dir().join(format!("shrincs-failure-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let conf = dir.join("cluster.conf");
    std::fs::write(
        &conf,
        (0..4).map(|i| format!("127.0.0.1 {}\n", 18180 + i)).collect::<String>(),
    )
    .unwrap();
    let mut nodes: Vec<Child> = (0..4)
        .map(|i| {
            Command::new(env!("CARGO_BIN_EXE_shrincs-node"))
                .args(["--cluster", conf.to_str().unwrap(), "--id", &i.to_string()])
                .args(["--journal", dir.join(format!("{i}.journal")).to_str().unwrap()])
                .spawn()
                .unwrap()
        })
        .collect();
    let deadline = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect("127.0.0.1:18183").is_err() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    std::thread::sleep(Duration::from_secs(1));
    assert!(request("127.0.0.1:18180", "/keygen?depth=1").contains("\"ok\":true"));

    nodes[3].kill().unwrap();
    nodes[3].wait().unwrap();
    let t = Instant::now();
    let answer = request("127.0.0.1:18180", "/sign?msg=00&ctx=");
    assert!(!answer.contains("\"ok\":true"), "{answer}");
    assert!(t.elapsed() < Duration::from_secs(60));
    for n in nodes.iter_mut().take(3) {
        let status = n.wait().unwrap();
        assert!(!status.success());
    }
}
