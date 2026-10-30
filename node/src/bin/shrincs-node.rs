//! `shrincs-node --cluster FILE --id I [--port P] [--streams K] [--journal FILE]`

#![forbid(unsafe_code)]

const USAGE: &str = "usage: shrincs-node --cluster FILE --id I [--port P] [--streams K] [--journal FILE]";

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn fail(msg: &str) -> ! {
    eprintln!("{msg}\n{USAGE}");
    std::process::exit(2);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let id: usize = arg(&args, "--id")
        .and_then(|s| s.parse().ok())
        .filter(|&i| i < 4)
        .unwrap_or_else(|| fail("--id 0..3"));
    let path = arg(&args, "--cluster").unwrap_or_else(|| fail("--cluster is required"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| fail(&format!("{path}: {e}")));
    let peers = node::read_cluster(&text).unwrap_or_else(|e| fail(&format!("{path}: {e}")));
    let (host, own_port) = peers[id].rsplit_once(':').unwrap_or(("0.0.0.0", ""));
    let port = arg(&args, "--port").unwrap_or_else(|| own_port.to_string());
    if port.parse::<u16>().is_err() {
        fail("--port must be a port number");
    }
    let cfg = node::Config {
        id,
        listen: format!("{host}:{port}"),
        peers,
        streams: arg(&args, "--streams").and_then(|s| s.parse().ok()).unwrap_or(1),
        journal: arg(&args, "--journal").unwrap_or_else(|| format!("shrincs-node-{id}.journal")),
    };
    if let Err(e) = node::run(cfg) {
        eprintln!("node {id}: {e}");
        std::process::exit(1);
    }
}
