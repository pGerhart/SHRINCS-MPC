//! One request per connection, no body, a JSON answer.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::mpsc::{channel, Sender};
use std::time::{Duration, Instant};

use crate::op::Op;
use crate::Event;

/// A request head, enough for a 32 KiB message in hex.
const MAX_HEAD: usize = 1 << 17;

fn query(url: &str) -> HashMap<String, String> {
    url.split_once('?')
        .map(|(_, q)| {
            q.split('&')
                .filter_map(|kv| kv.split_once('='))
                .map(|(k, v)| (k.into(), v.into()))
                .collect()
        })
        .unwrap_or_default()
}

/// TCP connect time to a peer.
fn ping(addr: &str) -> String {
    let Ok(a) = addr.parse::<SocketAddr>() else {
        return "{\"ok\":false,\"error\":\"bad address\"}".into();
    };
    let t = Instant::now();
    match TcpStream::connect_timeout(&a, Duration::from_secs(5)) {
        Ok(_) => format!("{{\"ok\":true,\"connect_ms\":{:.3}}}", t.elapsed().as_secs_f64() * 1e3),
        Err(e) => format!("{{\"ok\":false,\"error\":\"{e}\"}}"),
    }
}

/// Answer, then drain unread input, so the close is not a reset.
fn respond(conn: &mut TcpStream, code: &str, body: &str) {
    let _ = write!(
        conn,
        "HTTP/1.1 {code}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = conn.shutdown(Shutdown::Write);
    let _ = conn.set_read_timeout(Some(Duration::from_millis(500)));
    let mut sink = [0u8; 4096];
    while matches!(conn.read(&mut sink), Ok(n) if n > 0) {}
}

pub fn serve(mut conn: TcpStream, ev: Sender<Event>, peers: &[String]) {
    if conn.set_read_timeout(Some(Duration::from_secs(10))).is_err() {
        return;
    }
    let mut head = Vec::new();
    let mut buf = [0u8; 4096];
    let complete = loop {
        let tail = head.len().saturating_sub(buf.len() + 3);
        if head[tail..].windows(4).any(|w| w == b"\r\n\r\n") {
            break true;
        }
        if head.len() > MAX_HEAD {
            break false;
        }
        match conn.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => head.extend_from_slice(&buf[..n]),
        }
    };
    let line = String::from_utf8_lossy(&head).lines().next().unwrap_or("").to_string();
    let mut parts = line.split(' ');
    let (method, url) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    if !complete || !parts.next().is_some_and(|v| v.starts_with("HTTP/")) {
        respond(
            &mut conn,
            "400 Bad Request",
            "{\"ok\":false,\"error\":\"incomplete or oversized request\"}",
        );
        return;
    }
    let q = query(url);
    let hex = |k: &str| q.get(k).and_then(|v| hex::decode(v).ok());
    let flag = |k: &str, default: bool| match q.get(k).map(String::as_str) {
        None => Some(default),
        Some("1") => Some(true),
        Some("0") => Some(false),
        Some(_) => None,
    };
    let modes = flag("exact", false).zip(flag("cache", true));
    let op = match (method, url.split('?').next().unwrap_or("")) {
        ("POST", "/keygen") => {
            let balanced = match q.get("shape").map(String::as_str) {
                None | Some("balanced") => Some(true),
                Some("unbalanced") => Some(false),
                Some(_) => None,
            };
            q.get("depth")
                .and_then(|d| d.parse().ok())
                .zip(balanced)
                .map(|(depth, balanced)| {
                    Some(Op::Keygen {
                        structure: shrincs::Structure { depth, balanced },
                    })
                })
        }
        ("POST", "/sign") => hex("msg")
            .zip(hex("ctx"))
            .zip(modes)
            .map(|((msg, ctx), (exact, cache))| Some(Op::Sign { msg, ctx, exact, cache })),
        ("POST", "/sign_stateless") => hex("msg")
            .zip(hex("ctx"))
            .zip(modes)
            .map(|((msg, ctx), (exact, cache))| Some(Op::SignStateless { msg, ctx, exact, cache })),
        ("GET", "/status") => Some(None),
        ("GET", "/ping") => {
            let body = match q
                .get("peer")
                .and_then(|p| p.parse::<usize>().ok())
                .and_then(|p| peers.get(p))
            {
                Some(addr) => ping(addr),
                None => "{\"ok\":false,\"error\":\"bad peer\"}".to_string(),
            };
            respond(&mut conn, "200 OK", &body);
            return;
        }
        _ => None,
    };
    let Some(op) = op else {
        respond(&mut conn, "400 Bad Request", "{\"ok\":false,\"error\":\"bad request\"}");
        return;
    };
    let (reply, answer) = channel();
    let t = Instant::now();
    if ev.send(Event::Local(op, reply)).is_err() {
        respond(
            &mut conn,
            "503 Service Unavailable",
            "{\"ok\":false,\"error\":\"node stopped\"}",
        );
        return;
    }
    let body = answer
        .recv()
        .unwrap_or_else(|_| "{\"ok\":false,\"error\":\"node stopped\"}".into());
    let body = format!(
        "{},\"request_seconds\":{:.6}}}",
        body.trim_end_matches('}'),
        t.elapsed().as_secs_f64()
    );
    respond(&mut conn, "200 OK", &body);
}
