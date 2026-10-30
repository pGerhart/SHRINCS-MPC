//! One Fantastic Four party as a server.

#![forbid(unsafe_code)]

pub mod agreement;
pub mod error;
pub mod http;
pub mod net;
pub mod op;
pub mod service;

use std::fs::OpenOptions;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::time::Instant;

pub use error::Error;

const DATA: u8 = 0;
const CONTROL: u8 = 1;
/// HTTP connections served at once, which bounds the request queue.
const MAX_HTTP: usize = 64;

pub enum Event {
    /// `None` asks for the status.
    Local(Option<op::Op>, Sender<String>),
    Peer(usize, Vec<u64>),
    /// The control link to this peer closed.
    Gone(usize),
}

pub struct Config {
    pub id: usize,
    /// All four, in id order.
    pub peers: Vec<String>,
    pub listen: String,
    pub streams: usize,
    pub journal: String,
}

/// One `host port` per line in id order, `#` comments.
pub fn read_cluster(text: &str) -> Result<Vec<String>, Error> {
    let peers: Vec<String> = text
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .map(|l| match l.split_whitespace().collect::<Vec<_>>()[..] {
            [host, port] if port.parse::<u16>().is_ok() => Ok(format!("{host}:{port}")),
            _ => Err(Error::Config),
        })
        .collect::<Result<_, _>>()?;
    if peers.len() == 4 {
        Ok(peers)
    } else {
        Err(Error::Config)
    }
}

/// Serves until a peer breaks the protocol.
pub fn run(cfg: Config) -> Result<(), Error> {
    let id = cfg.id;
    if cfg.peers.len() != 4 || id >= 4 || cfg.streams == 0 || cfg.streams > net::MAX_STREAMS {
        return Err(Error::Config);
    }
    let journal = OpenOptions::new().create(true).append(true).open(&cfg.journal)?;
    let t = Instant::now();
    let hub = net::Hub::listen(&cfg.listen)?;
    let data = hub.connect(DATA, id, &cfg.peers, cfg.streams)?;
    let control = hub.connect(CONTROL, id, &cfg.peers, 1)?;
    hub.close_mesh();
    let keys = net::key_setup(id, &data)?;
    let wire = [data.wire_bytes.clone(), data.wire_recv.clone()];
    let party = ff4::Party::new(
        id,
        keys.try_into().expect("four parties"),
        data.tx.try_into().expect("four parties"),
        data.rx.try_into().expect("four parties"),
    );
    eprintln!(
        "node {id}: connected in {:.2} s on {}",
        t.elapsed().as_secs_f64(),
        cfg.listen
    );

    let (events, inbox) = channel::<Event>();
    for (p, rx) in control.rx.into_iter().enumerate() {
        if let Some(rx) = rx {
            let ev = events.clone();
            thread::spawn(move || {
                for m in rx {
                    if ev.send(Event::Peer(p, m)).is_err() {
                        return;
                    }
                }
                let _ = ev.send(Event::Gone(p));
            });
        }
    }
    let ev = events.clone();
    let requests = hub.http;
    let peers = std::sync::Arc::new(cfg.peers.clone());
    let open = std::sync::Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for conn in requests {
            if open.fetch_add(1, Ordering::Relaxed) >= MAX_HTTP {
                open.fetch_sub(1, Ordering::Relaxed);
                continue;
            }
            let (ev, peers, open) = (ev.clone(), peers.clone(), open.clone());
            thread::spawn(move || {
                http::serve(conn, ev, &peers);
                open.fetch_sub(1, Ordering::Relaxed);
            });
        }
    });

    let ctl = control.tx;
    let send_all = |m: Vec<u64>| {
        for tx in ctl.iter().flatten() {
            let _ = tx.send(m.clone());
        }
    };
    let mut node = service::Node::new(id, party, journal, wire);
    let mut agree = agreement::Agreement::new(id);
    let mut step = |e: Event, agree: &mut agreement::Agreement| -> Result<(), Error> {
        match e {
            Event::Local(None, reply) => {
                let _ = reply.send(format!("{{\"ok\":true,{}}}", node.status()));
            }
            Event::Local(Some(op), reply) => agree.queue.push_back((op, reply)),
            Event::Peer(p, m) => agree.receive(p, m)?,
            Event::Gone(p) => return Err(Error::Protocol(ff4::Error::PeerGone(p))),
        }
        agree.progress(&mut node, &send_all)
    };
    loop {
        if let Err(e) = step(inbox.recv().expect("senders live as long as the loop"), &mut agree) {
            for (_, reply) in agree.queue.drain(..) {
                let _ = reply.send(format!("{{\"ok\":false,\"error\":\"{e}\"}}"));
            }
            // Let the HTTP threads write the answers before the process exits.
            thread::sleep(std::time::Duration::from_millis(500));
            return Err(e);
        }
    }
}
