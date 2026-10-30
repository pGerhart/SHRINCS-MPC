//! A TCP mesh whose links behave like in-process channels. One port per
//! node carries every connection, sorted by its first byte.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use socket2::SockRef;

const SOCKET_BUFFER: usize = 64 << 20;
const MAGIC: u8 = 0xA5;
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_STREAMS: usize = 64;
/// Largest accepted message, 1 GiB.
const MAX_MESSAGE_WORDS: u64 = 1 << 27;
/// Receive buffers grow in steps of 8 MiB.
const READ_WORDS: usize = 1 << 20;

pub struct Mesh {
    pub tx: Vec<Option<Sender<Vec<u64>>>>,
    pub rx: Vec<Option<Receiver<Vec<u64>>>>,
    /// Bytes put on the wire.
    pub wire_bytes: Arc<AtomicU64>,
    /// Bytes taken off the wire.
    pub wire_recv: Arc<AtomicU64>,
}

fn tune(s: &TcpStream) -> io::Result<()> {
    s.set_nodelay(true)?;
    let r = SockRef::from(s);
    r.set_send_buffer_size(SOCKET_BUFFER)?;
    r.set_recv_buffer_size(SOCKET_BUFFER)?;
    Ok(())
}

fn as_bytes(v: &[u64]) -> &[u8] {
    bytemuck::cast_slice(v)
}

fn as_bytes_mut(v: &mut [u64]) -> &mut [u8] {
    bytemuck::cast_slice_mut(v)
}

/// Mesh links are filed for `connect`, everything else goes to `http`.
pub struct Hub {
    links: Arc<(Mutex<HashMap<(u8, usize, usize), TcpStream>>, Condvar)>,
    closed: Arc<std::sync::atomic::AtomicBool>,
    pub http: Receiver<TcpStream>,
}

impl Hub {
    pub fn listen(addr: &str) -> io::Result<Hub> {
        let a: SocketAddr = addr
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| io::Error::other("bad address"))?;
        // A public IP on AWS is not on an interface.
        let listener = TcpListener::bind(a).or_else(|_| TcpListener::bind(("0.0.0.0", a.port())))?;
        let links: Arc<(Mutex<HashMap<(u8, usize, usize), TcpStream>>, Condvar)> = Arc::default();
        let (http_tx, http) = channel();
        let l = links.clone();
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let c = closed.clone();
        thread::spawn(move || {
            for s in listener.incoming().flatten() {
                let (l, http_tx, c) = (l.clone(), http_tx.clone(), c.clone());
                thread::spawn(move || {
                    let mut s = s;
                    let mut first = [0u8; 1];
                    if s.set_read_timeout(Some(HELLO_TIMEOUT)).is_err() || s.peek(&mut first).ok() != Some(1) {
                        return;
                    }
                    if first[0] != MAGIC {
                        let _ = http_tx.send(s);
                        return;
                    }
                    let mut hello = [0u8; 4];
                    if s.read_exact(&mut hello).is_err()
                        || hello[1] > 1
                        || hello[2] > 3
                        || usize::from(hello[3]) >= MAX_STREAMS
                    {
                        return;
                    }
                    if c.load(Ordering::Relaxed) || s.set_read_timeout(None).is_err() || tune(&s).is_err() {
                        return;
                    }
                    let (lock, cv) = &*l;
                    let mut links = lock.lock().expect("hub lock");
                    // The first connection per slot wins.
                    links
                        .entry((hello[1], hello[2] as usize, hello[3] as usize))
                        .or_insert(s);
                    cv.notify_all();
                });
            }
        });
        Ok(Hub { links, closed, http })
    }

    /// Refuse mesh connections from now on and drop unclaimed ones.
    pub fn close_mesh(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.links.0.lock().expect("hub lock").clear();
    }

    /// Higher ids dial lower ids.
    pub fn connect(&self, kind: u8, id: usize, addrs: &[String], streams: usize) -> io::Result<Mesh> {
        let n = addrs.len();
        let mut conns: Vec<Vec<Option<TcpStream>>> = (0..n).map(|_| (0..streams).map(|_| None).collect()).collect();
        for (peer, slot) in conns.iter_mut().enumerate().take(id) {
            for (k, conn) in slot.iter_mut().enumerate() {
                let deadline = Instant::now() + Duration::from_secs(300);
                let mut s = loop {
                    match TcpStream::connect(&addrs[peer]) {
                        Ok(s) => break s,
                        Err(e) if Instant::now() > deadline => return Err(e),
                        Err(_) => thread::sleep(Duration::from_millis(200)),
                    }
                };
                tune(&s)?;
                s.write_all(&[MAGIC, kind, id as u8, k as u8])?;
                *conn = Some(s);
            }
        }
        let (lock, cv) = &*self.links;
        for (peer, slot) in conns.iter_mut().enumerate().skip(id + 1) {
            for (k, conn) in slot.iter_mut().enumerate() {
                let mut links = lock.lock().unwrap();
                let deadline = Instant::now() + Duration::from_secs(300);
                *conn = loop {
                    if let Some(s) = links.remove(&(kind, peer, k)) {
                        break Some(s);
                    }
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(io::Error::other(format!("node {peer} did not connect")));
                    }
                    links = cv.wait_timeout(links, left).expect("hub lock").0;
                };
            }
        }
        link_up(id, conns)
    }
}

fn link_up(id: usize, conns: Vec<Vec<Option<TcpStream>>>) -> io::Result<Mesh> {
    let n = conns.len();
    let wire_bytes = Arc::new(AtomicU64::new(0));
    let wire_recv = Arc::new(AtomicU64::new(0));
    let mut tx = vec![None; n];
    let mut rx: Vec<Option<Receiver<Vec<u64>>>> = (0..n).map(|_| None).collect();
    for (peer, slot) in conns.into_iter().enumerate() {
        if peer == id {
            continue;
        }
        let socks: Vec<TcpStream> = slot.into_iter().map(|s| s.expect("connected")).collect();
        let (to_peer, outgoing) = channel::<Vec<u64>>();
        let (incoming, from_peer) = channel::<Vec<u64>>();
        spawn_link(socks, outgoing, incoming, wire_bytes.clone(), wire_recv.clone())?;
        tx[peer] = Some(to_peer);
        rx[peer] = Some(from_peer);
    }
    Ok(Mesh {
        tx,
        rx,
        wire_bytes,
        wire_recv,
    })
}

fn spawn_link(
    socks: Vec<TcpStream>,
    outgoing: Receiver<Vec<u64>>,
    incoming: Sender<Vec<u64>>,
    wire_bytes: Arc<AtomicU64>,
    wire_recv: Arc<AtomicU64>,
) -> io::Result<()> {
    let k = socks.len();
    let mut part_tx: Vec<Sender<(Arc<Vec<u64>>, usize, usize)>> = Vec::with_capacity(k);
    let mut part_rx: Vec<Receiver<Vec<u64>>> = Vec::with_capacity(k);
    for s in socks {
        let mut w = s.try_clone()?;
        let (ptx, prx) = channel::<(Arc<Vec<u64>>, usize, usize)>();
        let wb = wire_bytes.clone();
        thread::spawn(move || {
            for (msg, from, to) in prx {
                let part = &msg[from..to];
                let header = [part.len() as u64];
                if w.write_all(as_bytes(&header))
                    .and_then(|_| w.write_all(as_bytes(part)))
                    .is_err()
                {
                    return;
                }
                wb.fetch_add(8 * (1 + part.len() as u64), Ordering::Relaxed);
            }
        });
        part_tx.push(ptx);

        let mut r = s;
        let wr = wire_recv.clone();
        let (rtx, rrx) = channel::<Vec<u64>>();
        thread::spawn(move || loop {
            let mut header = [0u64];
            if r.read_exact(as_bytes_mut(&mut header)).is_err() {
                return;
            }
            if header[0] > MAX_MESSAGE_WORDS {
                return;
            }
            let n = header[0] as usize;
            let mut part = Vec::new();
            while part.len() < n {
                let at = part.len();
                part.resize(n.min(at + READ_WORDS), 0);
                if r.read_exact(as_bytes_mut(&mut part[at..])).is_err() {
                    return;
                }
            }
            wr.fetch_add(8 * (1 + header[0]), Ordering::Relaxed);
            if rtx.send(part).is_err() {
                return;
            }
        });
        part_rx.push(rrx);
    }
    thread::spawn(move || {
        for msg in outgoing {
            let len = msg.len();
            let msg = Arc::new(msg);
            for (i, p) in part_tx.iter().enumerate() {
                if p.send((msg.clone(), len * i / k, len * (i + 1) / k)).is_err() {
                    return;
                }
            }
        }
    });
    thread::spawn(move || loop {
        let mut parts = Vec::with_capacity(k);
        for r in &part_rx {
            match r.recv() {
                Ok(p) => parts.push(p),
                Err(_) => return,
            }
        }
        let msg = if k == 1 { parts.pop().unwrap() } else { parts.concat() };
        if incoming.send(msg).is_err() {
            return;
        }
    });
    Ok(())
}

/// Every holder of share m contributes to its key, so P_m never learns it.
pub fn key_setup(id: usize, mesh: &Mesh) -> io::Result<Vec<Option<[u8; 32]>>> {
    let n = mesh.tx.len();
    let mut keys: Vec<Option<[u8; 32]>> = (0..n)
        .map(|m| {
            (m != id).then(|| {
                let mut c = [0u8; 32];
                getrandom::fill(&mut c).expect("OS randomness");
                c
            })
        })
        .collect();
    let words = |c: &[u8; 32]| -> Vec<u64> { c.chunks(8).map(|b| u64::from_le_bytes(b.try_into().unwrap())).collect() };
    for p in (0..n).filter(|&p| p != id) {
        let msg: Vec<u64> = (0..n)
            .filter(|&m| m != id && m != p)
            .flat_map(|m| words(keys[m].as_ref().unwrap()))
            .collect();
        mesh.tx[p]
            .as_ref()
            .expect("peer link")
            .send(msg)
            .map_err(|_| io::Error::other("peer gone"))?;
    }
    for p in (0..n).filter(|&p| p != id) {
        let msg = mesh.rx[p]
            .as_ref()
            .expect("peer link")
            .recv()
            .map_err(|_| io::Error::other("peer gone"))?;
        if msg.len() != 4 * (n - 2) {
            return Err(io::Error::other("bad key setup message"));
        }
        for (i, m) in (0..n).filter(|&m| m != id && m != p).enumerate() {
            let k = keys[m].as_mut().expect("held share");
            for (j, w) in msg[4 * i..4 * i + 4].iter().enumerate() {
                for (b, byte) in w.to_le_bytes().iter().enumerate() {
                    k[8 * j + b] ^= byte;
                }
            }
        }
    }
    confirm_keys(id, mesh, &keys)?;
    Ok(keys)
}

/// Holders of a share compare its key's hash.
fn confirm_keys(id: usize, mesh: &Mesh, keys: &[Option<[u8; 32]>]) -> io::Result<()> {
    let n = mesh.tx.len();
    let tag = |p: usize| -> Vec<u64> {
        let mut h = Sha256::new();
        for m in (0..n).filter(|&m| m != id && m != p) {
            h.update([m as u8]);
            h.update(keys[m].expect("held share"));
        }
        let d: [u8; 32] = h.finalize().into();
        d.chunks(8)
            .map(|c| u64::from_le_bytes(c.try_into().expect("8 bytes")))
            .collect()
    };
    for p in (0..n).filter(|&p| p != id) {
        mesh.tx[p]
            .as_ref()
            .expect("peer link")
            .send(tag(p))
            .map_err(|_| io::Error::other("peer gone"))?;
    }
    for p in (0..n).filter(|&p| p != id) {
        let theirs = mesh.rx[p]
            .as_ref()
            .expect("peer link")
            .recv()
            .map_err(|_| io::Error::other("peer gone"))?;
        if theirs != tag(p) {
            return Err(io::Error::other(format!("share keys disagree with node {p}")));
        }
    }
    Ok(())
}
