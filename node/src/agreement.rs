//! Ordering without a coordinator. A request is proposed for a slot, the
//! others answer, all echo a hash of the four proposals and run the slot.

use std::collections::VecDeque;
use std::sync::mpsc::Sender;

use crate::error::Error;
use crate::op::Op;
use crate::service::Node;

const PROPOSE: u64 = 1;
const ECHO: u64 = 2;

pub struct Agreement {
    id: usize,
    slot: u64,
    pub queue: VecDeque<(Op, Sender<String>)>,
    props: [Option<Option<Op>>; 4],
    echoes: [Option<Vec<u64>>; 4],
    digest: Option<Vec<u64>>,
    proposed: bool,
    next: Vec<(usize, Vec<u64>)>,
}

impl Agreement {
    pub fn new(id: usize) -> Self {
        Agreement {
            id,
            slot: 0,
            queue: VecDeque::new(),
            props: Default::default(),
            echoes: Default::default(),
            digest: None,
            proposed: false,
            next: Vec::new(),
        }
    }

    pub fn receive(&mut self, p: usize, m: Vec<u64>) -> Result<(), Error> {
        let bad = Error::Agreement {
            peer: p,
            slot: self.slot,
        };
        if m.len() < 2 {
            return Err(bad);
        }
        if m[1] == self.slot + 1 {
            // A peer is at most one slot ahead.
            if self.next.iter().filter(|(q, _)| *q == p).count() >= 2 {
                return Err(bad);
            }
            self.next.push((p, m));
            return Ok(());
        }
        if m[1] != self.slot {
            return Err(bad);
        }
        match m[0] {
            PROPOSE if self.props[p].is_none() => self.props[p] = Some(Op::decode(&m[2..]).ok_or(bad)?),
            ECHO if self.echoes[p].is_none() && m.len() == 6 => self.echoes[p] = Some(m[2..].to_vec()),
            _ => return Err(bad),
        }
        Ok(())
    }

    fn propose(&mut self, send_all: &impl Fn(Vec<u64>)) {
        let mine = self.queue.front().map(|(op, _)| op.clone());
        let mut m = vec![PROPOSE, self.slot];
        m.extend(Op::encode(&mine));
        send_all(m);
        self.props[self.id] = Some(mine);
        self.proposed = true;
    }

    pub fn progress(&mut self, node: &mut Node, send_all: &impl Fn(Vec<u64>)) -> Result<(), Error> {
        loop {
            if !self.proposed && (!self.queue.is_empty() || self.props.iter().any(Option::is_some)) {
                self.propose(send_all);
            }
            if self.digest.is_none() && self.props.iter().all(Option::is_some) {
                let mut h = node.state_tag().to_vec();
                for p in &self.props {
                    let e = Op::encode(p.as_ref().expect("all proposals present"));
                    h.extend((e.len() as u64).to_le_bytes());
                    h.extend(e.iter().flat_map(|w| w.to_le_bytes()));
                }
                let d: Vec<u64> = shrincs::sha256(&h)
                    .chunks(8)
                    .map(|c| u64::from_le_bytes(c.try_into().expect("8 bytes")))
                    .collect();
                let mut m = vec![ECHO, self.slot];
                m.extend(&d);
                send_all(m);
                self.digest = Some(d);
            }
            let Some(d) = &self.digest else { return Ok(()) };
            if (0..4).filter(|&p| p != self.id).any(|p| self.echoes[p].is_none()) {
                return Ok(());
            }
            if let Some(peer) = (0..4)
                .filter(|&p| p != self.id)
                .find(|&p| self.echoes[p].as_ref() != Some(d))
            {
                return Err(Error::Agreement { peer, slot: self.slot });
            }

            for p in 0..4 {
                if let Some(op) = self.props[p].take().expect("all proposals present") {
                    let (out, fatal) = node.run(&op);
                    eprintln!(
                        "node {}: slot {}, op from node {p}: {}",
                        self.id,
                        self.slot,
                        out.chars().take(200).collect::<String>()
                    );
                    if p == self.id {
                        let (_, reply) = self.queue.pop_front().expect("own proposal queued");
                        let _ = reply.send(out);
                    }
                    if let Some(e) = fatal {
                        return Err(e);
                    }
                }
            }
            self.slot += 1;
            self.echoes = Default::default();
            self.digest = None;
            self.proposed = false;
            for (p, m) in std::mem::take(&mut self.next) {
                self.receive(p, m)?;
            }
        }
    }
}
