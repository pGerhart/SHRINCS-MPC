//! The operations a node runs once the four agree.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use ff4::{Party, Plan, PrfKeys, Shares, R};
use shrincs::{Structure, WOTS_C_CHAIN_COUNT};

use crate::error::Error;
use crate::op::Op;

/// Deepest balanced tree a node generates: 2^16 signatures.
pub const MAX_DEPTH: u8 = 16;

/// A `/proc/self/status` field such as `VmHWM:` in bytes, 0 off Linux.
fn proc_bytes(field: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(field))?
                .split_whitespace()
                .nth(1)?
                .parse::<u64>()
                .ok()
        })
        .map_or(0, |kb| kb * 1024)
}

struct Key {
    pk: [u8; 48],
    pk_seed: [u8; 16],
    sl_root: [u8; 16],
    sf_root: [u8; 16],
    structure: Structure,
    tree: shrincs::Fxmss,
    nodes: Vec<Shares>,
    sk_seed: Shares,
    sk_prf: Shares,
    prf: PrfKeys,
    top_offset: usize,
    top_pks: Vec<[u8; 16]>,
}

pub struct Node {
    pub id: usize,
    party: Party,
    plan: Plan,
    key: Option<Key>,
    journal: File,
    used: HashMap<u64, String>,
    /// Bytes sent and received on the data mesh.
    wire: [Arc<AtomicU64>; 2],
}

impl Node {
    pub fn new(id: usize, party: Party, journal: File, wire: [Arc<AtomicU64>; 2]) -> Node {
        Node {
            id,
            party,
            plan: ff4::sha256_plan(),
            key: None,
            journal,
            used: HashMap::new(),
            wire,
        }
    }

    fn keygen(&mut self, structure: Structure) -> Result<String, Error> {
        if self.key.is_some() {
            return Err(Error::KeyExists);
        }
        let max = if structure.balanced { MAX_DEPTH } else { 255 };
        if !(1..=max).contains(&structure.depth) {
            return Err(Error::Depth);
        }
        let p = &mut self.party;
        let coin = p.random_secret(1);
        let pk_seed = ff4::shares::lanes_of(&p.open_agreed(&coin)?, 1, 1)[0];
        let sk_prf = p.random_secret(1);
        let leaves = structure.leaves();
        let k = ff4::dkg_party(p, &self.plan, &pk_seed, &shrincs::keygen_chains(&leaves))?;
        let prf = p.prf_keys(&self.plan, &sk_prf)?;
        let n_sf = leaves.len() * WOTS_C_CHAIN_COUNT;
        let leaf_pks: Vec<[u8; 16]> = leaves
            .iter()
            .zip(k.tips.chunks(WOTS_C_CHAIN_COUNT))
            .map(|(l, t)| shrincs::t_sf(&pk_seed, l, t))
            .collect();
        let tree = shrincs::Fxmss::new(&pk_seed, structure, &leaf_pks);
        let sf_root = tree.root();
        let top_pks = shrincs::top_pks_from_tips(&pk_seed, &k.tips[n_sf..]);
        let sl_root = shrincs::sl_root_from_leaves(&pk_seed, &top_pks);
        let pk = shrincs::shrincs_pubkey(&pk_seed, &sl_root, &sf_root);
        self.key = Some(Key {
            pk,
            pk_seed,
            sl_root,
            sf_root,
            structure,
            tree,
            nodes: k.nodes,
            sk_seed: k.sk_seed,
            sk_prf,
            prf,
            top_offset: n_sf,
            top_pks,
        });
        self.used.clear();
        Ok(format!(
            "\"pk\":\"{}\",\"signatures\":{}",
            hex::encode(pk),
            leaves.len()
        ))
    }

    /// The HMAC key state if `exact`, recomputed without `cache`.
    fn prepare(&mut self, cache: bool, exact: bool) -> Result<Option<PrfKeys>, Error> {
        let k = self.key.as_ref().ok_or(Error::NoKey)?;
        Ok(match (exact, cache) {
            (false, _) => None,
            (true, true) => Some(k.prf.clone()),
            (true, false) => Some(self.party.prf_keys(&self.plan, &k.sk_prf)?),
        })
    }

    fn sign(&mut self, msg: &[u8], ctx: &[u8], exact: bool, cache: bool) -> Result<String, Error> {
        if ctx.len() > 255 {
            return Err(Error::BadRequest);
        }
        let state = self.used.len();
        let k = self.key.as_ref().ok_or(Error::NoKey)?;
        let leaf = k.structure.leaf(state as u64).ok_or(Error::LeavesUsed)?;
        let tag = hex::encode(shrincs::sha256(&[&[ctx.len() as u8], ctx, msg].concat()));
        writeln!(self.journal, "{} {state} {tag}", hex::encode(k.pk))?;
        self.journal.sync_all()?;
        self.used.insert(state as u64, tag);
        let prf = self.prepare(cache, exact)?;
        let k = self.key.as_ref().expect("checked above");
        let bound = shrincs::bound_message(ctx, &k.sl_root, msg).map_err(|_| Error::BadRequest)?;
        let key = ff4::Key {
            sk_seed: &k.sk_seed,
            nodes: cache.then_some(&k.nodes[..]),
            top_offset: k.top_offset,
            top_pks: &k.top_pks,
        };
        let r = prf.as_ref().map_or(R::Fast, R::Exact);
        let (r, wots) = ff4::sign_sf(
            &mut self.party,
            &self.plan,
            &key,
            &leaf,
            state * WOTS_C_CHAIN_COUNT,
            &k.pk_seed,
            &k.sf_root,
            &bound,
            r,
        )?;
        let sig = shrincs::shrincs_sf_signature(&r, &leaf, &wots, &k.tree.auth_path(&leaf));
        Ok(format!("\"leaf\":{state},\"sig\":\"{}\"", hex::encode(sig)))
    }

    fn sign_stateless(&mut self, msg: &[u8], ctx: &[u8], exact: bool, cache: bool) -> Result<String, Error> {
        if ctx.len() > 255 {
            return Err(Error::BadRequest);
        }
        let prf = self.prepare(cache, exact)?;
        let k = self.key.as_ref().ok_or(Error::NoKey)?;
        let key = ff4::Key {
            sk_seed: &k.sk_seed,
            nodes: cache.then_some(&k.nodes[..]),
            top_offset: k.top_offset,
            top_pks: &k.top_pks,
        };
        let r = prf.as_ref().map_or(R::Fast, R::Exact);
        let sig = ff4::sign_sl(
            &mut self.party,
            &self.plan,
            &key,
            &k.pk_seed,
            &k.sl_root,
            &k.sf_root,
            msg,
            ctx,
            r,
        )?;
        Ok(format!("\"sig\":\"{}\"", hex::encode(sig)))
    }

    /// `peak_rss_bytes` counts from the start of the last operation.
    pub fn status(&self) -> String {
        let cpu = std::fs::read_to_string("/proc/cpuinfo")
            .ok()
            .and_then(|c| {
                c.lines()
                    .find(|l| l.starts_with("model name"))
                    .map(|l| l.split(':').nth(1).unwrap_or("").trim().replace('"', ""))
            })
            .unwrap_or_default();
        let cpus = std::thread::available_parallelism().map_or(0, |n| n.get());
        let storage = self.key.as_ref().map_or(String::new(), |k| {
            // A node holds three of the four shares of a secret.
            let lanes = k.top_offset + k.top_pks.len() * shrincs::WOTS_TW_CHAIN_COUNT;
            let seeds = 2 * 3 * 16;
            let cache = shrincs::W * lanes * 3 * 16 + 4 * 3 * 32;
            let public = 48 + k.tree.len() * 16 + k.top_pks.len() * 16;
            format!(
                ",\"secret_bytes_cache\":{},\"secret_bytes_min\":{seeds},\"public_bytes\":{public}",
                seeds + cache
            )
        });
        format!(
            "\"version\":\"{}\",\"cpu\":\"{cpu}\",\"cpus\":{cpus},\"id\":{},\"pk\":{},\"used_leaves\":{},\"rounds_total\":{},\"wire_sent_total\":{},\"wire_recv_total\":{},\"rss_bytes\":{},\"peak_rss_bytes\":{},\"journal_bytes\":{}{storage}",
            env!("CARGO_PKG_VERSION"),
            self.id,
            self.key.as_ref().map_or("null".into(), |k| format!("\"{}\"", hex::encode(k.pk))),
            self.used.len(),
            self.party.rounds,
            self.wire[0].load(Ordering::Relaxed),
            self.wire[1].load(Ordering::Relaxed),
            proc_bytes("VmRSS:"),
            proc_bytes("VmHWM:"),
            self.journal.metadata().map_or(0, |m| m.len()),
        )
    }

    /// Bound by the agreement, so diverged nodes stop.
    pub fn state_tag(&self) -> [u8; 32] {
        let pk = self.key.as_ref().map_or([0u8; 48], |k| k.pk);
        shrincs::sha256(&[&pk[..], &(self.used.len() as u64).to_le_bytes()].concat())
    }

    /// Also returns a protocol abort, after which the node stops.
    pub fn run(&mut self, op: &Op) -> (String, Option<Error>) {
        let (r0, s0, v0) = (
            self.party.rounds,
            self.wire[0].load(Ordering::Relaxed),
            self.wire[1].load(Ordering::Relaxed),
        );
        // Resets the peak RSS, so `peak_rss` covers this operation.
        let _ = std::fs::write("/proc/self/clear_refs", "5");
        let t = Instant::now();
        let result = match op {
            Op::Keygen { structure } => self.keygen(*structure),
            Op::Sign { msg, ctx, exact, cache } => self.sign(msg, ctx, *exact, *cache),
            Op::SignStateless { msg, ctx, exact, cache } => self.sign_stateless(msg, ctx, *exact, *cache),
        };
        let stats = format!(
            "\"mpc_seconds\":{:.6},\"mpc_rounds\":{},\"wire_sent\":{},\"wire_recv\":{},\"peak_rss\":{}",
            t.elapsed().as_secs_f64(),
            self.party.rounds - r0,
            self.wire[0].load(Ordering::Relaxed) - s0,
            self.wire[1].load(Ordering::Relaxed) - v0,
            proc_bytes("VmHWM:")
        );
        match result {
            Ok(f) => (format!("{{\"ok\":true,{f},{stats}}}"), None),
            Err(e) => {
                let out = format!("{{\"ok\":false,\"error\":\"{e}\",{stats}}}");
                (out, matches!(e, Error::Protocol(_) | Error::Io(_)).then_some(e))
            }
        }
    }
}
