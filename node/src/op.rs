//! Operations and their encoding on the control mesh.

use shrincs::Structure;

#[derive(Clone, Debug, PartialEq)]
pub enum Op {
    Keygen {
        structure: Structure,
    },
    Sign {
        msg: Vec<u8>,
        ctx: Vec<u8>,
        exact: bool,
        cache: bool,
    },
    SignStateless {
        msg: Vec<u8>,
        ctx: Vec<u8>,
        exact: bool,
        cache: bool,
    },
}

fn pack_bytes(out: &mut Vec<u64>, b: &[u8]) {
    out.push(b.len() as u64);
    out.extend(b.chunks(8).map(|c| {
        let mut w = [0u8; 8];
        w[..c.len()].copy_from_slice(c);
        u64::from_le_bytes(w)
    }));
}

fn unpack_bytes(w: &[u64], at: &mut usize) -> Option<Vec<u8>> {
    let len = usize::try_from(*w.get(*at)?).ok()?;
    let n = len.div_ceil(8);
    let words = w.get(*at + 1..(*at + 1).checked_add(n)?)?;
    *at += 1 + n;
    Some(words.iter().flat_map(|x| x.to_le_bytes()).take(len).collect())
}

impl Op {
    pub fn encode(op: &Option<Op>) -> Vec<u64> {
        let mut out = Vec::new();
        match op {
            None => out.push(0),
            Some(Op::Keygen { structure }) => {
                out.extend([1, u64::from(structure.depth), u64::from(structure.balanced)])
            }
            Some(Op::Sign { msg, ctx, exact, cache }) | Some(Op::SignStateless { msg, ctx, exact, cache }) => {
                out.push(if matches!(op, Some(Op::Sign { .. })) { 2 } else { 3 });
                out.push(u64::from(*exact) | u64::from(*cache) << 1);
                pack_bytes(&mut out, msg);
                pack_bytes(&mut out, ctx);
            }
        }
        out
    }

    /// None on malformed input.
    pub fn decode(w: &[u64]) -> Option<Option<Op>> {
        match *w.first()? {
            0 if w.len() == 1 => Some(None),
            1 if w.len() == 3 && w[2] <= 1 => Some(Some(Op::Keygen {
                structure: Structure {
                    depth: u8::try_from(w[1]).ok()?,
                    balanced: w[2] == 1,
                },
            })),
            k @ (2 | 3) => {
                let flags = *w.get(1)?;
                if flags > 3 {
                    return None;
                }
                let (exact, cache) = (flags & 1 == 1, flags & 2 == 2);
                let mut at = 2;
                let msg = unpack_bytes(w, &mut at)?;
                let ctx = unpack_bytes(w, &mut at)?;
                if at != w.len() {
                    return None;
                }
                Some(Some(if k == 2 {
                    Op::Sign { msg, ctx, exact, cache }
                } else {
                    Op::SignStateless { msg, ctx, exact, cache }
                }))
            }
            _ => None,
        }
    }
}
