//! SHRINCS key generation and signing by Fantastic Four (Dalskov, Escudero
//! and Keller, USENIX Security 2021).

#![forbid(unsafe_code)]

pub mod circuit;
pub mod error;
pub mod hmac;
pub mod keygen;
pub mod party;
pub mod plan;
pub mod shares;
pub mod sign;

pub use error::Error;
pub use hmac::PrfKeys;
pub use keygen::{dkg_party, PartyKeys};
#[cfg(feature = "adversary")]
pub use party::Cheat;
pub use party::{parties, Party};
pub use plan::Plan;
pub use shares::{Shares, Wide};
pub use sign::{sign_sf, sign_sl, Key, R};

pub fn sha256_plan() -> Plan {
    let c = circuit::sha256::build_circuit(circuit::sha256::Adder::Sklansky);
    Plan::new(&c, &circuit::Schedule::new(&c))
}
