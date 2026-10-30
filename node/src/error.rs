use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Protocol(ff4::Error),
    Agreement { peer: usize, slot: u64 },
    NoKey,
    KeyExists,
    Depth,
    LeavesUsed,
    BadRequest,
    Config,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "io: {e}"),
            Error::Protocol(e) => write!(f, "{e}"),
            Error::Agreement { peer, slot } => write!(f, "abort: node {peer} broke the agreement at slot {slot}"),
            Error::NoKey => f.write_str("no key"),
            Error::KeyExists => f.write_str("a key exists already"),
            Error::Depth => write!(f, "depth must be 1 to {}", crate::service::MAX_DEPTH),
            Error::Config => write!(
                f,
                "need four peers, an id below four and 1 to {} streams",
                crate::net::MAX_STREAMS
            ),
            Error::LeavesUsed => f.write_str("all stateful leaves used"),
            Error::BadRequest => f.write_str("bad request"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<ff4::Error> for Error {
    fn from(e: ff4::Error) -> Self {
        Error::Protocol(e)
    }
}
