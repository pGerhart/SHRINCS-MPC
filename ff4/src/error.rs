use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    HashMismatch,
    CopiesDiffer,
    MessageLength,
    PeerGone(usize),
    PeerAborted,
    Grinding,
    Context,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::HashMismatch => f.write_str("abort: a joint message does not match its hash"),
            Error::CopiesDiffer => f.write_str("abort: copies of a share differ"),
            Error::MessageLength => f.write_str("abort: message of the wrong length"),
            Error::PeerGone(p) => write!(f, "abort: party {p} is gone"),
            Error::PeerAborted => f.write_str("abort: another party aborted"),
            Error::Grinding => f.write_str("no WOTS+C counter reaches the constant sum"),
            Error::Context => f.write_str("context longer than 255 bytes"),
        }
    }
}

impl std::error::Error for Error {}
