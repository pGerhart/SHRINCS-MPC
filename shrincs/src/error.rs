use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Indicator,
    Length,
    LeafIndex,
    Grinding,
    Root,
    PublicKey,
    Context,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Indicator => "indicator byte does not match the signature path",
            Error::Length => "signature length does not match its indicator",
            Error::LeafIndex => "leaf index outside the tree",
            Error::Grinding => "WOTS+C counter does not reach the constant sum",
            Error::Root => "recomputed root differs from the public key",
            Error::PublicKey => "public key is not 48 bytes",
            Error::Context => "context longer than 255 bytes",
        })
    }
}

impl std::error::Error for Error {}
