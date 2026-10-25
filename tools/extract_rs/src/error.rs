use std::collections::BTreeMap;

use thiserror::Error;

/// Extraction failure. Mirrors Python's ExtractError.
#[derive(Debug, Error)]
pub enum ExtractError {
    #[error("{0}")]
    Message(String),
    /// The selected route cannot work on this kernel layout. `numbers` carries
    /// the derivation values that decided it, for the verdict report.
    #[error("route not feasible: {message}")]
    Infeasible {
        message: String,
        numbers: BTreeMap<String, i64>,
    },
    /// The kernel lacks offsets the exploit chain needs.
    #[error("kernel missing required offsets: {0}")]
    Unsupported(String),
    /// The kernel already includes the rtmutex remove_waiter() fix,
    /// so the chain cannot work.
    #[error("kernel already fixed the vulnerability: {0}")]
    AlreadyFixed(String),
    /// The embedded kallsyms table could not be recovered from the image.
    #[error("kallsyms recovery failed: {0}")]
    Kallsyms(String),
}

impl ExtractError {
    pub fn new(msg: impl Into<String>) -> Self {
        ExtractError::Message(msg.into())
    }

    pub fn infeasible(msg: impl Into<String>) -> Self {
        ExtractError::Infeasible {
            message: msg.into(),
            numbers: BTreeMap::new(),
        }
    }

    pub fn infeasible_with(
        msg: impl Into<String>,
        numbers: BTreeMap<String, i64>,
    ) -> Self {
        ExtractError::Infeasible {
            message: msg.into(),
            numbers,
        }
    }

    pub fn unsupported(msg: impl Into<String>) -> Self {
        ExtractError::Unsupported(msg.into())
    }

    pub fn already_fixed(msg: impl Into<String>) -> Self {
        ExtractError::AlreadyFixed(msg.into())
    }

    pub fn kallsyms(msg: impl Into<String>) -> Self {
        ExtractError::Kallsyms(msg.into())
    }
}

pub type Result<T> = std::result::Result<T, ExtractError>;

impl From<std::io::Error> for ExtractError {
    fn from(err: std::io::Error) -> Self {
        ExtractError::Message(format!("{err}"))
    }
}

impl From<std::string::FromUtf8Error> for ExtractError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        ExtractError::Message(format!("{err}"))
    }
}
