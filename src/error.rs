use std::fmt::Display;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RevttyError {
    #[error("{0} is not implemented in the initial scaffold")]
    NotImplemented(&'static str),

    #[error("{0}")]
    Runtime(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl RevttyError {
    pub fn runtime(context: &str, error: impl Display) -> Self {
        Self::Runtime(format!("{context}: {error}"))
    }

    pub fn message(message: impl Into<String>) -> Self {
        Self::Runtime(message.into())
    }
}
