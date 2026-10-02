use thiserror::Error;

#[derive(Debug, Error)]
pub enum RevttyError {
    #[error("{0} is not implemented in the initial scaffold")]
    NotImplemented(&'static str),
}
