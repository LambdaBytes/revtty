use std::fmt::Display;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RevttyError {
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

/// `error` followed by its sources: TLS, DNS and connection failures only show in the chain.
pub fn with_sources(error: &(dyn std::error::Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut source = error.source();

    while let Some(cause) = source {
        let cause_text = cause.to_string();
        if !text.contains(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }

    text
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use super::with_sources;

    #[derive(Debug)]
    struct Layer(&'static str, Option<Box<Layer>>);

    impl fmt::Display for Layer {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.0)
        }
    }

    impl std::error::Error for Layer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            self.1.as_deref().map(|layer| layer as _)
        }
    }

    #[test]
    fn error_chain_includes_every_cause() {
        let error = Layer(
            "error sending request",
            Some(Box::new(Layer(
                "client error (Connect)",
                Some(Box::new(Layer(
                    "invalid peer certificate: UnknownIssuer",
                    None,
                ))),
            ))),
        );

        assert_eq!(
            with_sources(&error),
            "error sending request: client error (Connect): invalid peer certificate: UnknownIssuer"
        );
    }
}
