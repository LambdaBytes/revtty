use std::ffi::OsStr;
use std::io::IsTerminal;

use tracing::level_filters::LevelFilter;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::prelude::*;

use crate::error::RevttyError;

/// At trace level, axum logs the text of every request it refuses, credentials included when a
/// client sent one malformed. Off whatever `RUST_LOG` says.
const REFUSED_REQUESTS: &str = "axum::rejection";

/// Sends the events of a long-running service (`agent run`, `relay serve`) to stderr, where
/// journald and launchd collect them, each with its time and level. `RUST_LOG` picks what is
/// logged, `info` by default. Libraries that log through the `log` crate, as russh, reqwest
/// and tungstenite do, stay silent: nothing bridges them, and tungstenite would log whole
/// WebSocket frames, credentials included, at trace level.
pub fn init_service_logging() -> Result<(), RevttyError> {
    let filter = log_filter(std::env::var_os("RUST_LOG").as_deref())?;
    let output = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_ansi(std::io::stderr().is_terminal());

    tracing_subscriber::registry()
        .with(output)
        .with(filter)
        .try_init()
        .map_err(|error| RevttyError::runtime("start logging", error))
}

/// The filter `RUST_LOG` describes, or `info` for everything when it is unset or empty.
fn log_filter(value: Option<&OsStr>) -> Result<Targets, RevttyError> {
    let filter = match value.filter(|value| !value.is_empty()) {
        None => Targets::new().with_default(LevelFilter::INFO),
        Some(value) => {
            let value = value
                .to_str()
                .ok_or_else(|| RevttyError::message("RUST_LOG is not valid UTF-8"))?;
            parse_filter(value).map_err(|reason| {
                RevttyError::message(format!("RUST_LOG={value:?} is not a log filter: {reason}"))
            })?
        }
    };

    // The most specific directive for a target decides, and a later one for the same target
    // replaces an earlier one.
    Ok(filter.with_target(REFUSED_REQUESTS, LevelFilter::OFF))
}

/// A comma-separated list of levels and `module=level` pairs. tracing reads any other word as
/// a module to log at trace level: a misspelt level would silence the service, so it is
/// refused instead.
fn parse_filter(value: &str) -> Result<Targets, String> {
    let mut filter = Targets::new();
    for directive in value.split(',') {
        filter = match directive.split_once('=') {
            None => filter.with_default(parse_level(directive)?),
            Some((target, level)) => {
                let is_module_path = target.split("::").all(|part| {
                    !part.is_empty()
                        && part
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                });
                if !is_module_path {
                    return Err(format!("{target:?} is not a module path"));
                }
                filter.with_target(target, parse_level(level)?)
            }
        };
    }
    Ok(filter)
}

fn parse_level(text: &str) -> Result<LevelFilter, String> {
    // tracing would read an empty level as `error`.
    if text.is_empty() {
        return Err("a level is missing".to_owned());
    }
    text.parse()
        .map_err(|_| format!("{text:?} is not a level: off, error, warn, info, debug or trace"))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use tracing::Level;

    use super::log_filter;

    #[test]
    fn without_rust_log_services_log_info_and_above() {
        for value in [None, Some(OsStr::new(""))] {
            let filter = log_filter(value).expect("default filter");

            assert!(filter.would_enable("revtty::relay", &Level::INFO));
            assert!(filter.would_enable("h2", &Level::WARN));
            assert!(!filter.would_enable("revtty::agent", &Level::DEBUG));
        }
    }

    #[test]
    fn rust_log_selects_levels_per_target() {
        let filter = log_filter(Some(OsStr::new("warn,revtty=trace"))).expect("filter");

        assert!(filter.would_enable("revtty::agent::ssh", &Level::TRACE));
        assert!(!filter.would_enable("hyper_util::client", &Level::INFO));
        assert!(filter.would_enable("hyper_util::client", &Level::WARN));
    }

    #[test]
    fn an_invalid_rust_log_is_refused() {
        let error = log_filter(Some(OsStr::new("revtty=loud"))).expect_err("an invalid filter");

        assert!(
            error
                .to_string()
                .starts_with("RUST_LOG=\"revtty=loud\" is not a log filter: "),
            "{error}"
        );
    }

    #[test]
    fn a_misspelt_or_stray_directive_is_refused() {
        // Each would otherwise be read as a target or an empty level and silence the service.
        for value in [
            "warning",
            "inf",
            "info ",
            " ",
            "revtty",
            "revtty:debug",
            "info,",
            ",",
            "=debug",
            "revtty=",
        ] {
            let error = log_filter(Some(OsStr::new(value))).expect_err(value);

            assert!(
                error
                    .to_string()
                    .starts_with(&format!("RUST_LOG={value:?} is not a log filter: ")),
                "{error}"
            );
        }
    }

    #[test]
    fn rejected_requests_are_never_logged_whatever_rust_log_says() {
        for value in ["", "trace", "axum=trace", "axum::rejection=trace"] {
            let filter = log_filter(Some(OsStr::new(value))).expect(value);

            assert!(
                !filter.would_enable("axum::rejection", &Level::ERROR),
                "{value}"
            );
        }
        let filter = log_filter(Some(OsStr::new("axum=trace"))).expect("filter");
        assert!(filter.would_enable("axum::serve", &Level::TRACE));
    }

    #[test]
    fn a_rust_log_that_is_not_utf8_is_refused() {
        use std::os::unix::ffi::OsStrExt;

        let error =
            log_filter(Some(OsStr::from_bytes(b"revtty=\xff"))).expect_err("an unreadable filter");

        assert_eq!(error.to_string(), "RUST_LOG is not valid UTF-8");
    }
}
