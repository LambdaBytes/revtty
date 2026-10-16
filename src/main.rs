mod agent;
mod app;
mod cli;
mod client;
mod config;
mod error;
mod identity;
mod pairing;
mod protocol;
mod relay;
mod storage;
mod token;
mod transport;

use std::process::ExitCode;

use clap::Parser;

#[tokio::main]
async fn main() -> ExitCode {
    let args = cli::Args::parse();

    match app::run(args).await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
