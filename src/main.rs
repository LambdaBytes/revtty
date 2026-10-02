mod agent;
mod app;
mod cli;
mod client;
mod config;
mod error;
mod identity;
mod protocol;
mod relay;
mod storage;
mod token;
mod transport;

use clap::Parser;

#[tokio::main]
async fn main() {
    let args = cli::Args::parse();

    if let Err(error) = app::run(args).await {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
