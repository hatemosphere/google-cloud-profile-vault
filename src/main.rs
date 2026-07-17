mod app;
mod auth;
mod chrome;
mod cli;
mod config;
mod credentials;
mod keychain;
mod process;
mod secret;

use std::process::ExitCode;

use clap::Parser as _;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match app::run(cli::Cli::parse()).await {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("gcpv: {error:#}");
            ExitCode::FAILURE
        }
    }
}
