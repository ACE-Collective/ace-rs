//! `ace user`: accounts an operator makes from a shell. `ace user create-first` makes the first user
//! (PLAN.md 5.4), because ace4 ships no default account. It reads Postgres directly, so whoever can run it
//! already has the database, and it runs where `ace serve` does, with `ACE4_DATABASE_URL`. A password
//! never goes on the command line, where `ps` and a shell's history keep it. The rest of ace3's
//! `ace user` comes with the users router (5.6).

use std::io::{BufRead, Write};
use std::process::ExitCode;

use ace_core::db::{Db, DbConfig};
use ace_core::eligibility::Catalog;
use ace_core::orchestrator::Orchestrator;
use ace_service::{Password, Service, Username};
use anyhow::{Context, Result};
use clap::Subcommand;

use crate::App;

#[derive(Subcommand)]
pub enum UserCommand {
    /// Make the first user, holding every permission. It prints a generated password, once, unless
    /// --password-stdin gives one. It refuses if any user exists, unless --force.
    CreateFirst {
        username: String,
        /// Read the password from one line of standard input. It isn't hidden on a terminal, so pipe
        /// it, as from a secrets file.
        #[arg(long)]
        password_stdin: bool,
        /// Make this user even though users exist, such as when every admin's password is lost.
        #[arg(long)]
        force: bool,
    },
}

pub fn run(app: &App, command: UserCommand) -> Result<ExitCode> {
    let UserCommand::CreateFirst {
        username,
        password_stdin,
        force,
    } = command;
    let username = Username::new(&username)?;
    let password = if password_stdin {
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .context("reading the password")?;
        Password::new(line.trim_end_matches(['\r', '\n']))
    } else {
        Password::generate()?
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .context("starting the runtime")?;
    let printed = (!password_stdin).then(|| password.expose().to_owned());
    runtime.block_on(async {
        let db = Db::connect(&DbConfig::from_env("ace")?)
            .await
            .context("connecting to Postgres")?;
        db.migrate().await.context("migrating")?;
        // This makes no analysis, so no module matters to it.
        let orchestrator = Orchestrator::new(Catalog::new([]), app.modes());
        Service::new(db, orchestrator)
            .create_first_user(&username, password, force)
            .await?;
        anyhow::Ok(())
    })?;
    // Only now, so a refusal doesn't print a password that isn't anyone's.
    let mut out = std::io::stdout().lock();
    writeln!(out, "created user {}", username.as_str())?;
    if let Some(password) = printed {
        writeln!(out, "password (shown once): {password}")?;
    }
    Ok(ExitCode::SUCCESS)
}
