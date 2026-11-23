//! `ace user`: accounts an operator makes from a shell. `ace user create-first` makes the first user
//! (PLAN.md 5.4), because ace-rs ships no default account. It reads Postgres directly, so whoever can run it
//! already has the database, and it runs where `ace serve` does, with `ACE_RS_DATABASE_URL`. A password
//! never goes on the command line, where `ps` and a shell's history keep it.
//!
//! `ace user create-key` makes an API key that stands for a service rather than a user, with the grants
//! it names, for a script such as `tests/e2e/run`'s submissions or `ace compare` (PLAN.md 5.5). It acts as
//! the component `bootstrap`, as `create-first` does, and prints the token once. The rest of ace3's
//! `ace user` comes with the users router (5.6).

use std::io::{BufRead, Write};
use std::process::ExitCode;

use ace_core::db::{Db, DbConfig};
use ace_core::eligibility::Catalog;
use ace_core::orchestrator::Orchestrator;
use ace_service::{Actor, Component, Password, PermissionPattern, Service, Username};
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
    /// Make an API key with no owner, holding what each --grant names, and print its token, once.
    CreateKey {
        /// What the key is for, such as `e2e-submitter`.
        name: String,
        /// A permission the key holds, as `major:minor`, such as `alert:create`. Repeat for more.
        #[arg(long = "grant", required = true, value_name = "MAJOR:MINOR")]
        grants: Vec<String>,
    },
}

fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .context("starting the runtime")
}

async fn service(app: &App) -> Result<Service> {
    let db = Db::connect(&DbConfig::from_env("ace")?)
        .await
        .context("connecting to Postgres")?;
    db.migrate().await.context("migrating")?;
    // This makes no analysis, so no module matters to it.
    let orchestrator = Orchestrator::new(Catalog::new([]), app.modes());
    Ok(Service::new(db, orchestrator))
}

pub fn run(app: &App, command: UserCommand) -> Result<ExitCode> {
    match command {
        UserCommand::CreateFirst {
            username,
            password_stdin,
            force,
        } => create_first(app, &username, password_stdin, force),
        UserCommand::CreateKey { name, grants } => create_key(app, &name, &grants),
    }
}

fn create_key(app: &App, name: &str, grants: &[String]) -> Result<ExitCode> {
    let patterns = grants
        .iter()
        .map(|grant| {
            let (major, minor) = grant
                .split_once(':')
                .with_context(|| format!("{grant:?} isn't major:minor"))?;
            Ok(PermissionPattern::new(major, minor)?)
        })
        .collect::<Result<Vec<_>>>()?;
    let bootstrap = Actor::Internal {
        id: Component::new("bootstrap")?,
    };
    let key = runtime()?.block_on(async {
        let service = service(app).await?;
        let key = service
            .create_api_key(&bootstrap, name, None, &patterns)
            .await?;
        anyhow::Ok(key)
    })?;
    let mut out = std::io::stdout().lock();
    let held: Vec<String> = patterns.iter().map(ToString::to_string).collect();
    writeln!(
        out,
        "created API key {} named {name}, holding {}",
        key.id.0,
        held.join(", ")
    )?;
    writeln!(out, "token (shown once): {}", key.token.expose())?;
    Ok(ExitCode::SUCCESS)
}

fn create_first(app: &App, username: &str, password_stdin: bool, force: bool) -> Result<ExitCode> {
    let username = Username::new(username)?;
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
    let printed = (!password_stdin).then(|| password.expose().to_owned());
    runtime()?.block_on(async {
        service(app)
            .await?
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
