//! Serves recorded HTTP exchanges (`ace_testkit::replay`) as a long-running server, for the
//! Compose stack's end-to-end test (PLAN.md 2.30), so its lookups never reach the internet.
//!
//! ```text
//! replay-server --listen 0.0.0.0:443 --public http://responder:443 \
//!     --recording DIR[=PREFIX,PREFIX...]...
//! ```
//!
//! A request for `/<scheme>/<host>/<path>` gets the response recorded for
//! `<scheme>://<host>/<path>` in any of the recordings; anything else gets a 404. The bodies of
//! responses to URLs starting with one of a recording's prefixes have their URLs pointed at
//! `--public`. Each request is logged on stderr, with the ones nothing was recorded for marked.

use std::path::PathBuf;
use std::time::Duration;

use ace_testkit::replay::HttpReplay;

struct Args {
    listen: String,
    public: Option<String>,
    recordings: Vec<(PathBuf, Vec<String>)>,
}

fn parse() -> Result<Args, String> {
    let mut args = std::env::args().skip(1);
    let mut parsed = Args {
        listen: "0.0.0.0:443".to_owned(),
        public: None,
        recordings: Vec::new(),
    };
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or(format!("{arg} takes a value"));
        match arg.as_str() {
            "--listen" => parsed.listen = value()?,
            "--public" => parsed.public = Some(value()?),
            "--recording" => {
                let value = value()?;
                let (dir, prefixes) = value.split_once('=').unwrap_or((&value, ""));
                parsed.recordings.push((
                    dir.into(),
                    prefixes
                        .split(',')
                        .filter(|p| !p.is_empty())
                        .map(str::to_owned)
                        .collect(),
                ));
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    if parsed.recordings.is_empty() {
        return Err("no --recording".to_owned());
    }
    Ok(parsed)
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    let args = match parse() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("replay-server: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    let listener = match tokio::net::TcpListener::bind(&args.listen).await {
        Ok(listener) => listener,
        Err(e) => {
            eprintln!("replay-server: binding {}: {e}", args.listen);
            return std::process::ExitCode::from(2);
        }
    };
    let prefixes: Vec<Vec<&str>> = args
        .recordings
        .iter()
        .map(|(_, p)| p.iter().map(String::as_str).collect())
        .collect();
    let recordings: Vec<(&std::path::Path, &[&str])> = args
        .recordings
        .iter()
        .zip(&prefixes)
        .map(|((dir, _), p)| (dir.as_path(), p.as_slice()))
        .collect();
    let replay = match HttpReplay::serve(&recordings, listener, args.public.clone()).await {
        Ok(replay) => replay,
        Err(e) => {
            eprintln!("replay-server: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    eprintln!(
        "replay-server: serving {} recordings on {}",
        recordings.len(),
        args.listen
    );
    let mut logged = 0;
    let mut terminate =
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(e) => {
                eprintln!("replay-server: no SIGTERM handler: {e}");
                return std::process::ExitCode::from(2);
            }
        };
    loop {
        tokio::select! {
            _ = terminate.recv() => return std::process::ExitCode::SUCCESS,
            _ = tokio::signal::ctrl_c() => return std::process::ExitCode::SUCCESS,
            () = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
        let requests = replay.requests();
        let unmatched = replay.unmatched();
        for request in requests.iter().skip(logged) {
            let line = format!("{} {}", request.method, request.url);
            let mark = if unmatched.contains(&line) {
                " (not recorded: 404)"
            } else {
                ""
            };
            eprintln!("replay-server: {line}{mark}");
        }
        logged = requests.len();
    }
}
