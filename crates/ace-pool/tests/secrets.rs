//! PLAN.md 2.24's Done check: a pool resolves only the secrets its own modules' manifests
//! declare (ace3 #1009). Two pools start from one site overlay that names a source for every
//! secret, and the environment holds them all. The resolver pool, which runs the example
//! resolver, reads only `resolver_token`; the Splunk pool reads only the Splunk module's two.
//! Neither asks for the other's variable or file, and each one's startup log lists only its
//! own. A resolver task then runs through the lease API with the secret its pool resolved.

use crate::common;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ace_mod_splunk::SplunkAnalyzer;
use ace_pool::client::LeaseClient;
use ace_pool::modules::{Modules, Registry};
use ace_pool::pool::{AsyncPool, PoolDefinition};
use ace_sdk::Overlay;
use ace_sdk::example::{RESOLVER_MANIFEST, Resolver};
use tokio_util::sync::CancellationToken;

use common::{Core, TOKEN, root_with_tasks, task_of, wait_until_idle};

/// Collects what tracing writes.
#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Logs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// What starting a pool did: its modules, the variables it asked for, and its startup log.
struct Started {
    modules: Modules,
    asked: Vec<String>,
    log: String,
}

/// Starts a pool of `registry`'s modules from `overlay`, with an environment that holds every
/// variable in `env` and records each one asked for.
fn start(
    pool: &str,
    registry: &Registry,
    overlay: &Overlay,
    env: &BTreeMap<&str, &str>,
) -> Started {
    let logs = Logs::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let asked = Mutex::new(Vec::new());
    let lookup = |name: &str| {
        asked.lock().expect("lock").push(name.to_owned());
        env.get(name).map(|v| (*v).to_owned())
    };
    let modules =
        tracing::subscriber::with_default(subscriber, || registry.start(pool, overlay, &lookup))
            .expect("the pool starts");
    let log = String::from_utf8(logs.0.lock().expect("lock").clone()).expect("text");
    println!("{pool}:\n{log}");
    Started {
        modules,
        asked: asked.into_inner().expect("lock"),
        log,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pool_resolves_only_the_secrets_its_modules_declare() {
    let dir = tempfile::tempdir().expect("a directory");
    let token_file = dir.path().join("splunk_default_token");
    std::fs::write(&token_file, "ace-rs-fake-splunk-token\n").expect("writes");
    let overlay = Overlay::from_yaml(&format!(
        "connections:
  default:
    type: splunk
    settings: {{host: splunk.example.com, username: ace-rs}}
    secrets: {{password: splunk_default_password, token: splunk_default_token}}
modules:
  splunk_api:
    instances:
      proxy_domain_lookup:
        connections: {{splunk: default}}
        settings:
          query: index=proxy hostname=\"<O_VALUE>\"
secrets:
  resolver_token: env:ACE_RS_TEST_RESOLVER_TOKEN
  splunk_default_password: env:ACE_RS_TEST_SPLUNK_PASSWORD
  splunk_default_token: file:{}
",
        token_file.display()
    ))
    .expect("the overlay loads");
    let env = BTreeMap::from([
        ("ACE_RS_TEST_RESOLVER_TOKEN", "ace-rs-fake-resolver-token"),
        ("ACE_RS_TEST_SPLUNK_PASSWORD", "ace-rs-fake-splunk-password"),
    ]);

    let resolvers = start(
        "resolvers",
        &Registry::new().lookup::<Resolver>(),
        &overlay,
        &env,
    );
    assert_eq!(resolvers.asked, ["ACE_RS_TEST_RESOLVER_TOKEN"]);
    assert!(
        resolvers
            .log
            .contains(r#"resolved the pool's secrets pool="resolvers" secrets=["resolver_token"]"#),
        "{}",
        resolvers.log
    );
    // nothing about the Splunk pool's secrets or section, not even a warning
    assert!(!resolvers.log.contains("splunk"), "{}", resolvers.log);

    let splunk = start(
        "splunk",
        &Registry::new().lookup::<SplunkAnalyzer>(),
        &overlay,
        &env,
    );
    // the token comes from its file, which the resolver pool never opened
    assert_eq!(splunk.asked, ["ACE_RS_TEST_SPLUNK_PASSWORD"]);
    assert!(
        splunk.log.contains(
            r#"resolved the pool's secrets pool="splunk" secrets=["splunk_default_password", "splunk_default_token"]"#
        ),
        "{}",
        splunk.log
    );
    assert!(!splunk.log.contains("resolver"), "{}", splunk.log);
    assert!(splunk.modules.lookup("proxy_domain_lookup").is_some());

    // a declared secret with no source is a warning, and the pool still starts
    let bare = start(
        "bare",
        &Registry::new().lookup::<Resolver>(),
        &Overlay::default(),
        &env,
    );
    assert!(bare.asked.is_empty());
    assert!(
        bare.log.contains(r#"secrets=[]"#) && bare.log.contains("WARN"),
        "{}",
        bare.log
    );
    assert!(
        bare.log.contains("secret=\"resolver_token\""),
        "{}",
        bare.log
    );

    // the resolver pool's module runs with the secret its pool resolved
    let core = Core::start(
        vec![RESOLVER_MANIFEST],
        &["example_resolver"],
        Duration::from_secs(30),
    )
    .await;
    let root = root_with_tasks(&core, &["www.example.com".to_owned()], "example_resolver").await;
    let definition = PoolDefinition {
        name: "resolvers".to_owned(),
        modules: Arc::new(resolvers.modules).into(),
        concurrency: 1,
        sandbox: Default::default(),
    };
    let client = LeaseClient::new(&core.url, TOKEN, "pool").expect("a client");
    let pool = AsyncPool::new(client, &definition).lease_wait(Duration::from_secs(1));
    let stop = CancellationToken::new();
    let running = tokio::spawn({
        let stop = stop.clone();
        async move { pool.run(stop).await }
    });
    wait_until_idle(&core, root, Duration::from_secs(30)).await;
    stop.cancel();
    running.await.expect("the pool stops");
    assert_eq!(
        task_of(&core, root, "example_resolver").await,
        ("done".to_owned(), None)
    );
}
