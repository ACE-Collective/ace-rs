//! Alert routing (PLAN.md 7.13): ace3's `saq/alert_routing/`, which decides which queue an alert belongs
//! in, and which a site extends with routers of its own.
//!
//! # The pieces
//!
//! - A **router** (`Router`, ace3's `AlertRouter`) reads an alert (`Alert`) and returns a `Decision`, a queue
//!   and a reason, or None to let the next router decide. Its name and priority are the registry's, as
//!   ace3's constructor takes them from its config entry.
//! - The **registry** (`Routers`, ace3's `registry.py`) is the built-in `detection_queue` (priority 500,
//!   `DetectionQueue`), the routers the binary adds (`Routers::with`, `App::alert_router`) and those the
//!   overlay's `alert_routers:` configures from the types the binary has (`RouterTypes`,
//!   `App::alert_router_type`). They run lowest priority first, the built-in first on a tie, and the first
//!   decision wins; the registry puts the deciding router's name on it (`Routed`).
//! - **Moving** an alert (`move_alert`, ace3's `move_alert_to_queue`) updates its queue and records the move
//!   in `analysis.queue_changes`, with who made it and, for a router, the router's name, in the caller's
//!   transaction, which is a `Gate::write` with its audit row. `last_queue_change` is ace3's
//!   `get_last_queue_change`, the newest move, which says where the alert came from.
//!
//! # Where it runs
//!
//! On 2.11's completion event (#848). The transaction that ends an alert's analysis pass adds a row to
//! `queue.routing_due` (`ace_core::queue::check_completion`), and `ace serve`'s routing worker
//! (`run_worker`), woken by the completion's notification (`ace_core::queue::Completions`) or its poll, takes
//! each row (`Service::route_due`): in one transaction, as the component `alert_routing`, which holds
//! `alert:queue`, it locks the root, reads the alert, runs the routers, moves it when one decided another
//! queue, and removes the row. A row waits while `ace serve` is down, so no completion is lost; replicas take
//! rows with `SKIP LOCKED`.
//!
//! An alert's first routing is ace3's `PRE_INSERT` (`Stage::Alerted`); every later one is its
//! `POST_ANALYSIS` (`Stage::Analyzed`). Either moves only an OPEN alert that no analyst owns, judged under
//! the root's lock, so a disposition or a take made meanwhile keeps the alert where it is.
//!
//! # Extending it
//!
//! A router is a type implementing `Router`, in any crate. A site's binary adds one through `ace_app::App`:
//! `alert_router(name, priority, router)` for one it always runs, or `alert_router_type(type, builder)` for
//! one its overlay names, places and configures, as an ace3 integration's `alert_routers:` entry does:
//!
//! ```yaml
//! alert_routers:
//!   example_tag_router:    # its name, recorded with every move it makes
//!     type: example_tag    # what App::alert_router_type registered
//!     priority: 400        # below 500 runs before detection_queue
//!     settings: {tag: example_route, queue: example}
//! ```
//!
//! SVS's marker router (PLAN.md 7.10 batch 7, `crate::svs_association::MarkerRouter`) is such a router: it
//! implements `Router`, reads the attributions the core's SVS hook wrote at the end of the pass (in `tx`,
//! under the root's lock, judging nothing again), and every binary runs it: `App::alert_routers` adds
//! `svs_marker` at 100, ahead of `detection_queue`, as ace3's `saq.default.yaml` adds it, so a site's
//! binary can't lack it and a site's router can't take its name (7.10 batch 8). Holding an alert a person moved through SVS reads `Alert::last_change`;
//! moving one back reads its `from_queue`. Nothing here changed for it but the owner check.
//!
//! The contract is ace3's: a router never changes the tree (the move is the only change made for it); it
//! should not fail, and one that does, or panics, is logged and skipped, and the next one runs; it's shared
//! by every task of its process, so it must be `Send + Sync`; it's cheap when it has nothing to do. Its reads
//! and any rows of its own go in `tx`, inside a savepoint that's rolled back when it fails, so a failed
//! router never fails the routing.
//!
//! # ace3's tests
//!
//! `ace3/tests/saq/alert_routing/`'s cases are `tests/service.rs`'s `routing_*` tests, each named for its
//! case, and `ace-site-example`'s for the example integration's router; that file's docs map each one.
//!
//! # What differs from ace3
//!
//! - Routing runs when an alert's pass completes, in `ace serve`, where ace3 runs it inside every alert
//!   insert (`ALERT()`) and after every engine pass, in whichever process does those. So the first routing
//!   sees the alert after the pass that made it an alert, its correlation analysis included: ace-rs makes a
//!   root an alert when its detection lands and goes on in correlation mode in the same pass, where ace3
//!   inserts the alert at the end of the detection pass and analyzes it again. An alert a submitter made
//!   (a hunt) is first routed after its analysis too, not before it.
//! - There is no `final` flag. A pass completes in ace-rs only when nothing is queued, delayed or running, so
//!   every routing is after what ace3 calls the final pass; a cancelled pass completes too, as ace3's
//!   aborted pass is final.
//! - The first routing moves only an OPEN alert nobody has taken too, since in ace-rs the alert existed while
//!   it was analyzed. ace3's owner check (an analyst who took the alert keeps it) is in `move_alert`,
//!   over `analysis.roots.owner_id` (7.10 batch 7a). ace3's automation user owns
//!   what it dispositions and counts as nobody; here a component never owns an alert.
//! - The routers are built once when `ace serve` starts and never change, and an overlay entry that can't be
//!   built (an unknown type, a built-in's name, settings its type refuses) stops startup, as the rest of the
//!   overlay does, where ace3 logs it and loads the others. There's no reload, so ace3's lock-free swap has
//!   nothing to do.
//! - A router's move is made by the component `alert_routing`, which every move records, with the router's
//!   name; ace3 records no user. Every move has an audit row, as ace3's `log_audit` line.
//! - The tree carries no queue of its own to reconcile: the root's row is the alert's one queue.
//! - ace3 refreshes a moved alert's search payload; ace-rs's search comes with 7.11.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::panic::AssertUnwindSafe;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

/// The routing transaction a router reads in, re-exported so a site's router needs only this crate.
pub use ace_core::db::Tx;
use ace_core::tree::{DEFAULT_QUEUE, check_queue_name};
use ace_sdk::AlertRouterSection;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::actor::{Actor, Component, UserId};
use crate::alerts::no_alert;
use crate::gate::{Audited, Change, Recorded, Target};
use crate::observables::OPEN;
use crate::permission::ALERT_QUEUE;
use crate::{Service, ServiceError};

/// The built-in router's name, ace3's `DETECTION_QUEUE_ROUTER_NAME`.
pub const DETECTION_QUEUE: &str = "detection_queue";
/// Its priority, ace3's `DETECTION_QUEUE_ROUTER_PRIORITY`.
pub const DETECTION_QUEUE_PRIORITY: i32 = 500;
/// The component routing acts as, which migration 0050 grants `alert:queue`.
pub const ROUTING_COMPONENT: &str = "alert_routing";
/// The longest reason a move keeps, `analysis.queue_changes.reason`'s, ace3's `String(1024)`.
pub const MAX_REASON_CHARS: usize = 1024;
/// The longest router name, `analysis.queue_changes.router`'s, ace3's `String(64)`.
pub const MAX_ROUTER_NAME_CHARS: usize = 64;

/// When a router runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// The alert's first routing, after the pass that made it an alert: ace3's `PRE_INSERT`.
    Alerted,
    /// Every later one, after another pass over the alert: ace3's `POST_ANALYSIS`.
    Analyzed,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Alerted => "alerted",
            Stage::Analyzed => "analyzed",
        }
    }
}

/// A queue's name, checked (`ace_core::tree::check_queue_name`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Queue(String);

impl Queue {
    pub fn new(name: impl Into<String>) -> Result<Queue, String> {
        let name = name.into();
        check_queue_name(&name)?;
        Ok(Queue(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Queue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A router's decision, ace3's `RouteDecision`: send the alert to `queue`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub queue: Queue,
    pub reason: String,
}

impl Decision {
    /// A decision, held to ace3's rules: a queue that isn't blank, at most 64 characters, and here no
    /// control characters, with a reason of at most `MAX_REASON_CHARS`.
    pub fn new(queue: impl Into<String>, reason: impl Into<String>) -> Result<Decision, String> {
        let reason = reason.into();
        if reason.chars().count() > MAX_REASON_CHARS {
            return Err(format!("a reason is at most {MAX_REASON_CHARS} characters"));
        }
        Ok(Decision {
            queue: Queue::new(queue)?,
            reason,
        })
    }
}

/// A decision with the name of the router that made it, which the registry sets whatever the router said.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Routed {
    pub router: String,
    pub queue: Queue,
    pub reason: String,
}

/// One of an alert's detections, ace3's `DetectionPoint` as a router reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionPoint {
    pub description: String,
    /// The queue it asks for, such as a YARA rule's `queue` meta.
    pub queue: Option<String>,
    pub signature_uuid: Option<String>,
    /// The observable it's on, as (type, value), or None for one on the root.
    pub observable: Option<(String, String)>,
}

/// One move of an alert between queues, ace3's `AlertQueueChange`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueChange {
    pub id: i64,
    pub from_queue: String,
    pub to_queue: String,
    pub reason: String,
    /// The router that decided it, or None for a person's move.
    pub router: Option<String>,
    /// Who made it, as `service.actor`'s JSON.
    pub moved_by: Value,
    pub changed_at: DateTime<Utc>,
}

/// What a router reads: the alert as its pass left it, read under the root's lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alert {
    pub root: Uuid,
    pub description: String,
    /// The pass that completed.
    pub pass: i32,
    /// The queue it's in now.
    pub queue: String,
    /// None or OPEN for an alert nobody has dispositioned.
    pub disposition: Option<String>,
    pub alerted_at: DateTime<Utc>,
    /// Every detection, on the root and on its observables, ace3's `all_detection_points`, oldest first.
    pub detections: Vec<DetectionPoint>,
    /// Every tag on its observables and results.
    pub tags: BTreeSet<String>,
    /// The newest move, ace3's `get_last_queue_change`.
    pub last_change: Option<QueueChange>,
}

impl Alert {
    pub fn is_open(&self) -> bool {
        self.disposition.as_deref().is_none_or(|d| d == OPEN)
    }

    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.contains(tag)
    }
}

/// What a router's `route` returns: a decision, none, or why it failed, which is logged.
pub type RouteFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<Decision>, String>> + Send + 'a>>;

/// Decides which queue an alert belongs in, ace3's `AlertRouter`. See the module's docs for the contract.
pub trait Router: Send + Sync {
    /// A decision to send the alert to a queue, or None to let the next router decide. `tx` is the routing's
    /// transaction, with the root locked, inside a savepoint of this router's own.
    fn route<'a>(&'a self, alert: &'a Alert, stage: Stage, tx: &'a mut Tx<'_>) -> RouteFuture<'a>;
}

/// The built-in router for a detection's `queue` (a YARA rule's `queue` meta, say), ace3's
/// `DetectionQueueRouter`: when the alert is first routed, and only when every detection asks for a queue,
/// the alert goes to the first of them by name. A detection that asks for none makes the alert a real one,
/// which stays where analysts see it, and a queue other than the default, which a submitter or a hunt set,
/// is never overridden.
#[derive(Debug, Clone, Copy, Default)]
pub struct DetectionQueue;

impl DetectionQueue {
    /// The decision, apart from the registry: ace3's `route`.
    pub fn decide(alert: &Alert, stage: Stage) -> Result<Option<Decision>, String> {
        // only when the alert is created, when its whole set of detections is known
        if stage != Stage::Alerted || alert.queue != DEFAULT_QUEUE || alert.detections.is_empty() {
            return Ok(None);
        }
        if alert.detections.iter().any(|d| d.queue.is_none()) {
            // at least one plain detection: the default queue
            return Ok(None);
        }
        let requested: BTreeSet<&str> = alert
            .detections
            .iter()
            .filter_map(|d| d.queue.as_deref())
            .filter(|q| !q.is_empty())
            .collect();
        let Some(chosen) = requested.first() else {
            return Ok(None);
        };
        if requested.len() > 1 {
            tracing::warn!(
                alert = %alert.root,
                ?requested,
                chosen,
                "an alert's detections ask for several queues; routing it to the first"
            );
        }
        Decision::new(*chosen, "every detection point requests this queue").map(Some)
    }
}

impl Router for DetectionQueue {
    fn route<'a>(&'a self, alert: &'a Alert, stage: Stage, _: &'a mut Tx<'_>) -> RouteFuture<'a> {
        Box::pin(async move { DetectionQueue::decide(alert, stage) })
    }
}

/// What builds a router of a type from its overlay entry's `settings` (null when left out), or says why it
/// can't: ace3's class constructor with its `kwargs`.
pub type RouterBuilder = Arc<dyn Fn(&Value) -> Result<Arc<dyn Router>, String> + Send + Sync>;

/// A router's settings as its type's own struct, which should refuse unknown keys, as ace3's
/// `AlertRouter.__init__` refuses unexpected arguments. Null reads as `{}`.
pub fn settings<T: DeserializeOwned>(settings: &Value) -> Result<T, String> {
    let value = match settings {
        Value::Null => Value::Object(serde_json::Map::new()),
        other => other.clone(),
    };
    serde_json::from_value(value).map_err(|e| format!("its settings: {e}"))
}

/// The router types the overlay's `alert_routers:` entries can name, by type name.
#[derive(Clone, Default)]
pub struct RouterTypes {
    types: BTreeMap<String, RouterBuilder>,
}

impl RouterTypes {
    pub fn new() -> RouterTypes {
        RouterTypes::default()
    }

    /// Adds a type. One with a name already added takes its place.
    pub fn with(mut self, kind: &str, build: RouterBuilder) -> RouterTypes {
        self.types.insert(kind.to_owned(), build);
        self
    }

    pub fn names(&self) -> Vec<&str> {
        self.types.keys().map(String::as_str).collect()
    }
}

impl std::fmt::Debug for RouterTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.types.keys()).finish()
    }
}

#[derive(Clone)]
struct Entry {
    name: String,
    priority: i32,
    builtin: bool,
    router: Arc<dyn Router>,
}

/// The routers, in the order they run: ace3's registry. Built when `ace serve` starts and fixed after.
#[derive(Clone)]
pub struct Routers {
    entries: Arc<Vec<Entry>>,
}

impl Default for Routers {
    fn default() -> Routers {
        Routers::builtin()
    }
}

impl std::fmt::Debug for Routers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.names()).finish()
    }
}

fn check_router_name(name: &str) -> Result<(), String> {
    if name.trim().is_empty()
        || name.chars().count() > MAX_ROUTER_NAME_CHARS
        || name.chars().any(char::is_control)
    {
        return Err(format!(
            "a router's name is 1 to {MAX_ROUTER_NAME_CHARS} characters with no control characters, not {name:?}"
        ));
    }
    Ok(())
}

impl Routers {
    /// The built-in routers alone: `detection_queue`.
    pub fn builtin() -> Routers {
        Routers {
            entries: Arc::new(vec![Entry {
                name: DETECTION_QUEUE.to_owned(),
                priority: DETECTION_QUEUE_PRIORITY,
                builtin: true,
                router: Arc::new(DetectionQueue),
            }]),
        }
    }

    /// The routers with one more, ace3's `register_alert_router`. A name must be unique and not a built-in's.
    pub fn with(
        self,
        name: &str,
        priority: i32,
        router: Arc<dyn Router>,
    ) -> Result<Routers, String> {
        check_router_name(name)?;
        if let Some(there) = self.entries.iter().find(|e| e.name == name) {
            return Err(if there.builtin {
                format!("{name:?} is the name of a built-in router")
            } else {
                format!("an alert router named {name:?} is there already")
            });
        }
        let mut entries = (*self.entries).clone();
        entries.push(Entry {
            name: name.to_owned(),
            priority,
            builtin: false,
            router,
        });
        // ascending priority, the built-ins first on a tie, and otherwise as added
        entries.sort_by_key(|e| (e.priority, !e.builtin));
        Ok(Routers {
            entries: Arc::new(entries),
        })
    }

    /// The routers with those the overlay's `alert_routers:` configures, each built by its type, ace3's
    /// `load_alert_routers`. Every entry that can't be built is named in the error, which stops startup.
    pub fn configured(
        self,
        types: &RouterTypes,
        section: &BTreeMap<String, AlertRouterSection>,
    ) -> Result<Routers, String> {
        let mut routers = self;
        let mut errors = Vec::new();
        for (name, entry) in section {
            let Some(build) = types.types.get(&entry.kind) else {
                errors.push(format!(
                    "alert_routers.{name}: this binary has no router type {:?}; it has {:?}",
                    entry.kind,
                    types.names()
                ));
                continue;
            };
            let built = build(entry.settings.as_ref().unwrap_or(&Value::Null))
                .and_then(|router| routers.clone().with(name, entry.priority, router));
            match built {
                Ok(with) => routers = with,
                Err(e) => errors.push(format!("alert_routers.{name}: {e}")),
            }
        }
        if errors.is_empty() {
            Ok(routers)
        } else {
            Err(errors.join("; "))
        }
    }

    /// Each router's name and priority, in the order they run.
    pub fn names(&self) -> Vec<(&str, i32)> {
        self.entries
            .iter()
            .map(|e| (e.name.as_str(), e.priority))
            .collect()
    }

    /// Runs the routers in order and returns the first decision with its router's name, ace3's
    /// `route_alert`. A router that fails or panics is logged and skipped, and whatever it did in `tx` is
    /// rolled back to its savepoint.
    pub async fn decide(
        &self,
        alert: &Alert,
        stage: Stage,
        tx: &mut Tx<'_>,
    ) -> Result<Option<Routed>, ServiceError> {
        for entry in self.entries.iter() {
            let mut savepoint = tx.savepoint().await?;
            let outcome = CatchUnwind(entry.router.route(alert, stage, &mut savepoint)).await;
            let decision = match outcome {
                Ok(Ok(decision)) => {
                    savepoint.commit().await?;
                    decision
                }
                Ok(Err(e)) | Err(e) => {
                    savepoint.rollback().await?;
                    tracing::error!(
                        alert = %alert.root,
                        router = entry.name,
                        stage = stage.as_str(),
                        "alert router {} failed on {}; skipping it: {e}",
                        entry.name,
                        alert.root
                    );
                    continue;
                }
            };
            let Some(decision) = decision else {
                continue;
            };
            tracing::info!(
                alert_uuid = %alert.root,
                stage = stage.as_str(),
                router = entry.name,
                queue = decision.queue.as_str(),
                reason = decision.reason,
                "alert router decided a queue"
            );
            return Ok(Some(Routed {
                router: entry.name.clone(),
                queue: decision.queue,
                reason: decision.reason,
            }));
        }
        Ok(None)
    }
}

/// A future whose panic is caught and returned as an error, so a router's panic is a failure like its error.
struct CatchUnwind<'a>(RouteFuture<'a>);

impl Future for CatchUnwind<'_> {
    type Output = Result<Result<Option<Decision>, String>, String>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inner = &mut self.0;
        match std::panic::catch_unwind(AssertUnwindSafe(|| inner.as_mut().poll(cx))) {
            Ok(Poll::Pending) => Poll::Pending,
            Ok(Poll::Ready(result)) => Poll::Ready(Ok(result)),
            Err(panic) => {
                let message = panic
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_owned())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "a panic".to_owned());
                Poll::Ready(Err(format!("it panicked: {message}")))
            }
        }
    }
}

/// What a routing did, for its caller and its tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteOutcome {
    pub root: Uuid,
    pub pass: i32,
    /// None when the routers didn't run: a later pass had started, whose own completion routes the alert,
    /// or the pass was routed already.
    pub stage: Option<Stage>,
    /// The first decision, if any router made one.
    pub decision: Option<Routed>,
    /// The move it made, as (from, to): None when there was no decision, the alert was in that queue
    /// already, it was dispositioned, or an analyst owns it.
    pub moved: Option<(String, String)>,
}

/// A move's audit row, before and after.
#[derive(Serialize)]
struct QueueRecord<'a> {
    queue: &'a str,
}

impl Recorded for QueueRecord<'_> {}

/// What a router's move records beside it.
#[derive(Serialize)]
struct MoveRecord<'a> {
    router: Option<&'a str>,
    reason: &'a str,
    stage: Option<Stage>,
    pass: Option<i32>,
}

impl Recorded for MoveRecord<'_> {}

/// The user an actor acts as: themselves, or a key's owner. None for a key that belongs to nobody and for
/// ACE's components, who own no alert.
pub(crate) fn acting_user(actor: &Actor) -> Option<UserId> {
    match actor {
        Actor::User { id, .. } => Some(*id),
        Actor::ApiKey { owner, .. } => *owner,
        Actor::Internal { .. } => None,
    }
}

/// Moves the alert to `to`, ace3's `move_alert_to_queue`, in the caller's write: its queue and the row that
/// records the move, with `router`'s name for a router's move and who made it. Returns the queue it came from,
/// or None when it's already there, isn't an alert, has a disposition, or an analyst other than
/// `or_owned_by` owns it (ace3's `open_unless_owned_by_others`: None for a router's move, the person for
/// one they make through SVS), judged by the row under its lock, so an analyst who takes or dispositions it
/// meanwhile keeps it where it is. ACE's components never own an alert, so ace3's automation user, which
/// counts as nobody there, has nothing to stand for here. The caller locks the root first and writes the
/// audit row.
pub(crate) async fn move_alert(
    tx: &mut Tx<'_>,
    root: Uuid,
    to: &Queue,
    reason: &str,
    router: Option<&str>,
    actor: &Actor,
    or_owned_by: Option<UserId>,
) -> Result<Option<String>, ServiceError> {
    if reason.chars().count() > MAX_REASON_CHARS {
        return Err(ServiceError::InvalidRequest(format!(
            "a reason is at most {MAX_REASON_CHARS} characters"
        )));
    }
    let from = sqlx::query_scalar!(
        r#"SELECT queue AS "queue!: String" FROM analysis.roots
           WHERE id = $1 AND alerted_at IS NOT NULL
             AND (disposition IS NULL OR disposition = 'OPEN')
             AND (owner_id IS NULL OR owner_id = $2)
           FOR UPDATE"#,
        root,
        or_owned_by.map(|user| user.0),
    )
    .fetch_optional(tx.conn())
    .await?;
    let Some(from) = from.filter(|from| from != to.as_str()) else {
        return Ok(None);
    };
    sqlx::query!(
        "UPDATE analysis.roots SET queue = $2::text WHERE id = $1",
        root,
        to.as_str(),
    )
    .execute(tx.conn())
    .await?;
    sqlx::query!(
        "INSERT INTO analysis.queue_changes (root_id, from_queue, to_queue, reason, router, moved_by)
         VALUES ($1, $2::text, $3::text, $4, $5, $6::jsonb)",
        root,
        from,
        to.as_str(),
        reason,
        router,
        sqlx::types::Json(actor) as _,
    )
    .execute(tx.conn())
    .await?;
    tracing::info!(
        alert_uuid = %root,
        from_queue = from,
        to_queue = to.as_str(),
        router,
        actor = %actor,
        reason,
        "alert moved to queue"
    );
    Ok(Some(from))
}

/// The alert's newest move, ace3's `get_last_queue_change`, or None if it never moved.
pub(crate) async fn last_queue_change(
    tx: &mut Tx<'_>,
    root: Uuid,
) -> Result<Option<QueueChange>, ServiceError> {
    Ok(sqlx::query!(
        r#"SELECT id, from_queue AS "from_queue!: String", to_queue AS "to_queue!: String", reason,
                  router, moved_by AS "moved_by!: Value", changed_at
           FROM analysis.queue_changes WHERE root_id = $1 ORDER BY id DESC LIMIT 1"#,
        root,
    )
    .fetch_optional(tx.conn())
    .await?
    .map(|row| QueueChange {
        id: row.id,
        from_queue: row.from_queue,
        to_queue: row.to_queue,
        reason: row.reason,
        router: row.router,
        moved_by: row.moved_by,
        changed_at: row.changed_at,
    }))
}

/// The alert as a router reads it, with its root locked, or None when the root isn't an alert.
async fn read_alert(
    tx: &mut Tx<'_>,
    root: Uuid,
) -> Result<Option<(Alert, i32, Option<i32>)>, ServiceError> {
    let Some(row) = sqlx::query!(
        r#"SELECT description, queue AS "queue!: String", disposition, alerted_at, pass, completed_pass,
                  routed_pass
           FROM analysis.roots WHERE id = $1 FOR UPDATE"#,
        root,
    )
    .fetch_optional(tx.conn())
    .await?
    else {
        return Ok(None);
    };
    let Some(alerted_at) = row.alerted_at else {
        return Ok(None);
    };
    let detections = sqlx::query!(
        r#"SELECT d.description, d.queue, d.signature_uuid, o.type AS "type?", o.value AS "value?"
           FROM analysis.detections d
           LEFT JOIN analysis.observables o ON o.root_id = d.root_id AND o.id = d.observable_id
           WHERE d.root_id = $1 ORDER BY d.id"#,
        root,
    )
    .fetch_all(tx.conn())
    .await?
    .into_iter()
    .map(|d| DetectionPoint {
        description: d.description,
        queue: d.queue,
        signature_uuid: d.signature_uuid,
        observable: d.r#type.zip(d.value),
    })
    .collect();
    let tags = sqlx::query_scalar!(
        r#"SELECT DISTINCT t.tag AS "tag!" FROM (
             SELECT unnest(tags) AS tag FROM analysis.observables WHERE root_id = $1
             UNION ALL SELECT unnest(tags) FROM analysis.results WHERE root_id = $1
           ) t"#,
        root,
    )
    .fetch_all(tx.conn())
    .await?
    .into_iter()
    .collect();
    let last_change = last_queue_change(tx, root).await?;
    Ok(Some((
        Alert {
            root,
            description: row.description,
            pass: row.completed_pass,
            queue: row.queue,
            disposition: row.disposition,
            alerted_at,
            detections,
            tags,
            last_change,
        },
        row.pass,
        row.routed_pass,
    )))
}

impl Service {
    /// The service with the binary's routers (`Routers`), the built-in one alone unless it's given others.
    pub fn with_routers(mut self, routers: Routers) -> Self {
        self.routers = routers;
        self
    }

    /// The routers routing runs.
    pub fn routers(&self) -> &Routers {
        &self.routers
    }

    /// Routes the next alert whose pass completed (`queue.routing_due`): runs the routers over it and moves it
    /// to the queue the first one decides, with an audit row for the move. Returns None when nothing is due.
    /// It needs `alert:queue`, which ACE's routing component holds (`routing_actor`); `run_worker` calls it.
    pub async fn route_due(&self, actor: &Actor) -> Result<Option<RouteOutcome>, ServiceError> {
        let routers = &self.routers;
        self.gate
            .write(actor, "route_due", &ALERT_QUEUE, &|tx| {
                Box::pin(async move {
                    sqlx::raw_sql("SET LOCAL statement_timeout = '30s'")
                        .execute(tx.conn())
                        .await?;
                    let Some(due) = sqlx::query!(
                        "SELECT root_id, pass FROM queue.routing_due
                         ORDER BY due_at, root_id, pass LIMIT 1 FOR UPDATE SKIP LOCKED"
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    else {
                        return Ok(Audited::unchanged(None));
                    };
                    sqlx::query!(
                        "DELETE FROM queue.routing_due WHERE root_id = $1 AND pass = $2",
                        due.root_id,
                        due.pass,
                    )
                    .execute(tx.conn())
                    .await?;
                    let skipped = RouteOutcome {
                        root: due.root_id,
                        pass: due.pass,
                        stage: None,
                        decision: None,
                        moved: None,
                    };
                    let Some((alert, pass, routed_pass)) = read_alert(tx, due.root_id).await?
                    else {
                        return Ok(Audited::unchanged(Some(skipped)));
                    };
                    // a later pass runs, or ran: its completion routes the alert
                    if pass != alert.pass
                        || alert.pass != due.pass
                        || routed_pass.is_some_and(|routed| routed >= due.pass)
                    {
                        return Ok(Audited::unchanged(Some(skipped)));
                    }
                    let stage = if routed_pass.is_none() {
                        Stage::Alerted
                    } else {
                        Stage::Analyzed
                    };
                    let decision = routers.decide(&alert, stage, tx).await?;
                    sqlx::query!(
                        "UPDATE analysis.roots SET routed_pass = $2 WHERE id = $1",
                        alert.root,
                        due.pass,
                    )
                    .execute(tx.conn())
                    .await?;
                    let mut outcome = RouteOutcome {
                        stage: Some(stage),
                        decision: decision.clone(),
                        ..skipped
                    };
                    let Some(routed) = decision.filter(|d| d.queue.as_str() != alert.queue) else {
                        return Ok(Audited::unchanged(Some(outcome)));
                    };
                    let Some(from) = move_alert(
                        tx,
                        alert.root,
                        &routed.queue,
                        &routed.reason,
                        Some(&routed.router),
                        actor,
                        None,
                    )
                    .await?
                    else {
                        tracing::info!(
                            alert_uuid = %alert.root,
                            queue = routed.queue.as_str(),
                            router = routed.router,
                            "not moving the alert to the queue its router decided: it's dispositioned or an analyst owns it"
                        );
                        return Ok(Audited::unchanged(Some(outcome)));
                    };
                    let change = Change::updated(
                        Target::root(alert.root),
                        &QueueRecord { queue: &from },
                        &QueueRecord {
                            queue: routed.queue.as_str(),
                        },
                    )?
                    .details(&MoveRecord {
                        router: Some(&routed.router),
                        reason: &routed.reason,
                        stage: Some(stage),
                        pass: Some(due.pass),
                    })?;
                    outcome.moved = Some((from, routed.queue.as_str().to_owned()));
                    Ok(Audited::changed(Some(outcome), change))
                })
            })
            .await
    }

    /// The alert's newest move between queues, ace3's `get_last_queue_change`, or None if it never moved. It
    /// needs `alert:read`.
    pub async fn last_queue_change(
        &self,
        actor: &Actor,
        root: Uuid,
    ) -> Result<Option<QueueChange>, ServiceError> {
        self.gate
            .read(
                actor,
                "last_queue_change",
                &crate::permission::ALERT_READ,
                &|tx| {
                    Box::pin(async move {
                        let alert = sqlx::query_scalar!(
                            r#"SELECT EXISTS (SELECT FROM analysis.roots
                                          WHERE id = $1 AND alerted_at IS NOT NULL) AS "alert!""#,
                            root,
                        )
                        .fetch_one(tx.conn())
                        .await?;
                        if !alert {
                            return Err(no_alert(root));
                        }
                        last_queue_change(tx, root).await
                    })
                },
            )
            .await
    }
}

/// The actor routing acts as: the component `alert_routing`.
pub fn routing_actor() -> Actor {
    Actor::Internal {
        id: Component::new(ROUTING_COMPONENT).expect("a valid component name"),
    }
}

/// `ace serve`'s routing worker: routes every due alert (`Service::route_due`), then waits for the next
/// completion (2.11's event, `ace_core::queue::Completions`), or `poll`, in case a notification was lost
/// or the listener can't connect, until `stop` fires. A routing that fails is logged and its row stays due.
pub async fn run_worker(service: Service, poll: Duration, stop: CancellationToken) {
    let actor = routing_actor();
    let mut completions = None;
    loop {
        loop {
            if stop.is_cancelled() {
                return;
            }
            match service.route_due(&actor).await {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(e) => {
                    tracing::error!("routing an alert failed: {e}");
                    break;
                }
            }
        }
        if completions.is_none() {
            match ace_core::queue::Completions::listen(service.gate.db()).await {
                Ok(listening) => completions = Some(listening),
                Err(e) => tracing::warn!("listening for completions failed; polling: {e}"),
            }
        }
        let wait = async {
            match completions.as_mut() {
                Some(listening) => listening.next(poll).await.map(|_| ()),
                None => {
                    tokio::time::sleep(poll).await;
                    Ok(())
                }
            }
        };
        tokio::select! {
            _ = stop.cancelled() => return,
            waited = wait => {
                if let Err(e) = waited {
                    tracing::warn!("the completions listener failed; listening again: {e}");
                    completions = None;
                }
            }
        }
    }
}
