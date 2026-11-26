//! What the alert view (PLAN.md 5.8) reads: an alert's whole tree in one snapshot, and a watch that says
//! when a result lands on it, so an open page can draw it again.
//!
//! The tree is ace3's `TreeNode` walk (`app/analysis/views/index.py`) in rows: the observables the
//! submission added, each with its modules' results, each result with the observables it added
//! (`analysis.result_additions`), and so on down. The submission's observables are those added in the
//! transaction that made the root (`submit::create`), whose `created_at` is the root's, since both are
//! that transaction's `now()`; a result lands in a later one. An adapter draws it; this gives it every observable
//! with what's recorded about it, and which result added which. It's one read under `alert:read`, in one
//! repeatable-read transaction, so a page never shows half a landing. ace3 draws an alert of any size;
//! here a tree holds at most `MAX_TREE_OBSERVABLES`, and says when it was cut short.
//!
//! The watch is `LISTEN ace_rs_results`, which migration 0029's trigger notifies with a result's root and
//! id when it lands, and migration 0063's with the root when the alert's owner changes, so an open page
//! can say so. A notification is a wakeup and carries nothing to show: the watcher reads the tree
//! again through `alert_tree`, which checks its permission again. One listener serves every watch in the
//! process, on a connection of its own, and only while something watches: it starts with the first
//! watch and stops within a second of the last one going. Each watch holds one `watch` channel's
//! receiver, whose value is a count, so a burst of landings while the watcher is busy is one wakeup and
//! nothing queues up behind a slow one. Notifications go out at commit and aren't ordered by result id,
//! so a watcher reads the whole tree on every wakeup rather than results after an id.
//!
//! A notification sent while the listener reconnects is lost, so on reconnecting it wakes every watch.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sqlx::postgres::PgListener;
use tokio::sync::watch;
use uuid::Uuid;

use crate::alerts::{Alert, AlertObservable, alert_in, observables_in};
use crate::permission::ALERT_READ;
use crate::{Service, ServiceError};

/// The most observables a tree holds. ace3 has no limit; this keeps one page's read and its HTML
/// bounded, and a tree past it says it was cut short.
pub const MAX_TREE_OBSERVABLES: i64 = 5000;

/// The channel migration 0029's trigger notifies, with `<root>/<result id>`, and migration 0063's, with
/// `<root>/owner`.
pub const RESULTS_CHANNEL: &str = "ace_rs_results";

/// How often the listener, with nothing to hear, checks whether anything still watches.
const IDLE_CHECK: Duration = Duration::from_secs(1);

/// That a result added an observable to the tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Addition {
    pub result: i64,
    pub observable: i64,
}

/// An alert's tree, as one snapshot.
#[derive(Debug, Clone, PartialEq)]
pub struct AlertTree {
    pub alert: Alert,
    /// Its observables in the order they were added, each with its results, files and detections.
    pub observables: Vec<AlertObservable>,
    /// The observables the submission added, at the top of the tree, in the order it added them.
    pub top: Vec<i64>,
    /// Which result added which observable, in the order each result listed them, without those an
    /// observable modifier rule's `ignore` took out.
    pub additions: Vec<Addition>,
    /// The detections on the alert itself rather than on one of its observables, such as
    /// `configuration_defined_tagging`'s (PLAN.md 7.6), in the order they were made.
    pub root_detections: Vec<crate::alerts::AlertDetection>,
    /// Whether the alert has more observables than `MAX_TREE_OBSERVABLES`, which this leaves out.
    pub truncated: bool,
    /// What the root's submitter said about it, as `analysis.roots.origin` keeps it: its alert type,
    /// tool and details, such as a hunt's query and matched events. Null when it said nothing. The
    /// alert page chooses its summary by the alert type and draws it from the details.
    pub origin: serde_json::Value,
}

impl AlertTree {
    /// The root's alert type, ace3's `alert_type`, such as `mailbox` or `hunter - splunk - v2`: its
    /// origin's `alert_type`, which is also what a module reads on the lease's tree. None when the
    /// submitter named none.
    pub fn alert_type(&self) -> Option<&str> {
        self.origin
            .get("alert_type")
            .and_then(|kind| kind.as_str())
            .filter(|kind| !kind.is_empty())
    }
}

/// One open watch on an alert. Dropping it stops it, and the last one to go stops the listener.
pub struct AlertWatch {
    root: Uuid,
    receiver: Option<watch::Receiver<u64>>,
    feed: Arc<FeedState>,
}

impl AlertWatch {
    /// Waits until a result lands on the alert, or the listener reconnected and may have missed one.
    /// Every landing since the last call is one wakeup.
    pub async fn changed(&mut self) {
        let Some(receiver) = self.receiver.as_mut() else {
            return std::future::pending().await;
        };
        if receiver.changed().await.is_err() {
            // the sender only goes when the last receiver does, which this is one of
            std::future::pending::<()>().await;
        }
    }

    pub fn root(&self) -> Uuid {
        self.root
    }
}

impl Drop for AlertWatch {
    fn drop(&mut self) {
        drop(self.receiver.take());
        let mut state = self.feed.lock();
        if state
            .roots
            .get(&self.root)
            .is_some_and(|sender| sender.receiver_count() == 0)
        {
            state.roots.remove(&self.root);
        }
    }
}

impl std::fmt::Debug for AlertWatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlertWatch")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

/// The process's listener and who it wakes. `Service` holds one, shared by its clones.
#[derive(Debug, Default)]
pub(crate) struct Feed {
    state: Arc<FeedState>,
    /// Held while a listener starts, so two first watches don't start two.
    starting: tokio::sync::Mutex<()>,
}

#[derive(Debug, Default)]
struct FeedState {
    inner: Mutex<FeedInner>,
}

#[derive(Debug, Default)]
struct FeedInner {
    roots: HashMap<Uuid, watch::Sender<u64>>,
    listening: bool,
}

impl FeedState {
    fn lock(&self) -> std::sync::MutexGuard<'_, FeedInner> {
        // nothing panics while holding it, and the map is still whole if something did
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn wake(&self, root: Option<Uuid>) {
        let state = self.lock();
        match root {
            Some(root) => {
                if let Some(sender) = state.roots.get(&root) {
                    sender.send_modify(|count| *count = count.wrapping_add(1));
                }
            }
            None => {
                for sender in state.roots.values() {
                    sender.send_modify(|count| *count = count.wrapping_add(1));
                }
            }
        }
    }
}

/// The listener's loop: wakes the watches of each notified root, every watch after a reconnect, and
/// ends when nothing watches.
async fn listen(mut listener: PgListener, state: Arc<FeedState>) {
    loop {
        match tokio::time::timeout(IDLE_CHECK, listener.try_recv()).await {
            Err(_) => {}
            Ok(Ok(Some(notification))) => {
                let root = notification
                    .payload()
                    .split_once('/')
                    .and_then(|(root, _)| root.parse::<Uuid>().ok());
                match root {
                    Some(root) => state.wake(Some(root)),
                    None => tracing::warn!(
                        payload = notification.payload(),
                        "an unreadable result notification"
                    ),
                }
            }
            // the connection dropped and sqlx reconnects; what was sent meanwhile is lost
            Ok(Ok(None)) => state.wake(None),
            Ok(Err(error)) => {
                tracing::warn!("the result listener failed, so it starts again: {error}");
                state.wake(None);
                tokio::time::sleep(IDLE_CHECK).await;
            }
        }
        let mut inner = state.lock();
        if inner.roots.is_empty() {
            inner.listening = false;
            return;
        }
    }
}

impl Service {
    /// An alert's whole tree, as one snapshot, for the alert view. It needs `alert:read`.
    pub async fn alert_tree(
        &self,
        actor: &crate::Actor,
        id: Uuid,
    ) -> Result<AlertTree, ServiceError> {
        let comments = self.reads_comments();
        self.gate
            .read(actor, "alert_tree", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    let alert = alert_in(tx, id, comments).await?;
                    let (observables, truncated) =
                        observables_in(tx, id, None, MAX_TREE_OBSERVABLES, true).await?;
                    let additions = sqlx::query_as!(
                        Addition,
                        "SELECT result_id AS result, observable_id AS observable
                         FROM analysis.result_additions WHERE root_id = $1 AND NOT ignored
                         ORDER BY id",
                        id,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let root_detections = sqlx::query!(
                        "SELECT description, details FROM analysis.detections
                         WHERE root_id = $1 AND observable_id IS NULL ORDER BY id",
                        id,
                    )
                    .fetch_all(tx.conn())
                    .await?
                    .into_iter()
                    .map(|row| crate::alerts::AlertDetection {
                        description: row.description,
                        details: row.details,
                        module: None,
                    })
                    .collect();
                    let top = sqlx::query_scalar!(
                        "SELECT o.id FROM analysis.observables o
                         JOIN analysis.roots r ON r.id = o.root_id
                         WHERE o.root_id = $1 AND o.created_at = r.created_at
                         ORDER BY o.id",
                        id,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    let origin =
                        sqlx::query_scalar!("SELECT origin FROM analysis.roots WHERE id = $1", id,)
                            .fetch_optional(tx.conn())
                            .await?
                            .flatten()
                            .unwrap_or(serde_json::Value::Null);
                    Ok(AlertTree {
                        alert,
                        observables,
                        top,
                        additions,
                        root_detections,
                        truncated,
                        origin,
                    })
                })
            })
            .await
    }

    /// Watches an alert for results landing. It needs `alert:read`, and the alert has to exist. When this
    /// returns, the listener is listening, so a result that lands after it wakes the watch: a caller reads
    /// the tree after this, not before, to miss nothing.
    pub async fn watch_alert(
        &self,
        actor: &crate::Actor,
        id: Uuid,
    ) -> Result<AlertWatch, ServiceError> {
        self.gate
            .read(actor, "watch_alert", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    let alert = sqlx::query_scalar!(
                        "SELECT alerted_at IS NOT NULL FROM analysis.roots WHERE id = $1",
                        id,
                    )
                    .fetch_optional(tx.conn())
                    .await?
                    .flatten();
                    if alert == Some(true) {
                        Ok(())
                    } else {
                        Err(crate::alerts::no_alert(id))
                    }
                })
            })
            .await?;
        let feed = &self.feed;
        let _starting = feed.starting.lock().await;
        let receiver = {
            let mut inner = feed.state.lock();
            let receiver = inner
                .roots
                .entry(id)
                .or_insert_with(|| watch::channel(0).0)
                .subscribe();
            if inner.listening {
                return Ok(AlertWatch {
                    root: id,
                    receiver: Some(receiver),
                    feed: feed.state.clone(),
                });
            }
            receiver
        };
        let watch = AlertWatch {
            root: id,
            receiver: Some(receiver),
            feed: feed.state.clone(),
        };
        let mut listener = self.gate.listener().await?;
        listener.listen(RESULTS_CHANNEL).await?;
        feed.state.lock().listening = true;
        tokio::spawn(listen(listener, feed.state.clone()));
        Ok(watch)
    }

    /// How many alerts have an open watch, and whether the listener runs, for a test to see that a
    /// closed page leaves nothing behind.
    pub fn watching(&self) -> (usize, bool) {
        let inner = self.feed.state.lock();
        (inner.roots.len(), inner.listening)
    }
}
