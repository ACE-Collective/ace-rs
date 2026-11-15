//! Alert ownership (PLAN.md 7.17): ace3's `check_alert_ownership`, `change_alert_owner`, `describe_skipped`
//! and `describe_frozen` (`saq/database/util/alert.py`), and the ownership half of its `set_dispositions`.
//!
//! An alert's owner is the analyst who took it (`analysis.roots.owner_id`, migration 0056). As in ace3:
//!
//! - An alert nobody owns, or that the person already owns, is theirs to change.
//! - An alert another analyst owns is left alone, unless the person confirmed taking it from that analyst
//!   by naming them. The confirmation counts only while that analyst still owns the alert, so an alert
//!   someone else took in the meantime is left alone rather than taken from them unseen.
//! - An alert whose owner's account is disabled has nobody left to protect: it changes hands with no
//!   confirmation.
//! - Assigning alerts to someone needs no confirmation for the ones that person already owns.
//! - A disposition makes the analyst the owner of an alert nobody owned, and of one they took, so a later
//!   sweep by someone else can't silently overwrite it (`Service::disposition`). An alert whose
//!   disposition only ACE sets is left alone before its owner is looked at, so nothing is taken.
//!
//! `Service::change_alert_owner` is ace3's `PUT /alerts/owner`: the caller takes the alerts when the new
//! owner is themselves, assigns them otherwise, and unassigns them with None. Each alert is its own
//! transaction, with its row locked from the check to the write, and has its own audit row saying who
//! owned it before and whether it was taken from them.
//!
//! # What differs from ace3
//!
//! - ACE's components own nothing (0056), so ace3's automation user, which owns a SIMULATED alert there and
//!   counts as nobody, has nothing to stand for here. A component's disposition (SVS closing a run's
//!   alerts) neither checks nor takes ownership: its callers pick only alerts nobody owns.
//! - The person is the user, or the user an API key belongs to. A key with no user can't change owners
//!   (ace3's 400). Its disposition leaves an owned alert alone like anyone's, and a take it confirmed
//!   leaves the alert with nobody, since there is no user to give it to.
//! - A confirmation names the owner by id, as ace3's does. ace3's ids are integers and these are uuids.
//! - ace3 changes a request's alerts in one transaction; here each alert is its own, as a bulk
//!   disposition's are, so each has an audit row under its own id.
//! - `Service::set_alert_owner` (7.10 batch 7a) stays as the unchecked setter of one alert, with no route:
//!   SVS's tests stage owners with it.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;
use uuid::Uuid;

use crate::actor::{Actor, UserId};
use crate::gate::{Audited, Change, Recorded, Target};
use crate::permission::ALERT_WRITE;
use crate::routing::acting_user;
use crate::{Service, ServiceError};

/// The most alerts one change of owner takes, as a bulk disposition's.
pub const MAX_OWNER_ALERTS: usize = 500;
/// The most users `Service::alert_owner_choices` lists.
pub const MAX_OWNER_CHOICES: i64 = 1000;

/// Who owns an alert, as the ownership check needs to know it: ace3's `AlertOwner`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertOwner {
    pub id: UserId,
    /// What the GUI calls them: their display name, or their username when they have none.
    pub name: String,
    pub username: String,
    /// False for a disabled account, which protects nothing.
    pub enabled: bool,
}

/// An alert left alone because another analyst owns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedAlert {
    pub alert: Uuid,
    /// Who owned it when it was looked at: what a confirmation to take it names.
    pub owner: UserId,
    pub name: String,
}

/// Which of the alerts a person asked to change they may change: ace3's `OwnershipCheck`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OwnershipCheck {
    /// The alerts that may be changed, in the order they were asked for.
    pub permitted: Vec<Uuid>,
    /// The permitted alerts that change hands: taken from another analyst, or owned by a disabled
    /// account.
    pub reassigned: Vec<Uuid>,
    /// The alerts left alone, each with the analyst who owns it, in the order asked for.
    pub skipped: Vec<SkippedAlert>,
    /// The alerts left alone because only ACE sets their disposition, each with that disposition.
    pub frozen: Vec<(Uuid, String)>,
}

/// Decides which of `alerts` the person may change: ace3's `check_alert_ownership`.
///
/// `owners` has every alert that exists, with its owner or None; an alert missing from it is dropped, and
/// so is a repeat. `user` is the person, None for an API key that belongs to nobody. `confirmed` is, per
/// alert, the analyst the person agreed to take it from. `new_owner` is who the change gives the alerts
/// to, when that isn't the person: an alert they already own is theirs either way.
pub fn check_alert_ownership(
    alerts: &[Uuid],
    owners: &HashMap<Uuid, Option<AlertOwner>>,
    user: Option<UserId>,
    confirmed: &BTreeMap<Uuid, UserId>,
    new_owner: Option<UserId>,
) -> OwnershipCheck {
    let mut result = OwnershipCheck::default();
    let mut seen: Vec<Uuid> = Vec::with_capacity(alerts.len());
    for alert in alerts {
        if seen.contains(alert) {
            continue;
        }
        seen.push(*alert);
        let Some(owner) = owners.get(alert) else {
            continue;
        };
        match owner {
            None => result.permitted.push(*alert),
            Some(owner) if Some(owner.id) == user || Some(owner.id) == new_owner => {
                result.permitted.push(*alert);
            }
            Some(owner) if !owner.enabled || confirmed.get(alert) == Some(&owner.id) => {
                result.permitted.push(*alert);
                result.reassigned.push(*alert);
            }
            Some(owner) => result.skipped.push(SkippedAlert {
                alert: *alert,
                owner: owner.id,
                name: owner.name.clone(),
            }),
        }
    }
    result
}

/// Each value with how often it appears, most often first and otherwise in the order first seen: Python's
/// `Counter.most_common`.
fn most_common<'a>(values: impl Iterator<Item = &'a str>) -> Vec<(&'a str, usize)> {
    let mut counts: Vec<(&str, usize)> = Vec::new();
    for value in values {
        match counts.iter_mut().find(|(seen, _)| *seen == value) {
            Some((_, count)) => *count += 1,
            None => counts.push((value, 1)),
        }
    }
    counts.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
    counts
}

fn plural(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}

/// `left 2 SIMULATED alerts alone (only ACE sets that disposition)`, or None when no alert was left alone
/// for its disposition: ace3's `describe_frozen`.
pub fn describe_frozen(frozen: &[(Uuid, String)]) -> Option<String> {
    if frozen.is_empty() {
        return None;
    }
    let by = most_common(frozen.iter().map(|(_, disposition)| disposition.as_str()));
    let total = frozen.len();
    let s = plural(total);
    Some(match by.as_slice() {
        [(disposition, _)] => {
            format!("left {total} {disposition} alert{s} alone (only ACE sets that disposition)")
        }
        by => format!(
            "left {total} alert{s} alone whose disposition only ACE sets ({})",
            by.iter()
                .map(|(disposition, count)| format!("{disposition} {count}"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    })
}

/// `left 3 alerts owned by jsmith alone`, and the alerts left alone for their disposition
/// (`describe_frozen`), or None when nothing was skipped: ace3's `describe_skipped`.
pub fn describe_skipped(check: &OwnershipCheck) -> Option<String> {
    let mut parts = Vec::new();
    if !check.skipped.is_empty() {
        let by = most_common(check.skipped.iter().map(|skipped| skipped.name.as_str()));
        let total = check.skipped.len();
        let s = plural(total);
        parts.push(match by.as_slice() {
            [(owner, _)] => format!("left {total} alert{s} owned by {owner} alone"),
            by => format!(
                "left {total} alert{s} owned by other analysts alone ({})",
                by.iter()
                    .map(|(owner, count)| format!("{owner} {count}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        });
    }
    parts.extend(describe_frozen(&check.frozen));
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("; "))
    }
}

/// The form field's confirmations: ace3's `confirmed_takes_from_form` over its `take_owned` field,
/// comma-separated `alert:owner` pairs, the owner being who had the alert when the analyst looked. A
/// malformed pair is ignored: the alert it names is then unconfirmed, which leaves it alone.
pub fn confirmed_takes(field: &str) -> BTreeMap<Uuid, UserId> {
    let mut takes = BTreeMap::new();
    for pair in field.split(',') {
        let Some((alert, owner)) = pair.trim().split_once(':') else {
            continue;
        };
        if let (Ok(alert), Ok(owner)) = (alert.parse::<Uuid>(), owner.parse::<Uuid>()) {
            takes.insert(alert, UserId(owner));
        }
    }
    takes
}

/// What `Service::change_alert_owner` did: ace3's `SetOwnerResult`, with the check it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerChange {
    /// The alerts that now have the owner asked for, in the order asked for.
    pub applied: Vec<Uuid>,
    /// Those of them taken from another analyst, or from a disabled account.
    pub reassigned: Vec<Uuid>,
    /// The alerts left with the analyst who owns them.
    pub skipped: Vec<SkippedAlert>,
    /// What the GUI tells the analyst when alerts were skipped, in ace3's words; None otherwise.
    pub message: Option<String>,
}

/// A user an alert can be assigned to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerChoice {
    pub id: UserId,
    pub name: String,
    pub username: String,
}

/// What a user is called: their display name, or their username.
pub(crate) fn shown(display_name: Option<String>, username: &str) -> String {
    display_name.unwrap_or_else(|| username.to_owned())
}

/// An alert's owner, as a change of owner's audit row keeps its two sides.
#[derive(Serialize)]
struct OwnerRecord {
    owner: Option<Uuid>,
}

impl Recorded for OwnerRecord {}

/// What else the row says: whether the alert was taken from the analyst who owned it.
#[derive(Serialize)]
struct OwnerChangeRecord {
    taken: bool,
}

impl Recorded for OwnerChangeRecord {}

/// An alert's owner, with its row locked until the transaction ends, so ownership can't change between
/// the check and the write that relies on it: ace3's `_fetch_alert_owners`, for one alert. The outer None
/// is a root that isn't there; `alerts_only` leaves out one that isn't an alert.
pub(crate) async fn locked_owner(
    conn: &mut sqlx::PgConnection,
    root: Uuid,
    alerts_only: bool,
) -> Result<Option<Option<AlertOwner>>, ServiceError> {
    let row = sqlx::query!(
        r#"SELECT r.owner_id, u.username::text AS "username?", u.display_name AS "display_name?",
                  u.enabled AS "enabled?"
           FROM analysis.roots r LEFT JOIN service.users u ON u.id = r.owner_id
           WHERE r.id = $1 AND (NOT $2 OR r.alerted_at IS NOT NULL)
           FOR UPDATE OF r"#,
        root,
        alerts_only,
    )
    .fetch_optional(conn)
    .await?;
    Ok(row.map(|row| {
        row.owner_id.map(|id| {
            let username = row.username.unwrap_or_default();
            AlertOwner {
                id: UserId(id),
                name: shown(row.display_name, &username),
                username,
                enabled: row.enabled.unwrap_or(false),
            }
        })
    }))
}

/// What a change of owner did to one alert.
enum Changed {
    /// The id names no alert.
    Missing,
    /// It has the owner asked for; `taken` when it changed hands.
    Applied {
        taken: bool,
    },
    Skipped(SkippedAlert),
}

impl Service {
    /// Gives the alerts to `owner`, or unassigns them with None: ace3's `change_alert_owner` and its
    /// `PUT /alerts/owner`. The caller takes them when `owner` is themselves and assigns them otherwise.
    /// An alert another analyst owns is left alone unless `confirmed` names that analyst for it (the
    /// module's docs). It needs `alert:write`, and a caller that is a user or a key of one.
    ///
    /// Each alert is its own transaction, with its row locked from the check to the write, and its own
    /// audit row, as a bulk disposition's alerts are; ace3 changes them in one. An id that names no alert
    /// is dropped, as in ace3, and so is a repeat. No alerts, more than `MAX_OWNER_ALERTS`, a caller that
    /// isn't a user, or a new owner who doesn't exist or is disabled is `InvalidRequest`.
    pub async fn change_alert_owner(
        &self,
        actor: &Actor,
        alerts: &[Uuid],
        owner: Option<UserId>,
        confirmed: &BTreeMap<Uuid, UserId>,
    ) -> Result<OwnerChange, ServiceError> {
        if alerts.is_empty() || alerts.len() > MAX_OWNER_ALERTS {
            return Err(ServiceError::InvalidRequest(format!(
                "a change of owner takes 1 to {MAX_OWNER_ALERTS} alerts"
            )));
        }
        let mut check = OwnershipCheck::default();
        let mut new_owner_name = None;
        let mut seen: Vec<Uuid> = Vec::with_capacity(alerts.len());
        for alert in alerts.iter().copied() {
            if seen.contains(&alert) {
                continue;
            }
            seen.push(alert);
            let (changed, name) = self
                .gate
                .write(actor, "change_alert_owner", &ALERT_WRITE, &|tx| {
                    Box::pin(async move {
                        let Some(user) = acting_user(actor) else {
                            return Err(ServiceError::InvalidRequest(
                                "changing an alert's owner needs a caller that is a user"
                                    .to_owned(),
                            ));
                        };
                        let new_owner = match owner {
                            None => None,
                            Some(owner) => {
                                let found = sqlx::query!(
                                    r#"SELECT username::text AS "username!", display_name, enabled
                                       FROM service.users WHERE id = $1 FOR SHARE"#,
                                    owner.0,
                                )
                                .fetch_optional(tx.conn())
                                .await?
                                .filter(|found| found.enabled);
                                let Some(found) = found else {
                                    return Err(ServiceError::InvalidRequest(format!(
                                        "user {} does not exist or is disabled",
                                        owner.0
                                    )));
                                };
                                Some(shown(found.display_name, &found.username))
                            }
                        };
                        let Some(before) = locked_owner(tx.conn(), alert, true).await? else {
                            return Ok(Audited::unchanged((Changed::Missing, new_owner)));
                        };
                        let owners = HashMap::from([(alert, before.clone())]);
                        let one =
                            check_alert_ownership(&[alert], &owners, Some(user), confirmed, owner);
                        if let Some(skipped) = one.skipped.into_iter().next() {
                            return Ok(Audited::unchanged((Changed::Skipped(skipped), new_owner)));
                        }
                        let taken = !one.reassigned.is_empty();
                        // ace3 writes the owner and its time again for an alert that is already theirs
                        sqlx::query!(
                            "UPDATE analysis.roots
                             SET owner_id = $2,
                                 owned_at = CASE WHEN $2::uuid IS NULL THEN NULL ELSE now() END
                             WHERE id = $1",
                            alert,
                            owner.map(|owner| owner.0),
                        )
                        .execute(tx.conn())
                        .await?;
                        let applied = (Changed::Applied { taken }, new_owner);
                        let before_id = before.as_ref().map(|owner| owner.id);
                        if before_id == owner {
                            return Ok(Audited::unchanged(applied));
                        }
                        if taken {
                            tracing::info!(
                                alert_uuid = %alert,
                                alert_owner = before.as_ref().map(|owner| owner.username.as_str()),
                                new_owner = owner.map(|owner| owner.0.to_string()),
                                changed_by = %actor,
                                "alert ownership taken"
                            );
                        }
                        let change = Change::updated(
                            Target::root(alert),
                            &OwnerRecord {
                                owner: before_id.map(|owner| owner.0),
                            },
                            &OwnerRecord {
                                owner: owner.map(|owner| owner.0),
                            },
                        )?
                        .details(&OwnerChangeRecord { taken })?;
                        Ok(Audited::changed(applied, change))
                    })
                })
                .await?;
            new_owner_name = name;
            match changed {
                Changed::Missing => {}
                Changed::Applied { taken } => {
                    check.permitted.push(alert);
                    if taken {
                        check.reassigned.push(alert);
                    }
                }
                Changed::Skipped(skipped) => check.skipped.push(skipped),
            }
        }
        let user = acting_user(actor);
        let message = describe_skipped(&check).map(|skipped| {
            let count = check.permitted.len();
            let action = match owner {
                Some(owner) if Some(owner) == user => format!("took ownership of {count} alerts"),
                None => format!("unassigned {count} alerts"),
                Some(owner) => format!(
                    "assigned {count} alerts to {}",
                    new_owner_name
                        .clone()
                        .unwrap_or_else(|| owner.0.to_string())
                ),
            };
            format!("{action}; {skipped}")
        });
        Ok(OwnerChange {
            applied: check.permitted,
            reassigned: check.reassigned,
            skipped: check.skipped,
            message,
        })
    }

    /// The enabled users, by what each is called: who the GUI's Assign Ownership offers, as ace3's dialog
    /// lists its users. It needs `alert:write`, as assigning does, and lists at most
    /// `MAX_OWNER_CHOICES`.
    pub async fn alert_owner_choices(
        &self,
        actor: &Actor,
    ) -> Result<Vec<OwnerChoice>, ServiceError> {
        self.gate
            .read(actor, "alert_owner_choices", &ALERT_WRITE, &|tx| {
                Box::pin(async move {
                    let rows = sqlx::query!(
                        r#"SELECT id, username::text AS "username!", display_name
                           FROM service.users WHERE enabled
                           ORDER BY lower(COALESCE(display_name, username::text)), id
                           LIMIT $1"#,
                        MAX_OWNER_CHOICES,
                    )
                    .fetch_all(tx.conn())
                    .await?;
                    Ok(rows
                        .into_iter()
                        .map(|row| OwnerChoice {
                            id: UserId(row.id),
                            name: shown(row.display_name, &row.username),
                            username: row.username,
                        })
                        .collect())
                })
            })
            .await
    }
}

/// What a disposition does to the alert's owner, decided under the alert's lock: ace3's ownership half
/// of `set_dispositions`, for one alert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Claim {
    /// The owner stays as it is: the person's own alert, or a key with no user's change to an alert
    /// nobody owns.
    Keep,
    /// The person becomes the owner of an alert nobody owned.
    Take,
    /// The alert changes hands: confirmed, or its owner's account is disabled. The person becomes its
    /// owner, or nobody does when the person is a key with no user.
    TakeFrom(AlertOwner),
    /// Another analyst owns it and the person didn't confirm taking it from them.
    Refused(AlertOwner),
}

/// What a person's disposition does to the owner of one alert. `take_from` is the analyst they agreed to
/// take it from.
pub(crate) fn claim(
    owner: Option<AlertOwner>,
    user: Option<UserId>,
    take_from: Option<UserId>,
) -> Claim {
    match owner {
        None if user.is_some() => Claim::Take,
        None => Claim::Keep,
        Some(owner) if Some(owner.id) == user => Claim::Keep,
        Some(owner) if !owner.enabled || take_from == Some(owner.id) => Claim::TakeFrom(owner),
        Some(owner) => Claim::Refused(owner),
    }
}
