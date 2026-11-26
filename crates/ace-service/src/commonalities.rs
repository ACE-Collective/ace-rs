//! The alert list's Commonalities panel (PLAN.md 7.23), ace3's `POST /api/v2/alerts/commonalities`
//! (`9260f7cd`): which of a page's alerts share observable values, so two analysts don't each take one
//! of several alerts about the same activity. It needs `alert:read`, as ace3's route does, and changes
//! nothing.
//!
//! A value is one value whatever its type: an address that is the sender of one alert and the return
//! path of another links them, and is one column. It is matched by `analysis.value_hash`, the sha256 of
//! the value itself, as ace3 matches `sha2(value)`; a file's value is its sha256 in hex, so a file and
//! the sha256 observable of the same hash are one value. Two queries, whatever the number of alerts:
//! the page's observables whose value two or more of its alerts have, and how many values each alert
//! has. Both run under the list's `LIST_TIMEOUT`. A requested id that isn't an alert, or doesn't exist,
//! is left out. Observables named in `ignore` (`type:value`) are not grouped by.
//!
//! The rules are ace3's (`group`): pairs of alerts sharing two or more values form the groups, then
//! pairs sharing one group alerts no such pair took, and an alert still alone joins the partner it
//! shares the most with. A group whose pairs each share 90% of the values of the one with more is
//! near-identical. Grouping and measuring are linear in the number of pairs of alerts that share a
//! value, which a page bounds: `MAX_ALERTS` alerts make at most 124,750 pairs.
//!
//! The values come ordered by group and, within one, most useful first: values that link groups, then
//! by type (`Ranking`, the overlay's `gui.commonalities_priority_types`), then by how many of the
//! group's alerts have it. What differs from ace3: ace3 keeps the first holder of a tie in the order its
//! database returned the rows, and an alert left alone joins its partner in that order too; here both
//! follow the order the request lists the alerts in, so the same page groups the same way every time.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use ace_results::ObservableKind;
use uuid::Uuid;

use crate::alerts::{LIST_TIMEOUT, SET_LIST_TIMEOUT, cancelled};
use crate::permission::ALERT_READ;
use crate::{Service, ServiceError};

/// The most alerts one request compares, ace3's `COMMONALITIES_MAX_ALERTS`.
pub const MAX_ALERTS: usize = 500;
/// The most observables one request ignores, ace3's `CommonalitiesRequest.ignore` `max_length`.
pub const MAX_IGNORED: usize = 100;
/// A group is near-identical when every pair of its alerts shares at least this share of the values of
/// the one with more, ace3's `NEAR_IDENTICAL_SHARE`.
pub const NEAR_IDENTICAL_SHARE: f64 = 0.9;
/// ace3's default `gui.commonalities_priority_types`.
pub const DEFAULT_PRIORITY_TYPES: &[&str] = &[
    "user",
    "hostname",
    "email_address",
    "ipv4",
    "fqdn",
    "url",
    "email_subject",
    "file_name",
    "file_path",
];

/// The observable types the panel lists first, most useful first: ace3's
/// `gui.commonalities_priority_types`. A type ranks as itself or its nearest listed ancestor, and an
/// unlisted one after every listed one. A name that isn't a type ranks nothing, so a site may list a
/// type its types file adds later (PLAN.md decision 66).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ranking(Vec<String>);

impl Default for Ranking {
    fn default() -> Self {
        Ranking(
            DEFAULT_PRIORITY_TYPES
                .iter()
                .map(|t| (*t).to_owned())
                .collect(),
        )
    }
}

impl Ranking {
    /// The overlay's list, or ace3's when it gives none.
    pub fn new(types: Option<Vec<String>>) -> Self {
        types.map_or_else(Ranking::default, Ranking)
    }

    pub fn types(&self) -> &[String] {
        &self.0
    }

    /// Where a type ranks: the place of it or its nearest listed ancestor, or the list's length.
    pub fn rank(&self, kind: &str) -> usize {
        let place = |name: &str| self.0.iter().position(|listed| listed == name);
        std::iter::once(kind.to_owned())
            .chain(ancestors(kind))
            .filter_map(|name| place(&name))
            .min()
            .unwrap_or(self.0.len())
    }
}

/// The types `kind` extends, nearest first; none for a name that isn't a type.
fn ancestors(kind: &str) -> Vec<String> {
    kind.parse::<ObservableKind>()
        .map(|kind| kind.ancestors().map(|k| k.as_str().to_owned()).collect())
        .unwrap_or_default()
}

/// One group of alerts that potentially relate.
#[derive(Debug, Clone, PartialEq)]
pub struct CommonalityGroup {
    /// Its alerts, the most strongly linked first.
    pub alerts: Vec<Uuid>,
    /// 0 to 1: how much its alerts have in common, from its size and how many values its pairs share.
    pub intensity: f64,
    /// How many values every alert of the group has.
    pub shared: usize,
    /// The most values any alert of the group has.
    pub total: usize,
    /// Every pair of its alerts shares at least `NEAR_IDENTICAL_SHARE` of the values of the one with more.
    pub near_identical: bool,
}

/// One value two or more of the alerts have. The alerts may have it under more than one type (an
/// address as both the sender and the return path): `kinds` lists them, most useful first, and `kind` is
/// the first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommonalityObservable {
    pub kind: String,
    pub kinds: Vec<String>,
    pub value: String,
    /// The requested alerts that have it, in the request's order.
    pub alerts: Vec<Uuid>,
    /// The index in `groups` of the first group with an alert that has it.
    pub group: usize,
    /// The indexes of every group with an alert that has it; more than one means it links groups.
    pub groups: Vec<usize>,
}

impl CommonalityObservable {
    /// Every `type:value` the alerts have it as, the form `ignore` takes.
    pub fn specs(&self) -> Vec<String> {
        self.kinds
            .iter()
            .map(|kind| format!("{kind}:{}", self.value))
            .collect()
    }
}

/// The requested alerts grouped by the values they share.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Commonalities {
    /// The most in common first.
    pub groups: Vec<CommonalityGroup>,
    /// Ordered by group and, within one, most useful first.
    pub observables: Vec<CommonalityObservable>,
    /// Each related alert -> how many other requested alerts share at least one value with it.
    pub related: BTreeMap<Uuid, usize>,
    /// How many of the requested alerts share nothing with any other.
    pub unrelated: usize,
    /// Each type in `observables` -> the types it extends, nearest first (`email_from` ->
    /// `[email_address]`), so a type without a color of its own can take its parent's.
    pub type_ancestors: BTreeMap<String, Vec<String>>,
}

impl Commonalities {
    /// The index of the group `alert` is in.
    pub fn group_of(&self, alert: Uuid) -> Option<usize> {
        self.groups
            .iter()
            .position(|group| group.alerts.contains(&alert))
    }
}

/// What the two queries read: each (alert, type, value) whose value two or more of the alerts have,
/// and how many distinct values each alert has. An alert missing from `totals` isn't one.
#[derive(Debug, Clone, Default)]
pub struct Observed {
    pub rows: Vec<(Uuid, String, String)>,
    pub totals: HashMap<Uuid, usize>,
}

/// The grouping of `observed` for alerts in `order` (the request's, duplicates dropped), with the
/// observables `ignore` names left out, ranked by `ranking`. What `Service::alert_commonalities`
/// returns, without the database.
pub fn commonalities_of(
    order: &[Uuid],
    observed: Observed,
    ignore: &[String],
    ranking: &Ranking,
) -> Commonalities {
    let position: HashMap<Uuid, usize> =
        order.iter().enumerate().map(|(at, id)| (*id, at)).collect();
    let at = |id: &Uuid| position.get(id).copied().unwrap_or(usize::MAX);
    let ignored: HashSet<&str> = ignore.iter().map(String::as_str).collect();
    let mut totals = observed.totals;
    let mut types_of: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut holders: HashMap<String, HashSet<Uuid>> = HashMap::new();
    let mut kept: HashMap<Uuid, HashSet<String>> = HashMap::new();
    let mut dropped: HashMap<Uuid, HashSet<String>> = HashMap::new();
    for (alert, kind, value) in observed.rows {
        if !totals.contains_key(&alert) {
            continue;
        }
        if ignored.contains(format!("{kind}:{value}").as_str()) {
            dropped.entry(alert).or_default().insert(value);
            continue;
        }
        kept.entry(alert).or_default().insert(value.clone());
        types_of.entry(value.clone()).or_default().insert(kind);
        holders.entry(value).or_default().insert(alert);
    }
    // an ignored value no longer counts toward its alert's size either
    for (alert, values) in &dropped {
        let still = kept.get(alert);
        let gone = values
            .iter()
            .filter(|value| still.is_none_or(|kept| !kept.contains(*value)))
            .count();
        if let Some(total) = totals.get_mut(alert) {
            *total = total.saturating_sub(gone);
        }
    }
    // values in a fixed order, so every pass over them is the same
    let mut alerts_of: Vec<(String, Vec<Uuid>)> = holders
        .into_iter()
        .filter(|(_, alerts)| alerts.len() >= 2)
        .map(|(value, alerts)| {
            let mut alerts: Vec<Uuid> = alerts.into_iter().collect();
            alerts.sort_by_key(|id| at(id));
            (value, alerts)
        })
        .collect();
    alerts_of.sort_by(|a, b| a.0.cmp(&b.0));

    let grouping = group(&alerts_of, &position);
    let mut groups = grouping.groups;
    measure(
        &mut groups,
        &grouping.group_of,
        &alerts_of,
        &grouping.weight,
        &totals,
    );

    let mut observables = Vec::new();
    let mut placed: HashSet<String> = HashSet::new();
    for index in 0..groups.len() {
        let mut mine = Vec::new();
        for (value, alerts) in &alerts_of {
            if placed.contains(value)
                || !alerts
                    .iter()
                    .any(|id| grouping.group_of.get(id) == Some(&index))
            {
                continue;
            }
            let mut kinds: Vec<String> = types_of[value].iter().cloned().collect();
            kinds.sort_by_key(|kind| (ranking.rank(kind), kind.clone()));
            let linked: Vec<usize> = alerts
                .iter()
                .filter_map(|id| grouping.group_of.get(id).copied())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let in_group = alerts
                .iter()
                .filter(|id| grouping.group_of.get(id) == Some(&index))
                .count();
            let key = (
                linked.len() == 1,
                ranking.rank(&kinds[0]),
                std::cmp::Reverse(in_group),
                std::cmp::Reverse(alerts.len()),
                value.clone(),
            );
            mine.push((
                key,
                CommonalityObservable {
                    kind: kinds[0].clone(),
                    kinds,
                    value: value.clone(),
                    alerts: alerts.clone(),
                    group: index,
                    groups: linked,
                },
            ));
        }
        mine.sort_by(|a, b| a.0.cmp(&b.0));
        for (_, observable) in mine {
            placed.insert(observable.value.clone());
            observables.push(observable);
        }
    }

    let type_ancestors = observables
        .iter()
        .flat_map(|o| o.kinds.iter())
        .map(|kind| (kind.clone(), ancestors(kind)))
        .collect();
    let related = grouping
        .partners
        .iter()
        .map(|(id, others)| (*id, others.len()))
        .collect();
    Commonalities {
        unrelated: totals.len().saturating_sub(grouping.group_of.len()),
        groups,
        observables,
        related,
        type_ancestors,
    }
}

/// What `group` makes: the groups (most in common first, not yet measured), alert -> its group's
/// index, alert -> the alerts it shares anything with, and (alert, alert) -> how many values the pair
/// shares, the first of each pair earlier in the request.
#[derive(Debug, Default)]
pub struct Grouping {
    pub groups: Vec<CommonalityGroup>,
    pub group_of: HashMap<Uuid, usize>,
    pub partners: HashMap<Uuid, HashSet<Uuid>>,
    pub weight: HashMap<(Uuid, Uuid), usize>,
}

/// ace3's `_group_alerts`: pairs sharing two or more values form the groups, then pairs sharing one
/// group alerts no such pair took, and an alert still alone joins the partner it shares the most with
/// (the earliest in the request of those sharing as much). `alerts_of` is each value's alerts, two or
/// more, in the request's order (`position`).
pub fn group(alerts_of: &[(String, Vec<Uuid>)], position: &HashMap<Uuid, usize>) -> Grouping {
    let at = |id: &Uuid| position.get(id).copied().unwrap_or(usize::MAX);
    let mut weight: HashMap<(Uuid, Uuid), usize> = HashMap::new();
    for (_, alerts) in alerts_of {
        for (i, first) in alerts.iter().enumerate() {
            for second in &alerts[i + 1..] {
                *weight.entry((*first, *second)).or_default() += 1;
            }
        }
    }
    let mut partners: HashMap<Uuid, HashSet<Uuid>> = HashMap::new();
    for (first, second) in weight.keys() {
        partners.entry(*first).or_default().insert(*second);
        partners.entry(*second).or_default().insert(*first);
    }
    // the alerts in the request's order, which every pass below follows
    let mut members: Vec<Uuid> = partners.keys().copied().collect();
    members.sort_by_key(|id| at(id));
    let index: HashMap<Uuid, usize> = members.iter().enumerate().map(|(n, id)| (*id, n)).collect();
    let mut sets = UnionFind::new(members.len());
    let mut taken = vec![false; members.len()];
    for ((first, second), shared) in &weight {
        if *shared >= 2 {
            sets.union(index[first], index[second]);
            taken[index[first]] = true;
            taken[index[second]] = true;
        }
    }
    for ((first, second), shared) in &weight {
        let (a, b) = (index[first], index[second]);
        if *shared == 1 && !taken[a] && !taken[b] {
            sets.union(a, b);
        }
    }
    let shared_with = |a: &Uuid, b: &Uuid| {
        weight
            .get(&(*a, *b))
            .or_else(|| weight.get(&(*b, *a)))
            .copied()
            .unwrap_or(0)
    };
    let mut sizes = vec![0usize; members.len()];
    for n in 0..members.len() {
        sizes[sets.find(n)] += 1;
    }
    let alone: Vec<usize> = (0..members.len())
        .filter(|n| sizes[sets.find(*n)] == 1)
        .collect();
    for n in alone {
        let id = members[n];
        let partner = partners[&id]
            .iter()
            .max_by_key(|other| (shared_with(&id, other), std::cmp::Reverse(at(other))))
            .copied();
        if let Some(partner) = partner {
            sets.union(n, index[&partner]);
        }
    }

    // one pass over the pairs: each group's pair count and values shared, and each alert's strength
    // (the values it shares with the rest of its group)
    let mut pair_count: HashMap<usize, usize> = HashMap::new();
    let mut shared_total: HashMap<usize, usize> = HashMap::new();
    let mut strength: HashMap<Uuid, usize> = HashMap::new();
    for ((first, second), shared) in &weight {
        let root = sets.find(index[first]);
        if root != sets.find(index[second]) {
            continue;
        }
        *pair_count.entry(root).or_default() += 1;
        *shared_total.entry(root).or_default() += shared;
        *strength.entry(*first).or_default() += shared;
        *strength.entry(*second).or_default() += shared;
    }
    let mut by_root: BTreeMap<usize, Vec<Uuid>> = BTreeMap::new();
    for (n, id) in members.iter().enumerate() {
        by_root.entry(sets.find(n)).or_default().push(*id);
    }
    let mut groups: Vec<CommonalityGroup> = by_root
        .into_iter()
        .map(|(root, mut alerts)| {
            let pairs = pair_count.get(&root).copied().unwrap_or(1).max(1);
            let average = shared_total.get(&root).copied().unwrap_or(0) as f64 / pairs as f64;
            let size = alerts.len() as f64;
            let intensity = (0.45 * ((size - 2.0) / 4.0).clamp(0.0, 1.0)
                + 0.55 * ((average - 1.0) / 2.5).clamp(0.0, 1.0))
            .min(1.0);
            alerts.sort_by_key(|id| {
                (
                    std::cmp::Reverse(strength.get(id).copied().unwrap_or(0)),
                    at(id),
                )
            });
            CommonalityGroup {
                alerts,
                intensity: (intensity * 1000.0).round() / 1000.0,
                shared: 0,
                total: 0,
                near_identical: false,
            }
        })
        .collect();
    groups.sort_by(|a, b| {
        b.intensity
            .total_cmp(&a.intensity)
            .then(b.alerts.len().cmp(&a.alerts.len()))
            .then(at(&a.alerts[0]).cmp(&at(&b.alerts[0])))
    });
    let group_of = groups
        .iter()
        .enumerate()
        .flat_map(|(n, group)| group.alerts.iter().map(move |id| (*id, n)))
        .collect();
    Grouping {
        groups,
        group_of,
        partners,
        weight,
    }
}

/// ace3's `_measure_groups`: each group's `shared`, `total` and `near_identical`, in one pass over the
/// values and one over the pairs.
pub fn measure(
    groups: &mut [CommonalityGroup],
    group_of: &HashMap<Uuid, usize>,
    alerts_of: &[(String, Vec<Uuid>)],
    weight: &HashMap<(Uuid, Uuid), usize>,
    totals: &HashMap<Uuid, usize>,
) {
    let total = |id: &Uuid| totals.get(id).copied().unwrap_or(0);
    // a value every alert of a group has counts toward its `shared`
    let mut shared_by_all = vec![0usize; groups.len()];
    for (_, alerts) in alerts_of {
        let mut holders_in: HashMap<usize, usize> = HashMap::new();
        for id in alerts {
            if let Some(index) = group_of.get(id) {
                *holders_in.entry(*index).or_default() += 1;
            }
        }
        for (index, count) in holders_in {
            if count == groups[index].alerts.len() {
                shared_by_all[index] += 1;
            }
        }
    }
    // a group is near-identical when every pair of its alerts shares values, and each such pair shares
    // NEAR_IDENTICAL_SHARE of the values of the one with more
    let mut close_pairs = vec![0usize; groups.len()];
    for ((first, second), shared) in weight {
        let Some(index) = group_of.get(first) else {
            continue;
        };
        if group_of.get(second) == Some(index)
            && *shared as f64 >= NEAR_IDENTICAL_SHARE * total(first).max(total(second)) as f64
        {
            close_pairs[*index] += 1;
        }
    }
    for (index, group) in groups.iter_mut().enumerate() {
        let size = group.alerts.len();
        group.shared = shared_by_all[index];
        group.total = group.alerts.iter().map(total).max().unwrap_or(0);
        group.near_identical = close_pairs[index] == size * (size - 1) / 2;
    }
}

/// Disjoint sets by index, with path halving.
struct UnionFind(Vec<usize>);

impl UnionFind {
    fn new(len: usize) -> Self {
        UnionFind((0..len).collect())
    }

    fn find(&mut self, mut n: usize) -> usize {
        while self.0[n] != n {
            self.0[n] = self.0[self.0[n]];
            n = self.0[n];
        }
        n
    }

    fn union(&mut self, a: usize, b: usize) {
        let (a, b) = (self.find(a), self.find(b));
        if a != b {
            // the earlier alert is the root, so a group's root is its first alert in the request
            self.0[a.max(b)] = a.min(b);
        }
    }
}

impl Service {
    /// The service with the overlay's `gui.commonalities_priority_types` (`Ranking`), ace3's list
    /// unless the binary sets another.
    pub fn with_commonality_ranking(mut self, ranking: Ranking) -> Self {
        self.ranking = std::sync::Arc::new(ranking);
        self
    }

    /// The types the Commonalities panel lists first.
    pub fn commonality_ranking(&self) -> &Ranking {
        &self.ranking
    }

    /// `alerts` (1 to `MAX_ALERTS`, in the page's order) grouped by the observable values they share,
    /// leaving out the observables `ignore` names (at most `MAX_IGNORED`, each `type:value`). A request
    /// outside those bounds is `InvalidRequest`, and so is one whose queries run past `LIST_TIMEOUT`.
    pub async fn alert_commonalities(
        &self,
        actor: &crate::Actor,
        alerts: &[Uuid],
        ignore: &[String],
    ) -> Result<Commonalities, ServiceError> {
        if alerts.is_empty() || alerts.len() > MAX_ALERTS {
            return Err(ServiceError::InvalidRequest(format!(
                "commonalities compare 1 to {MAX_ALERTS} alerts"
            )));
        }
        if ignore.len() > MAX_IGNORED {
            return Err(ServiceError::InvalidRequest(format!(
                "commonalities ignore at most {MAX_IGNORED} observables"
            )));
        }
        let mut seen = HashSet::new();
        let order: Vec<Uuid> = alerts
            .iter()
            .copied()
            .filter(|id| seen.insert(*id))
            .collect();
        let ids = &order;
        let observed = self
            .gate
            .read(actor, "alert_commonalities", &ALERT_READ, &|tx| {
                Box::pin(async move {
                    sqlx::raw_sql(SET_LIST_TIMEOUT).execute(tx.conn()).await?;
                    // the page's observables whose value two or more of its alerts have
                    let rows = sqlx::query!(
                        r#"WITH page AS MATERIALIZED (
                               SELECT o.root_id, o.type, o.value, o.value_hash
                               FROM analysis.roots r
                               JOIN analysis.observables o ON o.root_id = r.id
                               WHERE r.id = ANY ($1::uuid[]) AND r.alerted_at IS NOT NULL)
                           SELECT root_id AS "root_id!", type AS "kind!", value AS "value!"
                           FROM page
                           WHERE value_hash IN (SELECT value_hash FROM page GROUP BY value_hash
                                                HAVING count(DISTINCT root_id) >= 2)"#,
                        ids,
                    )
                    .fetch_all(tx.conn())
                    .await
                    .map_err(too_long)?;
                    // how many values each alert has, and which of the ids are alerts
                    let totals = sqlx::query!(
                        r#"SELECT r.id AS "id!", count(DISTINCT o.value_hash) AS "values!"
                           FROM analysis.roots r
                           LEFT JOIN analysis.observables o ON o.root_id = r.id
                           WHERE r.id = ANY ($1::uuid[]) AND r.alerted_at IS NOT NULL
                           GROUP BY r.id"#,
                        ids,
                    )
                    .fetch_all(tx.conn())
                    .await
                    .map_err(too_long)?;
                    Ok(Observed {
                        rows: rows
                            .into_iter()
                            .map(|row| (row.root_id, row.kind, row.value))
                            .collect(),
                        totals: totals
                            .into_iter()
                            .map(|row| (row.id, usize::try_from(row.values).unwrap_or(0)))
                            .collect(),
                    })
                })
            })
            .await?;
        let found = observed.totals.len();
        let commonalities = commonalities_of(&order, observed, ignore, &self.ranking);
        tracing::debug!(
            %actor,
            requested = order.len(),
            found,
            groups = commonalities.groups.len(),
            values = commonalities.observables.len(),
            "compared a page of alerts"
        );
        Ok(commonalities)
    }
}

/// A query cancelled by its timeout as a request to make smaller; anything else as it is.
fn too_long(error: sqlx::Error) -> ServiceError {
    if cancelled(&error) {
        ServiceError::InvalidRequest(format!(
            "comparing these alerts took longer than {LIST_TIMEOUT}: compare fewer"
        ))
    } else {
        error.into()
    }
}
