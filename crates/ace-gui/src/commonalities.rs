//! The alert list's Commonalities panel (PLAN.md 7.23), ace3's `manage_commonalities.js` (`9260f7cd`):
//! a grid of the page's alerts that share observable values, a row per alert and a column per value,
//! grouped as `Service::alert_commonalities` groups them, above the list.
//!
//! ace3 draws the grid in the browser from its API's answer. Here the server draws it with the list, in
//! the fragment the refresh morphs in, so it follows the alerts listed with nothing more to poll, and the
//! page loads no script for it. Its state is the list's URL, as the rest of the list's is (`ListQuery`):
//! `common=1` shows it, `ignore=type:value` leaves a value out of the grouping, and `expand=<key>` shows
//! every column of a group, keyed by the group's least alert id, which stays its key while that alert is
//! in it. Every link of the list carries them.
//!
//! What it does, as ace3's: each group's head says how many alerts are in it and whether they are
//! near-identical, and what links it to other groups; its box ticks or unticks its alerts for the bulk
//! actions; a group shows its first `MAX_COLUMNS` values (none for a near-identical group) and the values
//! linking groups, and folds the rest into a column that says how many of them each alert has; a value's
//! label opens a menu that ticks its alerts, ignores it when grouping, or adds `NOT Observable` for it to
//! the list's filters; a count row says how many alerts have each value; and each listed alert in a group
//! says, beside its description, how many others it potentially relates to. Squares are colored by how
//! much their group's alerts have in common, and labels by their type, a type taking the color of its
//! furthest ancestor (`email_from` as `email_address`).
//!
//! Where it differs from ace3, each for a reason:
//! - Shown and ignored are in the URL, not the browser's storage, so a reload, the back button and a
//!   shared link keep them, and a new visit to the list starts without them.
//! - The policy refuses a `style` attribute (`headers`), so a square's color is one of five steps of the
//!   heat ramp, and a type's one of eight hues, each a class of the stylesheet, where ace3 sets colors
//!   inline.
//! - ace3 highlights the list's rows and a column as the pointer moves over the grid, and shows a tip
//!   beside the pointer. Here each square's and label's title says what it is, and a row is highlighted
//!   while the pointer is on it; nothing runs for the pointer.
//! - A group's box and a value's "Select" are Datastar expressions over `$_sel`, the list's ticked ids,
//!   reading the ids from the element's `data-ids`, which the server writes as JSON.
//! - A list page holds at most `MAX_PAGE_SIZE` (200) alerts, below the 500 the service compares, so ace3's
//!   "comparing the first 500" never shows. At most `MAX_SHOWN_COLUMNS` value columns are drawn; past
//!   that a group's values fold into its "+N more" column even when it's expanded, so one page's grid is
//!   bounded however many values its alerts share.
//! - A menu that's open when the list refreshes closes, since the refresh draws the panel again.
//! - "Filter out" is left out for a value longer than a filter's 256 characters, which the list's
//!   filters can't hold.

use std::collections::HashSet;

use ace_service::commonalities::{Commonalities, CommonalityObservable, MAX_IGNORED};
use ace_service::filters::{FilterEntry, FilterValue, MAX_FILTER_VALUE_CHARS};
use ace_service::{AlertPage, ServiceError};
use uuid::Uuid;

use crate::list::{AlertList, ListQuery, Mark};

/// The values a group shows before the rest fold into its "+N more" column, ace3's `MAX_COLUMNS`.
pub const MAX_COLUMNS: usize = 10;
/// The most value columns one grid draws.
pub const MAX_SHOWN_COLUMNS: usize = 200;
/// The heat ramp's steps, `heat-0` to `heat-4` in the stylesheet.
const HEAT_STEPS: f64 = 4.0;
/// The type hues, `hue-0` to `hue-7` in the stylesheet.
const HUES: u32 = 8;
/// The marks' classes by heat step: the list's marks take a `&'static str`.
const MARK_CLASSES: [&str; 5] = [
    "commonality heat-0",
    "commonality heat-1",
    "commonality heat-2",
    "commonality heat-3",
    "commonality heat-4",
];

/// The panel as the list's fragment draws it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Panel {
    /// Why the alerts couldn't be compared, which the panel says in their place.
    pub error: Option<String>,
    /// The page lists no alerts.
    pub empty_page: bool,
    /// The values left out of the grouping, each with the link that groups by it again.
    pub ignored: Vec<(Chip, String)>,
    pub max_ignored: usize,
    pub columns: Vec<Column>,
    pub groups: Vec<GroupView>,
    pub unrelated: usize,
    /// A value links groups, so the legend explains the outlined square.
    pub links: bool,
    /// Values that weren't drawn as columns of their own past `MAX_SHOWN_COLUMNS`.
    pub cut: usize,
    pub max_columns: usize,
    pub max_shown: usize,
    /// The link that hides the panel.
    pub hide: String,
}

/// A value's label: its type, and how many more types it has, its value, and its hue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chip {
    pub label: String,
    pub value: String,
    pub title: String,
    pub hue: u32,
}

/// A column of the grid: a value's, or a group's "+N more".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Column {
    pub stripe: bool,
    pub value: Option<ValueColumn>,
    pub more: Option<MoreColumn>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueColumn {
    pub chip: Chip,
    /// How many groups it links; 1 when it links none.
    pub groups: usize,
    /// How many of the page's alerts have it.
    pub count: usize,
    /// Its alerts, as JSON, for "Select".
    pub ids: String,
    /// The link that ignores it, None when `MAX_IGNORED` are already.
    pub ignore: Option<String>,
    /// The link that filters it out, and the filter it adds; None for a value too long for a filter.
    pub filter_out: Option<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoreColumn {
    /// `+3 more`, or `3 shared` for a near-identical group.
    pub label: String,
    pub href: String,
}

/// One group's head and rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupView {
    /// Its id in the page, which its alerts' marks link to.
    pub anchor: String,
    pub heat: u32,
    pub title: String,
    pub detail: String,
    /// Its alerts as JSON, for its box.
    pub ids: String,
    /// The link that shows every column or fewer, and its text.
    pub toggle: Option<(String, String)>,
    /// What links it to other groups: `also linked to 2 alerts via`, and the value.
    pub links: Vec<(String, String)>,
    pub rows: Vec<GroupRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRow {
    pub id: Uuid,
    pub description: String,
    pub squares: Vec<Square>,
}

/// A cell of an alert's row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Square {
    pub stripe: bool,
    /// `filled`, `linked` (filled, and the value links groups), `missing` (a value of the alert's own
    /// group it doesn't have), `wide` (its group's "+N more", with `text`), or empty for nothing.
    pub look: &'static str,
    pub text: String,
    pub title: String,
}

/// The group's key in `expand=`: its least alert id.
fn key(alerts: &[Uuid]) -> Uuid {
    alerts.iter().min().copied().unwrap_or_default()
}

fn heat(intensity: f64) -> u32 {
    (intensity.clamp(0.0, 1.0) * HEAT_STEPS).round() as u32
}

fn plural(n: usize, word: &str) -> String {
    format!("{n} {word}{}", if n == 1 { "" } else { "s" })
}

/// A type's hue: that of the furthest type it extends, so a type looks like its family in every column,
/// from its name as ace3 derives a color for a type with none of its own.
fn hue(kind: &str, found: &Commonalities) -> u32 {
    let family = found
        .type_ancestors
        .get(kind)
        .and_then(|chain| chain.last())
        .map_or(kind, String::as_str);
    family.bytes().fold(0u32, |hash, byte| {
        hash.wrapping_mul(31).wrapping_add(u32::from(byte))
    }) % HUES
}

fn chip(kind: &str, kinds: &[String], value: &str, found: &Commonalities) -> Chip {
    let more = kinds.len().saturating_sub(1);
    Chip {
        label: if more > 0 {
            format!("{kind} +{more}")
        } else {
            kind.to_owned()
        },
        value: value.to_owned(),
        title: format!(
            "{}: {value}",
            if kinds.is_empty() {
                kind.to_owned()
            } else {
                kinds.join(", ")
            }
        ),
        hue: hue(kind, found),
    }
}

fn ids_json(ids: &[Uuid]) -> String {
    serde_json::to_string(&ids.iter().map(Uuid::to_string).collect::<Vec<_>>())
        .expect("ids are JSON")
}

/// The list with `NOT Observable` for every type the alerts have `o` as.
fn filter_out(query: &ListQuery, o: &CommonalityObservable) -> Option<(String, String)> {
    if o.value.chars().count() > MAX_FILTER_VALUE_CHARS {
        return None;
    }
    let mut filters = query.filters.clone();
    filters.push(FilterEntry::new(
        "Observable",
        true,
        o.kinds
            .iter()
            .map(|kind| FilterValue::Pair(kind.clone(), o.value.clone()))
            .collect(),
    ));
    Some((
        query.with_filters(&filters),
        format!("NOT Observable: {}", o.specs().join(" | ")),
    ))
}

/// Where a column goes: a value's index in `observables`, or a group's "+N more" with the values it
/// folds.
enum Place {
    Value(usize),
    More(usize, Vec<usize>),
}

/// ace3's `layout`: per group, the values linking groups and its first `MAX_COLUMNS` (none for a
/// near-identical one), or all of them when it's expanded, then one "+N more" column for the rest.
fn layout(found: &Commonalities, expanded: &HashSet<Uuid>) -> (Vec<Place>, usize) {
    let mut places = Vec::new();
    let mut shown = 0;
    let mut cut = 0;
    for (g, group) in found.groups.iter().enumerate() {
        let all = expanded.contains(&key(&group.alerts));
        let limit = if group.near_identical { 0 } else { MAX_COLUMNS };
        let mut hidden = Vec::new();
        let owned = found
            .observables
            .iter()
            .enumerate()
            .filter(|(_, o)| o.group == g);
        for (n, (i, o)) in owned.enumerate() {
            let wanted = all || o.groups.len() > 1 || n < limit;
            if wanted && shown < MAX_SHOWN_COLUMNS {
                places.push(Place::Value(i));
                shown += 1;
            } else {
                if wanted {
                    cut += 1;
                }
                hidden.push(i);
            }
        }
        if !hidden.is_empty() {
            places.push(Place::More(g, hidden));
        }
    }
    (places, cut)
}

/// The panel for a page of the list and what the service made of it.
pub fn panel(
    page: &AlertPage,
    query: &ListQuery,
    compared: Result<&Commonalities, String>,
) -> Panel {
    let ignored = query
        .ignore
        .iter()
        .enumerate()
        .map(|(at, spec)| {
            let (kind, value) = spec.split_once(':').unwrap_or((spec.as_str(), ""));
            let href = query.changed(|q| {
                q.ignore.remove(at);
            });
            let empty = Commonalities::default();
            (chip(kind, &[], value, &empty), href)
        })
        .collect();
    let mut panel = Panel {
        error: None,
        empty_page: page.alerts.is_empty(),
        ignored,
        max_ignored: MAX_IGNORED,
        columns: Vec::new(),
        groups: Vec::new(),
        unrelated: 0,
        links: false,
        cut: 0,
        max_columns: MAX_COLUMNS,
        max_shown: MAX_SHOWN_COLUMNS,
        hide: query.changed(|q| {
            q.commonalities = false;
            q.expand.clear();
        }),
    };
    let found = match compared {
        Ok(found) => found,
        Err(why) => {
            panel.error = Some(why);
            return panel;
        }
    };
    let descriptions: std::collections::HashMap<Uuid, &str> = page
        .alerts
        .iter()
        .map(|alert| (alert.id, alert.title.as_str()))
        .collect();
    let expanded: HashSet<Uuid> = query.expand.iter().copied().collect();
    let (places, cut) = layout(found, &expanded);
    let has = |i: usize, alert: &Uuid| found.observables[i].alerts.contains(alert);

    panel.columns = places
        .iter()
        .enumerate()
        .map(|(n, place)| match place {
            Place::Value(i) => {
                let o = &found.observables[*i];
                let fresh: Vec<String> = o
                    .specs()
                    .into_iter()
                    .filter(|spec| !query.ignore.contains(spec))
                    .collect();
                Column {
                    stripe: n % 2 == 1,
                    value: Some(ValueColumn {
                        chip: chip(&o.kind, &o.kinds, &o.value, found),
                        groups: o.groups.len(),
                        count: o.alerts.len(),
                        ids: ids_json(&o.alerts),
                        ignore: (query.ignore.len() + fresh.len() <= MAX_IGNORED)
                            .then(|| query.changed(|q| q.ignore.extend(fresh.iter().cloned()))),
                        filter_out: filter_out(query, o),
                    }),
                    more: None,
                }
            }
            Place::More(g, hidden) => {
                let group = &found.groups[*g];
                Column {
                    stripe: n % 2 == 1,
                    value: None,
                    more: Some(MoreColumn {
                        label: if group.near_identical {
                            format!("{} shared", hidden.len())
                        } else {
                            format!("+{} more", hidden.len())
                        },
                        href: query.changed(|q| q.expand.push(key(&group.alerts))),
                    }),
                }
            }
        })
        .collect();

    panel.groups = found
        .groups
        .iter()
        .enumerate()
        .map(|(g, group)| {
            let owned = found.observables.iter().filter(|o| o.group == g).count();
            let group_key = key(&group.alerts);
            let is_expanded = expanded.contains(&group_key);
            let size = group.alerts.len();
            let (title, detail) = if group.near_identical {
                (
                    format!("{size} near-identical alerts"),
                    format!(
                        ": they share {} observables",
                        if group.shared == group.total {
                            format!("all {}", group.total)
                        } else {
                            format!("{} of their {}", group.shared, group.total)
                        }
                    ),
                )
            } else {
                (format!("{size} potentially related alerts"), String::new())
            };
            let limit = if group.near_identical { 0 } else { MAX_COLUMNS };
            let toggle = (owned > limit || is_expanded).then(|| {
                let text = if is_expanded {
                    "show fewer".to_owned()
                } else if group.near_identical {
                    "show the observables".to_owned()
                } else {
                    format!("show all {owned}")
                };
                let href = query.changed(|q| {
                    if is_expanded {
                        q.expand.retain(|k| *k != group_key);
                    } else {
                        q.expand.push(group_key);
                    }
                });
                (href, text)
            });
            let links = found
                .observables
                .iter()
                .filter(|o| o.groups.len() > 1 && o.groups.contains(&g))
                .map(|o| {
                    let others = o
                        .alerts
                        .iter()
                        .filter(|id| !group.alerts.contains(id))
                        .count();
                    (
                        format!("also linked to {} via", plural(others, "alert")),
                        o.value.clone(),
                    )
                })
                .collect();
            let rows = group
                .alerts
                .iter()
                .map(|alert| GroupRow {
                    id: *alert,
                    description: descriptions
                        .get(alert)
                        .map_or_else(|| alert.to_string(), |d| (*d).to_owned()),
                    squares: places
                        .iter()
                        .enumerate()
                        .map(|(n, place)| {
                            let stripe = n % 2 == 1;
                            match place {
                                Place::Value(i) => {
                                    let o = &found.observables[*i];
                                    let spec = format!("{}: {}", o.kinds.join(", "), o.value);
                                    if has(*i, alert) {
                                        Square {
                                            stripe,
                                            look: if o.groups.len() > 1 {
                                                "linked"
                                            } else {
                                                "filled"
                                            },
                                            text: String::new(),
                                            title: format!("{spec}: this alert has it"),
                                        }
                                    } else if o.group == g {
                                        Square {
                                            stripe,
                                            look: "missing",
                                            text: String::new(),
                                            title: format!("{spec}: this alert doesn't have it"),
                                        }
                                    } else {
                                        Square {
                                            stripe,
                                            look: "",
                                            text: String::new(),
                                            title: String::new(),
                                        }
                                    }
                                }
                                Place::More(more, hidden) if *more == g => {
                                    let count = hidden.iter().filter(|i| has(**i, alert)).count();
                                    Square {
                                        stripe,
                                        look: "wide",
                                        text: count.to_string(),
                                        title: format!(
                                            "this alert has {count} of the group's {} other values",
                                            hidden.len()
                                        ),
                                    }
                                }
                                Place::More(..) => Square {
                                    stripe,
                                    look: "",
                                    text: String::new(),
                                    title: String::new(),
                                },
                            }
                        })
                        .collect(),
                })
                .collect();
            GroupView {
                anchor: format!("commonality-group-{g}"),
                heat: heat(group.intensity),
                title,
                detail,
                ids: ids_json(&group.alerts),
                toggle,
                links,
                rows,
            }
        })
        .collect();
    panel.unrelated = found.unrelated;
    panel.links = found.observables.iter().any(|o| o.groups.len() > 1);
    panel.cut = cut;
    panel
}

/// Each listed alert in a group says how many others it potentially relates to, beside its
/// description, linking to its group in the panel: ace3's badge.
pub fn mark_related(list: &mut AlertList, found: &Commonalities) {
    for row in &mut list.rows {
        let (Some(related), Some(g)) = (found.related.get(&row.id), found.group_of(row.id)) else {
            continue;
        };
        let class = MARK_CLASSES[heat(found.groups[g].intensity) as usize];
        if let Some(cell) = row.cells.iter_mut().find(|cell| cell.id == "description") {
            cell.marks.push(Mark {
                text: format!("potentially related to {}", plural(*related, "alert")),
                class,
                title: Some(
                    "alerts on this page that share observables with it: see Commonalities",
                ),
                href: Some(format!("#commonality-group-{g}")),
            });
        }
    }
}

/// The panel for a page, asking the service to compare its alerts, and the list's marks: what the page
/// and its refresh draw while the panel is shown. A failure is the panel's to say, not the list's: the
/// list is still drawn.
pub(crate) async fn compare(
    gui: &crate::Gui,
    actor: &ace_service::Actor,
    page: &AlertPage,
    query: &ListQuery,
    list: &mut AlertList,
) {
    if page.alerts.is_empty() {
        list.panel = Some(panel(page, query, Ok(&Commonalities::default())));
        return;
    }
    let ids: Vec<Uuid> = page.alerts.iter().map(|alert| alert.id).collect();
    let compared = gui
        .service
        .alert_commonalities(actor, &ids, &query.ignore)
        .await;
    match compared {
        Ok(found) => {
            mark_related(list, &found);
            list.panel = Some(panel(page, query, Ok(&found)));
        }
        Err(error) => {
            match &error {
                ServiceError::InvalidRequest(_) | ServiceError::PermissionDenied { .. } => {
                    tracing::info!(%actor, "the alerts on a list page couldn't be compared: {error}");
                }
                _ => tracing::error!(%actor, "comparing the alerts on a list page failed: {error}"),
            }
            list.panel = Some(panel(
                page,
                query,
                Err(format!("Could not compare the alerts: {error}")),
            ));
        }
    }
}
