//! The alert dispositions (PLAN.md 7.14, the owner's decision of 2026-11-13): ace3's `dispositions:` and
//! `disposition_classification:` and `saq/disposition.py`, the one list of dispositions there is.
//!
//! Each disposition has ace3's four keys: `rank`, which an event's roll-up takes the highest of and the
//! event list sorts by; `css`, its badge's class; `show_save_to_event`, whether choosing it offers Save to
//! Event; and `analyst_selectable`, false for one only ACE sets. The defaults are ace3's `saq.default.yaml`
//! (`Dispositions::ace3`), and the site overlay's sections are merged over them (`Dispositions::configured`),
//! which `ace serve` checks when it starts. The service holds the result (`Service::with_dispositions`), and
//! everything reads it from there:
//! - `Service::disposition` takes only a configured name, and from an analyst only one that's
//!   `analyst_selectable`; an analyst can't change an alert whose disposition isn't (ace3's
//!   `is_frozen_disposition`). ACE's own components (`Actor::Internal`) can do both.
//! - The alert list's Disposition filter and the GUI's menus offer the configured names in their order, the
//!   menus only the selectable ones, as ace3's modals do. Badges take `css`.
//! - An event's disposition is its alerts' highest ranked (`Dispositions::rolled_up`), in Rust and in the
//!   event list's query (`Dispositions::ranks`).
//! - The detection verdicts' classes (`DispositionClasses`) are the classification, and which dispositions
//!   only ACE sets.
//! - `Service::disposition_list` is the set for a client, under `alert:read`: whoever reads alerts reads
//!   what their dispositions mean (the owner's decision of 2026-11-14).
//!
//! **What a site can change.** As in ace3, whose merge only adds and replaces, a site changes a disposition's
//! keys or adds a disposition, and can't remove one: a disposition a site no longer wants is set
//! `analyst_selectable: false`, which takes it out of the menus and refuses it from analysts. OPEN, an alert
//! with no disposition yet, keeps rank 0 and stays selectable, and has no class. A disposition stored on an
//! alert that the set doesn't have (a site's own, dropped from its overlay) is kept and shown as it is, as
//! ace3 shows one: its badge is `secondary`, it has no rank, so it never wins an event's roll-up, it's
//! unclassified, and the Disposition filter still finds it, since the filter takes any well-formed name, as
//! ace3's does. Nothing sets it again until it's configured again. `ace serve` doesn't look for such alerts
//! when it starts: it would read every root.
//!
//! What's checked when `ace serve` starts, beyond the overlay's own parse (an unknown key, a key written
//! twice, a null entry): a new disposition's name has the shape `Service::disposition` takes, up to 64 of
//! A-Z, 0-9 and `_` starting with a letter, which is within ace3's rule (upper case, at most 64 characters);
//! a new disposition has `rank` and `css`, as ace3's schema requires; a rank is 0 to `MAX_RANK`, which ace3
//! doesn't bound, since the event list sorts on its digits; `css` is a class token (`is_badge_class`); a
//! classification names a configured disposition, as ace3's schema checks. Ranks needn't be unique, as in ace3; a tie in an event's roll-up goes
//! to the name that sorts first, where ace3's goes to whichever alert it reads first.
//!
//! **`css`.** ace3 takes any text and writes it into a badge's class attribute as `text-bg-<css>`, escaped
//! by Jinja. ace4 writes `disposition-<css>` the same way, escaped by the templates (the owner's decision of
//! 2026-11-14: any text, not only Bootstrap's eight colours). One restriction keeps it one class: `css` is 1
//! to `MAX_BADGE_CLASS_CHARS` of ASCII letters, digits, `-` and `_`. That leaves out white space, which
//! would add other classes of the stylesheet's to the badge, and every character that means something in
//! HTML or a CSS selector. The stylesheet (`static/ace.css`) has a `disposition-` class for each of
//! `BADGE_STYLES`; a badge with any other `css` is the plain badge, the page's text colour in the standard
//! border, until the site's own stylesheet gives `.badge.disposition-<css>` a rule.

use std::collections::BTreeSet;

use crate::detection_verdicts::{DispositionClass, DispositionClasses};
use crate::observables::OPEN;
use crate::permission::ALERT_READ;
use crate::{Actor, Service, ServiceError};

/// The badge classes the GUI's stylesheet has a rule for, `disposition-<name>`: Bootstrap's colours, which
/// ace3's defaults use. A disposition's `css` may be any other class token, which shows as the plain badge.
pub const BADGE_STYLES: &[&str] = &[
    "primary",
    "secondary",
    "success",
    "danger",
    "warning",
    "info",
    "light",
    "dark",
];

/// The badge of a disposition the set doesn't have, ace3's `DEFAULT_DISPOSITION_CSS`.
pub const DEFAULT_BADGE: &str = "secondary";

/// The longest `css`.
pub const MAX_BADGE_CLASS_CHARS: usize = 64;

/// Whether a `css` is one class token: 1 to `MAX_BADGE_CLASS_CHARS` of ASCII letters, digits, `-` and `_`.
/// It's written after `disposition-` in a class attribute, so it needn't start with a letter.
pub fn is_badge_class(css: &str) -> bool {
    !css.is_empty()
        && css.len() <= MAX_BADGE_CLASS_CHARS
        && css
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The highest rank: the event list sorts on a rank's digits, ten of them.
pub const MAX_RANK: i64 = 999_999_999;

/// The longest disposition name: ace3's column.
pub const MAX_DISPOSITION_CHARS: usize = 64;

/// ace3's event disposition with no alerts.
pub(crate) const NO_ALERTS: &str = "DELIVERY";

/// One disposition, ace3's `DispositionConfig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disposition {
    pub name: String,
    /// An event's disposition is its alerts' highest ranked.
    pub rank: i32,
    /// Its badge's class, a class token (`is_badge_class`): the badge is `disposition-<css>`.
    pub css: String,
    /// Whether choosing it offers Save to Event.
    pub show_save_to_event: bool,
    /// False when only ACE sets it.
    pub analyst_selectable: bool,
}

/// ace3's `dispositions:` from its `saq.default.yaml`, in its order: name, rank, css, show_save_to_event,
/// analyst_selectable.
const ACE3: &[(&str, i32, &str, bool, bool)] = &[
    ("OPEN", 0, "light", false, true),
    ("FALSE_POSITIVE", 20, "success", false, true),
    ("IGNORE", 10, "light", false, true),
    ("UNKNOWN", 40, "secondary", true, true),
    ("REVIEWED", 50, "secondary", true, true),
    ("GRAYWARE", 60, "secondary", false, true),
    ("POLICY_VIOLATION", 70, "warning", false, true),
    ("RECONNAISSANCE", 80, "warning", true, true),
    ("WEAPONIZATION", 90, "danger", true, true),
    ("DELIVERY", 100, "danger", true, true),
    ("EXPLOITATION", 110, "danger", true, true),
    ("INSTALLATION", 120, "danger", true, true),
    ("COMMAND_AND_CONTROL", 130, "danger", true, true),
    ("EXFIL", 150, "danger", true, true),
    ("DAMAGE", 160, "danger", true, true),
    ("SIMULATED", 55, "info", false, false),
];

/// ace3's `disposition_classification:`.
const ACE3_CLASSES: &[(&str, DispositionClass)] = ace_sdk::ACE3_DISPOSITION_CLASSES;

/// Whether a name has the shape of a disposition: up to 64 of A-Z, 0-9 and `_`, starting with a letter.
pub fn is_disposition_name(name: &str) -> bool {
    name.len() <= MAX_DISPOSITION_CHARS
        && name.starts_with(|c: char| c.is_ascii_uppercase())
        && name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// Whether an actor is an analyst, whom ace3 checks against a disposition's `analyst_selectable`; ACE's
/// own components aren't.
pub(crate) fn is_analyst(actor: &Actor) -> bool {
    !matches!(actor, Actor::Internal { .. })
}

/// The site's dispositions, in their order: ace3's, then a site's own in its overlay's order, as ace3's
/// merge appends them. With them, the classification the detection verdicts read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dispositions {
    list: Vec<Disposition>,
    classes: DispositionClasses,
}

impl Default for Dispositions {
    fn default() -> Self {
        Dispositions::ace3()
    }
}

impl Dispositions {
    /// ace3's, from its `saq.default.yaml`.
    pub fn ace3() -> Self {
        let list = ACE3
            .iter()
            .map(
                |&(name, rank, css, show_save_to_event, analyst_selectable)| Disposition {
                    name: name.to_owned(),
                    rank,
                    css: css.to_owned(),
                    show_save_to_event,
                    analyst_selectable,
                },
            )
            .collect();
        Dispositions::with_list(
            list,
            ACE3_CLASSES
                .iter()
                .map(|(name, class)| ((*name).to_owned(), *class)),
        )
    }

    fn with_list(
        list: Vec<Disposition>,
        classes: impl IntoIterator<Item = (String, DispositionClass)>,
    ) -> Self {
        let set_by_ace = list
            .iter()
            .filter(|d| !d.analyst_selectable)
            .map(|d| d.name.clone())
            .collect::<Vec<_>>();
        Dispositions {
            classes: DispositionClasses::new(classes, set_by_ace),
            list,
        }
    }

    /// The set a site's overlay makes: its `dispositions` and `disposition_classification` entries over
    /// ace3's, as ace3 merges a site's config over its defaults. What's refused is in the module's docs;
    /// the message says where.
    pub fn configured(overlay: &ace_sdk::Overlay) -> Result<Self, String> {
        let mut list = Dispositions::ace3().list;
        // the file's order, then any entry it didn't record, by name
        let mut names: Vec<&String> = overlay
            .disposition_order
            .iter()
            .filter(|name| overlay.dispositions.contains_key(*name))
            .collect();
        let ordered: BTreeSet<&String> = names.iter().copied().collect();
        names.extend(
            overlay
                .dispositions
                .keys()
                .filter(|name| !ordered.contains(name)),
        );
        for name in names {
            let section = &overlay.dispositions[name];
            let at = |key: &str| format!("dispositions.{name}.{key}");
            let rank = section
                .rank
                .map(|rank| {
                    i32::try_from(rank)
                        .ok()
                        .filter(|rank| (0..=MAX_RANK).contains(&i64::from(*rank)))
                        .ok_or_else(|| {
                            format!(
                                "{}: {rank} isn't a rank, which is 0 to {MAX_RANK}",
                                at("rank")
                            )
                        })
                })
                .transpose()?;
            let css = section
                .css
                .as_deref()
                .map(|css| {
                    if is_badge_class(css) {
                        Ok(css.to_owned())
                    } else {
                        Err(format!(
                            "{}: {css:?} isn't a badge class, which is 1 to {MAX_BADGE_CLASS_CHARS} of \
                             letters, digits, - and _",
                            at("css")
                        ))
                    }
                })
                .transpose()?;
            if name == OPEN {
                if rank.is_some_and(|rank| rank != 0) {
                    return Err(format!(
                        "{}: OPEN is an alert with no disposition yet, which ranks 0, below every other",
                        at("rank")
                    ));
                }
                if section.analyst_selectable == Some(false) {
                    return Err(format!(
                        "{}: OPEN is an alert with no disposition yet, which an analyst can always go back to",
                        at("analyst_selectable")
                    ));
                }
            }
            match list.iter_mut().find(|d| d.name == *name) {
                Some(disposition) => {
                    if let Some(rank) = rank {
                        disposition.rank = rank;
                    }
                    if let Some(css) = css {
                        disposition.css = css;
                    }
                    if let Some(show) = section.show_save_to_event {
                        disposition.show_save_to_event = show;
                    }
                    if let Some(selectable) = section.analyst_selectable {
                        disposition.analyst_selectable = selectable;
                    }
                }
                None => {
                    if !is_disposition_name(name) {
                        return Err(format!(
                            "dispositions.{name}: a disposition's name is up to {MAX_DISPOSITION_CHARS} of \
                             A-Z, 0-9 and _, starting with a letter"
                        ));
                    }
                    let (Some(rank), Some(css)) = (rank, css) else {
                        return Err(format!(
                            "dispositions.{name}: a new disposition needs a rank and a css, as ace3's does"
                        ));
                    };
                    list.push(Disposition {
                        name: name.clone(),
                        rank,
                        css,
                        show_save_to_event: section.show_save_to_event.unwrap_or(false),
                        analyst_selectable: section.analyst_selectable.unwrap_or(true),
                    });
                }
            }
        }
        let mut classes: Vec<(String, DispositionClass)> = ACE3_CLASSES
            .iter()
            .map(|(name, class)| ((*name).to_owned(), *class))
            .collect();
        for (name, class) in &overlay.disposition_classification {
            if name == OPEN {
                return Err(format!(
                    "disposition_classification.{name}: OPEN is an alert with no disposition yet, which is \
                     always unclassified"
                ));
            }
            if !list.iter().any(|d| d.name == *name) {
                return Err(format!(
                    "disposition_classification.{name}: not a disposition in dispositions: {}",
                    list.iter()
                        .map(|d| d.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            classes.retain(|(known, _)| known != name);
            classes.push((name.clone(), *class));
        }
        Ok(Dispositions::with_list(list, classes))
    }

    /// Every disposition, in order.
    pub fn all(&self) -> &[Disposition] {
        &self.list
    }

    /// Every disposition's name, in order: what the Disposition filter offers.
    pub fn names(&self) -> Vec<String> {
        self.list.iter().map(|d| d.name.clone()).collect()
    }

    /// The names an analyst may choose, in order: what the menus offer, ace3's
    /// `get_selectable_dispositions`.
    pub fn selectable(&self) -> Vec<String> {
        self.list
            .iter()
            .filter(|d| d.analyst_selectable)
            .map(|d| d.name.clone())
            .collect()
    }

    /// One disposition, None for a name the set doesn't have.
    pub fn get(&self, name: &str) -> Option<&Disposition> {
        self.list.iter().find(|d| d.name == name)
    }

    /// A disposition's rank, None for a name the set doesn't have.
    pub fn rank(&self, name: &str) -> Option<i32> {
        self.get(name).map(|d| d.rank)
    }

    /// A disposition's badge class, `DEFAULT_BADGE` for a name the set doesn't have; none is OPEN.
    pub fn css(&self, disposition: Option<&str>) -> &str {
        self.get(disposition.unwrap_or(OPEN))
            .map_or(DEFAULT_BADGE, |d| d.css.as_str())
    }

    /// A disposition's class in the detection verdicts, None for an unclassified one.
    pub fn class(&self, name: &str) -> Option<DispositionClass> {
        self.classes.class(Some(name))
    }

    /// Whether choosing the disposition offers Save to Event.
    pub fn show_save_to_event(&self, name: &str) -> bool {
        self.get(name).is_some_and(|d| d.show_save_to_event)
    }

    /// Whether an analyst can't change an alert with this disposition: it's configured, and only ACE sets
    /// it, ace3's `is_frozen_disposition`.
    pub fn is_frozen(&self, disposition: Option<&str>) -> bool {
        disposition
            .and_then(|name| self.get(name))
            .is_some_and(|d| !d.analyst_selectable)
    }

    /// The classification the detection verdicts read.
    pub fn classes(&self) -> &DispositionClasses {
        &self.classes
    }

    /// The names and their ranks, as the event list's query takes them.
    pub fn ranks(&self) -> (Vec<String>, Vec<i32>) {
        self.list.iter().map(|d| (d.name.clone(), d.rank)).unzip()
    }

    /// An event's disposition from its alerts', as ace3's `Event.disposition` rolls it up: `DELIVERY` with no
    /// alerts, else the highest ranked above 0, else OPEN. An alert with none is OPEN, and a disposition the
    /// set doesn't have never wins. A tie goes to the name that sorts first, as the event list's query has it.
    pub fn rolled_up<'a>(&self, dispositions: impl IntoIterator<Item = Option<&'a str>>) -> String {
        let mut dispositions = dispositions.into_iter().peekable();
        if dispositions.peek().is_none() {
            return NO_ALERTS.to_owned();
        }
        let mut best: Option<(i32, &str)> = None;
        for disposition in dispositions.flatten() {
            if disposition == OPEN {
                continue;
            }
            let Some(rank) = self.rank(disposition).filter(|rank| *rank > 0) else {
                continue;
            };
            let beats = match best {
                None => true,
                Some((best_rank, best_name)) => {
                    rank > best_rank || (rank == best_rank && disposition < best_name)
                }
            };
            if beats {
                best = Some((rank, disposition));
            }
        }
        best.map_or(OPEN, |(_, name)| name).to_owned()
    }
}

impl Service {
    /// The site's dispositions for a client, under `alert:read`: the same set the alert list's filter and
    /// badges show to whoever reads alerts.
    pub async fn disposition_list(&self, actor: &Actor) -> Result<&Dispositions, ServiceError> {
        self.gate
            .read(actor, "dispositions", &ALERT_READ, &|_tx| {
                Box::pin(async { Ok(()) })
            })
            .await?;
        Ok(self.dispositions())
    }
}
