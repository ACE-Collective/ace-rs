//! Alert actions (PLAN.md decision 55): links a site's binary adds beside the alert page's own, such as
//! "Open in Triage tool".
//!
//! ace3's `AlertAction` (`saq/gui/alert_actions.py`) is a button with a name, a label, an icon, an
//! optional template included once, a permission and `is_available(alert)`, registered at import and
//! shown in registration order. Here an action is plain data and a link, as an observable action is
//! (`crate::actions`): a name, a label, an optional title, the permission a viewer needs to see it, and its
//! link for an alert, or None when it isn't one for that alert, which is ace3's `is_available`. The site
//! registers it with `ace_app::App::alert_action`, which builds it from the overlay's
//! `alert_actions.<name>` at `ace serve`'s start. It has no template, no script and no icon (ace4 draws no
//! Bootstrap icons): what it does is the page it leads to, which checks its own permission.
//!
//! **Where it may lead.** An observable action's link is built from an observable's value, which an
//! attacker can choose, so it may be only a path on this site or an `https://` URL. An alert action's is
//! built from the site's configuration and the alert's uuid, and may also be `http://` to a loopback
//! host (`localhost`, `127.0.0.0/8`, `[::1]`): a tool on the analyst's own machine, as a local triage tool's UI is
//! (the owner's B1 answer 3). Nothing crosses a network, and browsers treat loopback origins as secure
//! contexts. An absolute link never carries a user name or password, so it can't read as another host
//! (`http://ace.example.com@203.0.113.9/`). Every link is printable ASCII with nothing an attribute or a
//! browser would read differently, as an observable action's. The rule is checked when `ace serve`
//! starts, on the link the action gives a sample alert, and again on every link it draws, so a link
//! that turns unsafe for one alert isn't drawn. It opens in a new tab with `rel="noopener noreferrer"`,
//! so the page it leads to gets no handle on ACE's and no `Referer`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use ace_service::PermissionName;
use serde_json::Value;
use uuid::Uuid;

use crate::session::local_path;

/// The alert an action's link is for.
#[derive(Debug, Clone, Copy)]
pub struct AlertActionTarget<'a> {
    pub alert: Uuid,
    /// Its type, its origin's `alert_type`.
    pub alert_type: Option<&'a str>,
    /// `analysis.roots.origin`, as the submitter gave it.
    pub origin: &'a Value,
}

type Href = dyn Fn(&AlertActionTarget<'_>) -> Option<String> + Send + Sync;

/// One alert action: its name, its label, its title, the permission a viewer needs to see it, and its
/// link for an alert.
#[derive(Clone)]
pub struct AlertAction {
    /// ace3's name for it, such as `triage_open`: 1 to 64 of `a-z`, `0-9` and `_`.
    pub name: &'static str,
    pub label: String,
    /// The link's `title`, what a pointer over it says.
    pub title: Option<String>,
    pub permission: PermissionName,
    href: Arc<Href>,
}

impl std::fmt::Debug for AlertAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlertAction")
            .field("name", &self.name)
            .field("label", &self.label)
            .field("title", &self.title)
            .field("permission", &self.permission)
            .finish_non_exhaustive()
    }
}

impl AlertAction {
    /// An action whose link for an alert is `href`'s, which may capture the action's settings.
    pub fn new(
        name: &'static str,
        label: impl Into<String>,
        permission: PermissionName,
        href: impl Fn(&AlertActionTarget<'_>) -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        AlertAction {
            name,
            label: label.into(),
            title: None,
            permission,
            href: Arc::new(href),
        }
    }

    /// With the link's title.
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// The action's link for an alert, if it has one and it's one to draw (`drawable`).
    pub fn href(&self, target: &AlertActionTarget<'_>) -> Option<String> {
        (self.href)(target).filter(|href| drawable(href))
    }

    /// Why the action can't be offered, checked when `ace serve` starts: its name, its label, or the
    /// link it gives a sample alert, when that isn't one to draw. None when it can be.
    pub fn refusal(&self) -> Option<String> {
        let name_ok = !self.name.is_empty()
            && self.name.len() <= 64
            && self
                .name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        if !name_ok {
            return Some(format!(
                "an alert action's name is 1 to 64 of a-z, 0-9 and _, not {:?}",
                self.name
            ));
        }
        if self.label.trim().is_empty() {
            return Some(format!("the alert action {} has no label", self.name));
        }
        let sample = Value::Object(Default::default());
        let target = AlertActionTarget {
            alert: Uuid::nil(),
            alert_type: None,
            origin: &sample,
        };
        match (self.href)(&target) {
            Some(href) if !drawable(&href) => Some(format!(
                "the alert action {}'s link {href:?} isn't a path on this site, an https:// URL or \
                 an http:// URL to this machine (localhost, 127.0.0.0/8, [::1]), with no user name \
                 or password",
                self.name
            )),
            _ => None,
        }
    }
}

/// Whether an alert action's link may be drawn (the module's docs).
pub fn drawable(href: &str) -> bool {
    let plain = href.len() <= 4096
        && href.bytes().all(|byte| byte.is_ascii_graphic())
        && !href.contains(['"', '\'', '<', '>', '\\', '`']);
    if !plain {
        return false;
    }
    if local_path(href).is_some() {
        return true;
    }
    if let Some(rest) = href.strip_prefix("https://") {
        return authority(rest).is_some_and(|(host, _)| !host.is_empty());
    }
    if let Some(rest) = href.strip_prefix("http://") {
        return authority(rest).is_some_and(|(host, _)| loopback(host));
    }
    false
}

/// The host and port of a URL's authority, the part before its path, query or fragment; None when it
/// carries a user name or password, or its port isn't one.
fn authority(rest: &str) -> Option<(&str, Option<u16>)> {
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if authority.contains('@') {
        return None;
    }
    let port = |text: &str| -> Option<Option<u16>> {
        match text {
            "" => Some(None),
            _ if text.bytes().all(|b| b.is_ascii_digit()) => text.parse().ok().map(Some),
            _ => None,
        }
    };
    if let Some(v6) = authority.strip_prefix('[') {
        let (host, after) = v6.split_once(']')?;
        let after = match after {
            "" => "",
            _ => after.strip_prefix(':')?,
        };
        return Some((host, port(after)?)).filter(|(host, _)| host.parse::<Ipv6Addr>().is_ok());
    }
    match authority.split_once(':') {
        Some((host, text)) => Some((host, port(text)?)),
        None => Some((authority, None)),
    }
}

/// Whether a URL's host is this machine: `localhost`, an address in `127.0.0.0/8`, or `::1`.
fn loopback(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_loopback())
        || host.parse::<Ipv6Addr>().is_ok_and(|ip| ip.is_loopback())
}

/// The binary's alert actions, in the order it registered them.
#[derive(Debug, Clone, Default)]
pub struct AlertActions {
    actions: Vec<AlertAction>,
}

/// An action's link as the page draws it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertActionLink {
    pub name: &'static str,
    pub label: String,
    pub title: Option<String>,
    pub href: String,
}

impl AlertActions {
    /// No actions, ace4's own.
    pub fn empty() -> Self {
        AlertActions::default()
    }

    /// These actions and `action`, which takes the place of one with the same name.
    pub fn with(mut self, action: AlertAction) -> Self {
        match self.actions.iter_mut().find(|a| a.name == action.name) {
            Some(existing) => *existing = action,
            None => self.actions.push(action),
        }
        self
    }

    pub fn names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.actions.iter().map(|a| a.name)
    }

    pub fn iter(&self) -> impl Iterator<Item = &AlertAction> + '_ {
        self.actions.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    /// The links of the actions `may` lets the viewer see that have one for this alert.
    pub fn links(
        &self,
        target: &AlertActionTarget<'_>,
        may: impl Fn(&PermissionName) -> bool,
    ) -> Vec<AlertActionLink> {
        self.actions
            .iter()
            .filter(|action| may(&action.permission))
            .filter_map(|action| {
                Some(AlertActionLink {
                    name: action.name,
                    label: action.label.clone(),
                    title: action.title.clone(),
                    href: action.href(target)?,
                })
            })
            .collect()
    }
}
