//! The pages, as askama templates in this crate's `templates/` with a struct each. askama compiles a
//! template into Rust at build time, so the binary holds them all and a template that uses a field its
//! struct doesn't have fails the build, which is PLAN.md 5.7's Done check. These doctests are that
//! check, and `cargo test` runs them. A page that extends the base layout, with its `layout`, builds:
//!
//! ```
//! use ace_gui::templates::Layout;
//! use askama::Template;
//!
//! #[derive(Template)]
//! #[template(
//!     source = r#"{% extends "base.html" %}{% block content %}{{ present }}{% endblock %}"#,
//!     ext = "html"
//! )]
//! struct Page {
//!     layout: Layout,
//!     present: String,
//! }
//!
//! let page = Page { layout: Layout::signed_out("a-nonce"), present: "<b>".to_owned() };
//! assert!(page.render().unwrap().contains("&#60;b&#62;"));
//! ```
//!
//! The same page naming a field the struct doesn't have doesn't build. The error is rustc's E0609, "no
//! field `missing` on type", at the struct's `#[derive(Template)]`. Stable rustdoc doesn't check the code a `compile_fail` test names,
//! only that compiling fails, so what pins the cause is that this differs from the test above only in
//! the field it names:
//!
//! ```compile_fail,E0609
//! use ace_gui::templates::Layout;
//! use askama::Template;
//!
//! #[derive(Template)]
//! #[template(
//!     source = r#"{% extends "base.html" %}{% block content %}{{ missing }}{% endblock %}"#,
//!     ext = "html"
//! )]
//! struct Page {
//!     layout: Layout,
//!     present: String,
//! }
//! ```
//!
//! And the base layout itself fails for a page whose struct has no `layout`:
//!
//! ```compile_fail,E0609
//! use askama::Template;
//!
//! #[derive(Template)]
//! #[template(path = "base.html")]
//! struct Page {
//!     present: String,
//! }
//! ```
//!
//! Escaping: askama escapes every value for HTML in a template whose name ends in `.html`, unless it's
//! marked `|safe`, the template sets `escape = "none"`, or its type is marked `HtmlSafe`: two are, a
//! view's `ViewHtml` (`analysis`) and a guide's `GuideHtml` (`help`), each made in one place. Every
//! template here ends in `.html`, none uses `|safe` or sets its escaper, and there's no `askama.toml`
//! to change the escapers, which `tests/gui.rs` checks by reading
//! them. A value is text, and askama's escaper writes `&`, `<`, `>`, `"` and `'` as entities, so it's safe
//! inside an element or a quoted attribute. It isn't safe as a URL in `href`, or as code in a `data-*`
//! expression, so a template puts neither text from an alert nor any other outside value there.

use ace_service::Theme;
use askama::Template;

use crate::assets::{DATASTAR, STYLESHEET};

/// What the base layout needs, which every page has as its `layout`.
#[derive(Debug, Clone)]
pub struct Layout {
    /// This response's CSP nonce (`headers`), which Datastar's script and `<html data-nonce>` carry.
    pub nonce: String,
    pub theme: Theme,
    /// Every theme, for the menu.
    pub themes: &'static [Theme],
    /// The signed-in user's name, or None for a visitor who isn't.
    pub username: Option<String>,
    /// The page's own path, where the theme form comes back to.
    pub path: String,
    /// Whether the viewer holds `admin:read`, for the link to the administration area.
    pub admin: bool,
    /// Whether the viewer holds `signature:read`, for the link to the signatures area.
    pub signatures: bool,
    /// Whether the viewer holds `svs:run_read`, for the link to the SVS area (PLAN.md 7.10 batch 5).
    pub svs: bool,
    /// How many test runs need attention, beside that link (batch 9): ace3's `svs_nav_count`. None
    /// when no run does, when the count can't be read, and for a viewer without `svs:run_read`.
    pub svs_attention: Option<String>,
    /// Whether the viewer holds `event:read`, for the link to the event list.
    pub events: bool,
    /// Whether the viewer holds `remediation:read` and `file_collection:read`, for the links to those
    /// areas (PLAN.md 7.9).
    pub remediations: bool,
    pub file_collections: bool,
    pub stylesheet: String,
    pub datastar: String,
    /// The page's own scripts, after Datastar, each loaded with the nonce and deferred. Only the graph's
    /// page (5.13) has any.
    pub scripts: Vec<String>,
}

impl Layout {
    pub fn new(nonce: &str, theme: Theme, username: Option<String>, path: &str) -> Self {
        Layout {
            nonce: nonce.to_owned(),
            theme,
            themes: Theme::ALL,
            username,
            path: path.to_owned(),
            admin: false,
            signatures: false,
            svs: false,
            svs_attention: None,
            events: false,
            remediations: false,
            file_collections: false,
            stylesheet: STYLESHEET.url(),
            datastar: DATASTAR.url(),
            scripts: Vec::new(),
        }
    }

    /// A page for a visitor who isn't signed in, in the default theme.
    pub fn signed_out(nonce: &str) -> Self {
        Layout::new(nonce, Theme::default(), None, "/")
    }

    /// The section of the site the page is in, which the navigation marks as the current one:
    /// `alerts`, `events`, `remediations`, `file-collections`, `signatures`, `svs`, `admin`, `help`,
    /// or nothing for a page in none, such as the preferences.
    pub fn section(&self) -> &'static str {
        let path = self.path.split(['?', '#']).next().unwrap_or_default();
        let first = path.trim_start_matches('/').split('/').next().unwrap_or("");
        match first {
            "" | "alerts" | "search" | "filters" => "alerts",
            "events" => "events",
            "remediations" => "remediations",
            "file-collections" => "file-collections",
            "signatures" => "signatures",
            "svs" => "svs",
            "admin" => "admin",
            "help" => "help",
            _ => "",
        }
    }

    /// Whether the menu marks this theme as the page's.
    pub fn is_theme(&self, theme: &Theme) -> bool {
        *theme == self.theme
    }
}

/// `/login`.
#[derive(Debug, Template)]
#[template(path = "login.html")]
pub struct LoginPage {
    pub layout: Layout,
    /// Where to go after the login, already checked to be a path on this site.
    pub next: Option<String>,
    /// Whether this is the answer to a login that failed.
    pub failed: bool,
    /// Whether the visitor comes from changing their password, which ended their sessions.
    pub password_changed: bool,
}

/// `/login/change`, ace3's `auth/change-password.html`: a signed-in user changing their own password.
#[derive(Debug, Template)]
#[template(path = "change_password.html")]
pub struct ChangePasswordPage {
    pub layout: Layout,
    /// Why the last attempt was refused, or None for a first look.
    pub problem: Option<String>,
    /// `ace_service::MIN_PASSWORD_CHARS`, the rule the page states.
    pub min_chars: usize,
    /// `ace_service::MAX_PASSWORD_BYTES`.
    pub max_bytes: usize,
}

impl ChangePasswordPage {
    /// The page with the service's rules, and a problem or none.
    pub fn new(layout: Layout, problem: Option<String>) -> Self {
        ChangePasswordPage {
            layout,
            problem,
            min_chars: ace_service::MIN_PASSWORD_CHARS,
            max_bytes: ace_service::MAX_PASSWORD_BYTES,
        }
    }
}

/// A refusal or a failure, as a page.
#[derive(Debug, Template)]
#[template(path = "error.html")]
pub struct ErrorPage {
    pub layout: Layout,
    pub status: u16,
    pub message: String,
}
