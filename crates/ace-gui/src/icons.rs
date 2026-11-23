//! Pivot link icons (PLAN.md decision 32 part (b)): the images a pivot link may show beside its label,
//! each registered by name with its bytes, which the binary embeds, and served by the GUI itself at
//! `/icons/<name>.<hash>.png`, so a page loads images from ACE alone and its policy (`img-src 'self'`)
//! stays as it is.
//!
//! ace3's pivot link names its icon as a `data:` URL, another site's image or a file under its static
//! directory, and its alert page draws whichever. A result here names a registered icon
//! (`ace_results::PivotLink::icon`), and the link shows its label alone when the binary has no icon by
//! that name. A site registers its own with `ace_app::App::pivot_link_icon`. ace-rs ships none: no ace3
//! open-source module adds a pivot link unless a site's configuration gives it one (the Splunk API
//! analyzer's `pivot_links`, a hunt's), and those name the site's own images.
//!
//! An icon is a PNG of at most 64 KiB, checked when it is registered. Like an asset, its URL carries
//! the first 16 hex digits of its SHA-256, so a browser may keep it for a year.

use std::collections::BTreeMap;

use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

use crate::Gui;

/// The largest icon, in bytes.
pub const MAX_ICON_BYTES: usize = 64 * 1024;

const PNG_SIGNATURE: &[u8] = b"\x89PNG\r\n\x1a\n";

/// One registered icon.
#[derive(Debug, Clone)]
pub struct PivotIcon {
    pub name: &'static str,
    pub png: &'static [u8],
    file: String,
}

impl PivotIcon {
    /// The icon `name`, a PNG, or why it can't be one.
    pub fn new(name: &'static str, png: &'static [u8]) -> Result<PivotIcon, String> {
        if !ace_results::is_icon_name(name) {
            return Err(format!(
                "{name:?} isn't an icon's name: 1 to 64 of a-z, 0-9, _ and -"
            ));
        }
        if !png.starts_with(PNG_SIGNATURE) {
            return Err(format!("the icon {name} isn't a PNG"));
        }
        if png.len() > MAX_ICON_BYTES {
            return Err(format!(
                "the icon {name} is {} bytes, past {MAX_ICON_BYTES}",
                png.len()
            ));
        }
        let hash = hex::encode(Sha256::digest(png));
        Ok(PivotIcon {
            name,
            png,
            file: format!("{name}.{}.png", &hash[..16]),
        })
    }

    /// The path a page loads it from.
    pub fn url(&self) -> String {
        format!("/icons/{}", self.file)
    }
}

/// The binary's icons, by name.
#[derive(Debug, Clone, Default)]
pub struct PivotIcons {
    by_name: BTreeMap<&'static str, PivotIcon>,
}

impl PivotIcons {
    /// ace-rs's own: none (the module's docs).
    pub fn builtin() -> PivotIcons {
        PivotIcons::default()
    }

    /// With `icon`, in place of one of the same name.
    pub fn with(mut self, icon: PivotIcon) -> PivotIcons {
        self.by_name.insert(icon.name, icon);
        self
    }

    pub fn get(&self, name: &str) -> Option<&PivotIcon> {
        self.by_name.get(name)
    }

    pub fn names(&self) -> Vec<&'static str> {
        self.by_name.keys().copied().collect()
    }

    fn by_file(&self, file: &str) -> Option<&PivotIcon> {
        self.by_name.values().find(|icon| icon.file == file)
    }
}

/// A link as a page draws it: where it goes, what it says, and its icon's URL when the binary has the
/// icon it names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrawnLink {
    pub url: String,
    pub text: String,
    pub icon: Option<String>,
}

impl DrawnLink {
    /// The links to draw of `links`: each one that is still a plain `https://` link (the core took
    /// no other), with its icon's URL from `icons`.
    pub fn of(links: &[ace_results::PivotLink], icons: &PivotIcons) -> Vec<DrawnLink> {
        links
            .iter()
            .filter(|link| link.refusal().is_none())
            .map(|link| DrawnLink {
                url: link.url.clone(),
                text: link.text.clone(),
                icon: link
                    .icon
                    .as_deref()
                    .and_then(|name| icons.get(name))
                    .map(PivotIcon::url),
            })
            .collect()
    }
}

/// `GET /icons/{file}`.
pub(crate) async fn serve(State(gui): State<Gui>, Path(file): Path<String>) -> Response {
    let Some(icon) = gui.icons().by_file(&file) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut response = icon.png.into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("image/png"));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    response
}
