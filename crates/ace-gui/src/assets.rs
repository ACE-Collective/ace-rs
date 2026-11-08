//! The files a page loads, embedded in the binary with `include_bytes!`, so the binary serves them
//! wherever it runs and reads nothing from disk (PLAN.md 0.7, ace3 #920).
//!
//! An asset's URL carries the first 16 hex digits of its SHA-256, as `/static/ace.<hash>.css`, so a
//! browser may keep it for a year (`immutable`): a new build with a changed file has a new URL. Any other
//! name under `/static/` is 404, an old hash included, since this binary has only its own bytes. ace3
//! appends a hash as a query string to files it serves from disk; here the hash is in the path.

use std::sync::LazyLock;

use axum::extract::Path;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

/// One embedded file.
#[derive(Debug)]
pub struct Asset {
    /// Its name with the hash, as its URL has it.
    pub name: String,
    pub bytes: &'static [u8],
    pub content_type: &'static str,
}

impl Asset {
    fn new(stem: &str, extension: &str, bytes: &'static [u8], content_type: &'static str) -> Self {
        let hash = hex::encode(Sha256::digest(bytes));
        Asset {
            name: format!("{stem}.{}.{extension}", &hash[..16]),
            bytes,
            content_type,
        }
    }

    /// The path a page links to.
    pub fn url(&self) -> String {
        format!("/static/{}", self.name)
    }
}

/// Datastar, from `vendor/datastar` (`vendor/README.md`), unchanged.
pub(crate) static DATASTAR: LazyLock<Asset> = LazyLock::new(|| {
    Asset::new(
        "datastar-1.0.4",
        "js",
        include_bytes!("../../../vendor/datastar/datastar-1.0.4.js"),
        "text/javascript; charset=utf-8",
    )
});

/// The stylesheet, with ace3's five themes.
pub(crate) static STYLESHEET: LazyLock<Asset> = LazyLock::new(|| {
    Asset::new(
        "ace",
        "css",
        include_bytes!("../static/ace.css"),
        "text/css; charset=utf-8",
    )
});

/// The asset whose hashed name this is.
pub fn asset_named(name: &str) -> Option<&'static Asset> {
    [&*DATASTAR, &*STYLESHEET]
        .into_iter()
        .find(|asset| asset.name == name)
}

/// `GET /static/{name}`.
pub(crate) async fn serve(Path(name): Path<String>) -> Response {
    let Some(asset) = asset_named(&name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut response = asset.bytes.into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(asset.content_type),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    response
}
