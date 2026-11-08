//! A list's exports (PLAN.md 5.10), ace3's `aceapi_v2/common/listing.py` exports: every row a list's
//! filters match, in its order, streamed in one response as CSV or NDJSON, paging through the same service
//! function as the list. Everything that can be refused is refused before the first byte: the filters, the
//! permission, and a list past the site's bound (`WebConfig::max_export_rows`, `MAX_EXPORT_ROWS` by
//! default), which is 413 and asks for a narrower filter. The stream
//! stops at that bound too, so rows that arrive while it runs can't push it past. A page that fails after
//! the first can't change the status already sent: NDJSON then ends with an `{"error": ...}` line and CSV
//! ends where it was, as ace3's do, and the failure is logged.
//!
//! A CSV cell is text that came from an alert, a module or an analyst, and a spreadsheet runs a cell that
//! starts with `=`, `+`, `-` or `@` as a formula, and some a tab or a carriage return before one. So such a
//! cell gets a leading `'`, OWASP's advice for CSV injection, and every cell is quoted as RFC 4180 says when
//! it holds a comma, a quote or a line break. ace3's CSV doesn't guard its cells.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use ace_service::ServiceError;
use axum::body::{Body, Bytes};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use futures_util::stream;
use serde::Serialize;

use crate::error::ApiError;

/// The most rows one export holds, by default.
pub const MAX_EXPORT_ROWS: i64 = 100_000;
/// The rows an export reads at a time.
pub(crate) const EXPORT_PAGE: u32 = 1000;

/// An export's format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Format {
    Csv,
    Ndjson,
}

/// A row an export writes: its JSON for NDJSON, and its cells for CSV.
pub(crate) trait ExportRow: Serialize + Send + 'static {
    const HEADER: &'static [&'static str];
    fn cells(&self) -> Vec<String>;
}

/// The next page: its rows and where the one after starts, None after the last.
pub(crate) type Page<R, C> = (Vec<R>, Option<C>);
type Fetch<R, C> = Arc<
    dyn Fn(C) -> Pin<Box<dyn Future<Output = Result<Page<R, C>, ServiceError>> + Send>>
        + Send
        + Sync,
>;

/// A cell as a spreadsheet reads it safely: a formula's first character behind a `'`, and quoted when it
/// holds a comma, a quote or a line break.
pub(crate) fn csv_cell(text: &str) -> String {
    let guarded = if text.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{text}")
    } else {
        text.to_owned()
    };
    if guarded.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

fn csv_line(cells: &[String]) -> String {
    let mut line = cells
        .iter()
        .map(|cell| csv_cell(cell))
        .collect::<Vec<_>>()
        .join(",");
    line.push_str("\r\n");
    line
}

fn encode<R: ExportRow>(format: Format, rows: &[R]) -> String {
    let mut out = String::new();
    for row in rows {
        match format {
            Format::Csv => out.push_str(&csv_line(&row.cells())),
            Format::Ndjson => {
                out.push_str(&serde_json::to_string(row).expect("a row is JSON"));
                out.push('\n');
            }
        }
    }
    out
}

struct Exporting<R, C> {
    format: Format,
    /// The page read but not yet sent.
    rows: Option<Vec<R>>,
    next: Option<C>,
    fetch: Fetch<R, C>,
    sent: i64,
    max: i64,
    header: bool,
}

impl<R: ExportRow, C: Send + 'static> Exporting<R, C> {
    async fn step(mut self) -> Option<(Result<Bytes, std::io::Error>, Self)> {
        let mut chunk = String::new();
        if !self.header {
            self.header = true;
            if self.format == Format::Csv {
                let header: Vec<String> = R::HEADER.iter().map(|name| (*name).to_owned()).collect();
                chunk.push_str(&csv_line(&header));
            }
        }
        let rows = match self.rows.take() {
            Some(rows) => rows,
            None => {
                let next = self.next.take()?;
                if self.sent >= self.max {
                    tracing::warn!("an export stopped at its bound of {} rows", self.max);
                    return None;
                }
                match (self.fetch)(next).await {
                    Ok((rows, next)) => {
                        self.next = next;
                        rows
                    }
                    Err(error) => {
                        tracing::error!("an export failed part-way: {error}");
                        if self.format == Format::Ndjson {
                            let line = serde_json::json!({"error": "the export failed part-way"});
                            return Some((Ok(Bytes::from(format!("{line}\n"))), self));
                        }
                        return None;
                    }
                }
            }
        };
        let room = usize::try_from(self.max - self.sent).unwrap_or(0);
        let rows = &rows[..rows.len().min(room)];
        self.sent += i64::try_from(rows.len()).unwrap_or(i64::MAX);
        chunk.push_str(&encode(self.format, rows));
        Some((Ok(Bytes::from(chunk)), self))
    }
}

/// The response that streams `first` and then each page `fetch` reads from its cursor, to the end. `total`
/// is how many rows the list has, which is refused past `max`.
pub(crate) fn respond<R, C, F, Fut>(
    format: Format,
    name: &str,
    max: i64,
    total: i64,
    first: Page<R, C>,
    fetch: F,
) -> Result<Response, ApiError>
where
    R: ExportRow,
    C: Send + 'static,
    F: Fn(C) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Page<R, C>, ServiceError>> + Send + 'static,
{
    if total > max {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "an export holds at most {max} rows, and this one has more: narrow its filters"
            ),
        ));
    }
    let fetch: Fetch<R, C> = Arc::new(move |cursor| Box::pin(fetch(cursor)));
    let (rows, next) = first;
    let state = Exporting {
        format,
        rows: Some(rows),
        next,
        fetch,
        sent: 0,
        max,
        header: false,
    };
    let (content_type, extension) = match format {
        Format::Csv => ("text/csv; charset=utf-8", "csv"),
        Format::Ndjson => ("application/x-ndjson", "ndjson"),
    };
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type.to_owned()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{name}.{extension}\""),
            ),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff".to_owned()),
            (header::CACHE_CONTROL, "private, no-store".to_owned()),
        ],
        Body::from_stream(stream::unfold(state, Exporting::step)),
    )
        .into_response())
}

/// A time as a cell: RFC 3339, or empty.
pub(crate) fn time_cell(time: Option<chrono::DateTime<chrono::Utc>>) -> String {
    time.map(|time| time.to_rfc3339()).unwrap_or_default()
}
