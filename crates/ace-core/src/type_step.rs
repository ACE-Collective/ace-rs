//! A file's type: what its bytes are, found by the type step before anything else looks at the
//! file (PLAN.md decision 25, docs/decisions/0003).
//!
//! **The step.** For every new file the core queues `file_type`, `ace-mod-files`' module, on the
//! parser pool, contained like any parser task, and queues no other task on that file until it has
//! ended (`Orchestrator::queue_eligible`). The core reads none of the bytes itself. A file is typed
//! when any module the root's mode runs would be eligible for it by the core's own rules, so a
//! whitelisted file or one no module looks at isn't. A binary without `file_type` types nothing,
//! and nothing waits.
//!
//! **Its end.** The step's output is the file's `TypeFacts`, kept once per sha256 in
//! `store.file_types` (`store_facts`), not a result in the tree. However the step ends, with facts,
//! failed in the module, at its deadline or with its lease run out on its last attempt
//! (`queue::TypeStepEnded`), the file's other tasks are then queued in the same transaction. A file
//! whose step failed has no type, unless the same bytes were typed in another root: a declaration's
//! condition on its type is unknown and holds (`ace_sdk::takes::Condition::value`), so a failure
//! never keeps a module off a file it would have run on.
//!
//! **ace3's result.** ace3's `file_type` module wrote a `file_type_analysis` result on each file
//! its mode ran it on, and gave the file tags and `yara_meta` types. Where ace3's module would have
//! run, by the core's rules for the `file_type` component (the mode runs it, nothing excludes it),
//! the core gives the file those tags and types, built from the facts and the file's analysis path,
//! and marks it (`analysis.observables.type_result`). What still reads ace3's result gets one built
//! the same way (`results_of`): the modules ace3 makes depend on `file_type`, the declarations that
//! read it, the hooks' tree conditions and the comparison's normal form.

use std::collections::BTreeMap;

use ace_results::types::file_type::{FileTypeAnalysis, TypeFacts};
use ace_results::{ObservableAdditions, YaraMeta};
use serde_json::Value;
use sqlx::PgExecutor;
use uuid::Uuid;

use crate::db::{DbError, Tx};
use crate::tree::{self, ObservableId};

pub use crate::queue::TYPE_STEP;

/// Keeps what the type step found in a file's bytes. The same bytes typed again replace what was
/// kept, but a JavaScript check the new run didn't make keeps the old one's answer.
pub async fn store_facts(tx: &mut Tx<'_>, sha256: &str, facts: &TypeFacts) -> Result<(), DbError> {
    sqlx::query!(
        "INSERT INTO store.file_types AS t
             (sha256, description, mime, is_ole_file, is_rtf_file, has_pdf_marker, is_pe_file,
              is_zip_file, is_jar_file, is_x509, is_lnk_file, is_email_file, javascript)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
         ON CONFLICT (sha256) DO UPDATE SET
             description = EXCLUDED.description, mime = EXCLUDED.mime,
             is_ole_file = EXCLUDED.is_ole_file, is_rtf_file = EXCLUDED.is_rtf_file,
             has_pdf_marker = EXCLUDED.has_pdf_marker, is_pe_file = EXCLUDED.is_pe_file,
             is_zip_file = EXCLUDED.is_zip_file, is_jar_file = EXCLUDED.is_jar_file,
             is_x509 = EXCLUDED.is_x509, is_lnk_file = EXCLUDED.is_lnk_file,
             is_email_file = EXCLUDED.is_email_file,
             javascript = COALESCE(EXCLUDED.javascript, t.javascript),
             typed_at = now()",
        sha256,
        facts.description,
        facts.mime,
        facts.is_ole_file,
        facts.is_rtf_file,
        facts.has_pdf_marker,
        facts.is_pe_file,
        facts.is_zip_file,
        facts.is_jar_file,
        facts.is_x509,
        facts.is_lnk_file,
        facts.is_email_file,
        facts.javascript,
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// The facts kept for each of these sha256s that has them.
pub async fn facts_of<'e>(
    executor: impl PgExecutor<'e>,
    sha256s: &[String],
) -> Result<BTreeMap<String, TypeFacts>, DbError> {
    let rows = sqlx::query!(
        "SELECT sha256, description, mime, is_ole_file, is_rtf_file, has_pdf_marker, is_pe_file,
                is_zip_file, is_jar_file, is_x509, is_lnk_file, is_email_file, javascript
         FROM store.file_types WHERE sha256 = ANY($1)",
        sha256s,
    )
    .fetch_all(executor)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            (
                row.sha256,
                TypeFacts {
                    description: row.description,
                    mime: row.mime,
                    is_ole_file: row.is_ole_file,
                    is_rtf_file: row.is_rtf_file,
                    has_pdf_marker: row.has_pdf_marker,
                    is_pe_file: row.is_pe_file,
                    is_zip_file: row.is_zip_file,
                    is_jar_file: row.is_jar_file,
                    is_x509: row.is_x509,
                    is_lnk_file: row.is_lnk_file,
                    is_email_file: row.is_email_file,
                    javascript: row.javascript,
                },
            )
        })
        .collect())
}

/// The facts kept for one sha256.
pub async fn facts_for<'e>(
    executor: impl PgExecutor<'e>,
    sha256: &str,
) -> Result<Option<TypeFacts>, DbError> {
    Ok(facts_of(executor, &[sha256.to_owned()])
        .await?
        .remove(sha256))
}

/// A file ace3's `file_type` would have analyzed: its facts and its analysis path.
#[derive(Debug, Clone)]
pub struct Typed {
    pub path: String,
    pub facts: TypeFacts,
}

impl Typed {
    /// ace3's `file_type_analysis` details for it.
    pub fn details(&self) -> Value {
        serde_json::to_value(FileTypeAnalysis::from_facts(&self.facts, &self.path))
            .unwrap_or(Value::Null)
    }

    /// ace3's summary of that result.
    pub fn summary(&self) -> String {
        FileTypeAnalysis::from_facts(&self.facts, &self.path).summary()
    }
}

/// The files of `root` (of `observables`, or all) that show ace3's file_type result, with what
/// builds it: each one's facts and analysis path.
pub async fn results_of<'e>(
    executor: impl PgExecutor<'e>,
    root: Uuid,
    observables: Option<&[ObservableId]>,
) -> Result<BTreeMap<ObservableId, Typed>, DbError> {
    let only: Option<Vec<i64>> = observables.map(|ids| ids.iter().map(|id| id.0).collect());
    let rows = sqlx::query!(
        r#"SELECT o.id AS "id: ObservableId", f.path AS "path!",
                  t.description, t.mime, t.is_ole_file, t.is_rtf_file, t.has_pdf_marker,
                  t.is_pe_file, t.is_zip_file, t.is_jar_file, t.is_x509, t.is_lnk_file,
                  t.is_email_file, t.javascript
           FROM analysis.observables o
           JOIN store.file_types t ON t.sha256 = o.value
           JOIN LATERAL (
               SELECT path FROM analysis.files
               WHERE root_id = o.root_id AND observable_id = o.id
               ORDER BY analyzed DESC, depth, path COLLATE "C" LIMIT 1
           ) f ON true
           WHERE o.root_id = $1 AND o.type = 'file' AND o.type_result
             AND ($2::bigint[] IS NULL OR o.id = ANY($2))"#,
        root,
        only.as_deref(),
    )
    .fetch_all(executor)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            (
                row.id,
                Typed {
                    path: row.path,
                    facts: TypeFacts {
                        description: row.description,
                        mime: row.mime,
                        is_ole_file: row.is_ole_file,
                        is_rtf_file: row.is_rtf_file,
                        has_pdf_marker: row.has_pdf_marker,
                        is_pe_file: row.is_pe_file,
                        is_zip_file: row.is_zip_file,
                        is_jar_file: row.is_jar_file,
                        is_x509: row.is_x509,
                        is_lnk_file: row.is_lnk_file,
                        is_email_file: row.is_email_file,
                        javascript: row.javascript,
                    },
                },
            )
        })
        .collect())
}

/// Gives a file what ace3's file_type gave it, the tags and `yara_meta` types built from its facts
/// and its analysis path, and marks it as showing that result.
pub async fn show(
    tx: &mut Tx<'_>,
    root: Uuid,
    observable: ObservableId,
    path: &str,
    facts: &TypeFacts,
) -> Result<(), DbError> {
    let (tags, types) = facts.view(path);
    let additions = ObservableAdditions {
        tags: tags.into_iter().map(str::to_owned).collect(),
        yara_meta: types
            .into_iter()
            .filter_map(|kind| YaraMeta::new("type", kind).ok())
            .collect(),
        ..ObservableAdditions::default()
    };
    tree::add_to_observable(tx, root, observable, &additions).await?;
    sqlx::query!(
        "UPDATE analysis.observables SET type_result = true WHERE root_id = $1 AND id = $2",
        root,
        observable as ObservableId,
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}
