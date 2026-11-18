//! A file's type: what its bytes are, found by the type step before anything else looks at the
//! file (PLAN.md decision 25, docs/decisions/0003).
//!
//! **The step.** For a new file the core queues `file_type`, `ace-mod-files`' module, on the
//! parser pool, contained like any parser task, and queues no other task on that file until it has
//! ended (`Orchestrator::queue_eligible`). The core reads none of the bytes itself. A file is typed
//! only where something reads its type: where ace3's `file_type` would have run on it, by the
//! core's rules for that component, so its result shows where ace3's does, or where a module the
//! mode runs on the file declares on the type (`ace_sdk::takes::Reads::file_type`). Elsewhere, as
//! in ace3's YARA-only mode, the file's tasks are queued at once and it has no type. A binary
//! without `file_type` types nothing, and nothing waits.
//!
//! **A type kept from other bytes' step.** The type is the bytes' (`TypeFacts`), kept once per
//! sha256, so a file whose sha256 was typed before, in any root, needs no step: the core reads the
//! kept row by its sha256 in the transaction that adds the file (`kept`), and queues the file's
//! other tasks at once. Two things decide whether the row serves. The file's path must be settled
//! (`tree::choose_analysis_file`), since ace3's result reads the name (`is_office_ext`,
//! `.pdfparser`, JavaScript); the core settles it then where nothing nearer the root could still add
//! a path, the rule a file's first lease applies, and otherwise queues the step, whose lease waits
//! for the path and then ends the step in the core, without a pool (`Api::leased`). And the row must
//! answer what that path asks (`answers`): the JavaScript check, the one fact that isn't the bytes'
//! alone, is made only where the mime type or the name says JavaScript, so a row kept from another
//! name may lack it, and then the step runs and adds it. A failed step keeps no row, so the next
//! root types the bytes again. A row from before migration 0070 lacks seven facts and is no type.
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

use ace_results::types::file_type::{FileTypeAnalysis, TypeFacts, asks_about_javascript};
use ace_results::{ObservableAdditions, YaraMeta};
use serde_json::Value;
use sqlx::PgExecutor;
use uuid::Uuid;

use crate::db::{DbError, Tx};
use crate::tree::{self, ObservableId};

pub use crate::queue::TYPE_STEP;

/// A row of `store.file_types` as `TypeFacts`; `$flag` reads each of the seven columns migration
/// 0070 added, which a row typed before it has NULL.
macro_rules! facts_from_row {
    ($row:expr, $flag:expr) => {
        TypeFacts {
            description: $row.description,
            mime: $row.mime,
            is_ole_file: $row.is_ole_file,
            is_rtf_file: $row.is_rtf_file,
            has_pdf_marker: $row.has_pdf_marker,
            is_pe_file: $row.is_pe_file,
            is_zip_file: $row.is_zip_file,
            is_jar_file: $row.is_jar_file,
            is_x509: $row.is_x509,
            is_lnk_file: $row.is_lnk_file,
            is_email_file: $row.is_email_file,
            is_pcap_file: $flag($row.is_pcap_file),
            has_onenote_header: $flag($row.has_onenote_header),
            is_java_class_file: $flag($row.is_java_class_file),
            has_xml_marker: $flag($row.has_xml_marker),
            is_eps_file: $flag($row.is_eps_file),
            is_encoded_script: $flag($row.is_encoded_script),
            has_har_header: $flag($row.has_har_header),
            javascript: $row.javascript,
        }
    };
}

/// Keeps what the type step found in a file's bytes. The same bytes typed again replace what was
/// kept, but a JavaScript check the new run didn't make keeps the old one's answer.
pub async fn store_facts(tx: &mut Tx<'_>, sha256: &str, facts: &TypeFacts) -> Result<(), DbError> {
    sqlx::query!(
        "INSERT INTO store.file_types AS t
             (sha256, description, mime, is_ole_file, is_rtf_file, has_pdf_marker, is_pe_file,
              is_zip_file, is_jar_file, is_x509, is_lnk_file, is_email_file, is_pcap_file,
              has_onenote_header, is_java_class_file, has_xml_marker, is_eps_file,
              is_encoded_script, has_har_header, javascript)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18,
                 $19, $20)
         ON CONFLICT (sha256) DO UPDATE SET
             description = EXCLUDED.description, mime = EXCLUDED.mime,
             is_ole_file = EXCLUDED.is_ole_file, is_rtf_file = EXCLUDED.is_rtf_file,
             has_pdf_marker = EXCLUDED.has_pdf_marker, is_pe_file = EXCLUDED.is_pe_file,
             is_zip_file = EXCLUDED.is_zip_file, is_jar_file = EXCLUDED.is_jar_file,
             is_x509 = EXCLUDED.is_x509, is_lnk_file = EXCLUDED.is_lnk_file,
             is_email_file = EXCLUDED.is_email_file, is_pcap_file = EXCLUDED.is_pcap_file,
             has_onenote_header = EXCLUDED.has_onenote_header,
             is_java_class_file = EXCLUDED.is_java_class_file,
             has_xml_marker = EXCLUDED.has_xml_marker, is_eps_file = EXCLUDED.is_eps_file,
             is_encoded_script = EXCLUDED.is_encoded_script,
             has_har_header = EXCLUDED.has_har_header,
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
        facts.is_pcap_file,
        facts.has_onenote_header,
        facts.is_java_class_file,
        facts.has_xml_marker,
        facts.is_eps_file,
        facts.is_encoded_script,
        facts.has_har_header,
        facts.javascript,
    )
    .execute(tx.conn())
    .await?;
    Ok(())
}

/// The facts kept for each of these sha256s that has them. A row the type step wrote before
/// migration 0070 lacks seven of them and is left out: its file's type is unknown until it is typed
/// again.
pub async fn facts_of<'e>(
    executor: impl PgExecutor<'e>,
    sha256s: &[String],
) -> Result<BTreeMap<String, TypeFacts>, DbError> {
    let rows = sqlx::query!(
        r#"SELECT sha256, description, mime, is_ole_file, is_rtf_file, has_pdf_marker, is_pe_file,
                  is_zip_file, is_jar_file, is_x509, is_lnk_file, is_email_file,
                  is_pcap_file AS "is_pcap_file!", has_onenote_header AS "has_onenote_header!",
                  is_java_class_file AS "is_java_class_file!",
                  has_xml_marker AS "has_xml_marker!", is_eps_file AS "is_eps_file!",
                  is_encoded_script AS "is_encoded_script!",
                  has_har_header AS "has_har_header!", javascript
           FROM store.file_types
           WHERE sha256 = ANY($1)
             AND is_pcap_file IS NOT NULL AND has_onenote_header IS NOT NULL
             AND is_java_class_file IS NOT NULL AND has_xml_marker IS NOT NULL
             AND is_eps_file IS NOT NULL AND is_encoded_script IS NOT NULL
             AND has_har_header IS NOT NULL"#,
        sha256s,
    )
    .fetch_all(executor)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            (
                row.sha256.clone(),
                facts_from_row!(row, std::convert::identity),
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

/// Whether the facts kept for a file answer everything its analysis path asks of them, so the
/// file needs no type step of its own (PLAN.md decision 25). Every fact is the bytes' alone but
/// the JavaScript check, which the type step makes only where the mime type or the name it typed
/// the file under says JavaScript, as ace3 gates node: kept from a name that didn't, it is
/// unknown, and a path that does needs the step.
pub fn answers(facts: &TypeFacts, path: &str) -> bool {
    facts.javascript.is_some() || !asks_about_javascript(path, &facts.mime)
}

/// The files of `root` among `observables` whose type needs no step of their own: the path each is
/// analyzed under is settled (`tree::choose_analysis_file`), and the type kept for its bytes, from
/// whichever root typed them, answers what that path asks (`answers`). One indexed lookup of
/// `store.file_types` by sha256; the core reads no bytes.
pub async fn kept<'e>(
    executor: impl PgExecutor<'e>,
    root: Uuid,
    observables: &[ObservableId],
) -> Result<BTreeMap<ObservableId, Typed>, DbError> {
    let ids: Vec<i64> = observables.iter().map(|id| id.0).collect();
    let rows = sqlx::query!(
        r#"SELECT DISTINCT ON (o.id) o.id AS "id: ObservableId", f.path,
                  t.description, t.mime, t.is_ole_file, t.is_rtf_file, t.has_pdf_marker,
                  t.is_pe_file, t.is_zip_file, t.is_jar_file, t.is_x509, t.is_lnk_file,
                  t.is_email_file, t.is_pcap_file AS "is_pcap_file!",
                  t.has_onenote_header AS "has_onenote_header!",
                  t.is_java_class_file AS "is_java_class_file!",
                  t.has_xml_marker AS "has_xml_marker!", t.is_eps_file AS "is_eps_file!",
                  t.is_encoded_script AS "is_encoded_script!",
                  t.has_har_header AS "has_har_header!", t.javascript
           FROM analysis.observables o
           JOIN analysis.files f
                ON f.root_id = o.root_id AND f.observable_id = o.id AND f.analyzed
           JOIN store.file_types t ON t.sha256 = o.value
           WHERE o.root_id = $1 AND o.id = ANY($2) AND o.type = 'file'
             AND t.is_pcap_file IS NOT NULL AND t.has_onenote_header IS NOT NULL
             AND t.is_java_class_file IS NOT NULL AND t.has_xml_marker IS NOT NULL
             AND t.is_eps_file IS NOT NULL AND t.is_encoded_script IS NOT NULL
             AND t.has_har_header IS NOT NULL
           ORDER BY o.id, f.path COLLATE "C""#,
        root,
        &ids,
    )
    .fetch_all(executor)
    .await?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let typed = Typed {
                path: row.path.clone(),
                facts: facts_from_row!(row, std::convert::identity),
            };
            (row.id, typed)
        })
        .filter(|(_, typed)| answers(&typed.facts, &typed.path))
        .collect())
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
                  t.is_email_file, t.is_pcap_file, t.has_onenote_header, t.is_java_class_file,
                  t.has_xml_marker, t.is_eps_file, t.is_encoded_script, t.has_har_header,
                  t.javascript
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
                    path: row.path.clone(),
                    // ace3's result reads none of the flags migration 0070 added
                    facts: facts_from_row!(row, |flag: Option<bool>| flag.unwrap_or(false)),
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
