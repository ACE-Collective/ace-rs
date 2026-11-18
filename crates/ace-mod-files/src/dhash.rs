//! `dhash`: ace3's `DHashImageAnalyzer` (`saq/modules/dhash.py`), on `ace-dhash`, which decodes,
//! converts and resizes an image as Pillow 13 does.
//!
//! For an image with the `dhash` directive, the 16x16 difference hash, compared with each `.png`
//! in the analysts' dhash directory: a score per reference image, and a detection when the score
//! reaches the threshold in the image's `.score` file.
//!
//! Where ace4 departs:
//!
//! - ace3 reads `<analyst_data_dir>/dhash` on each run. A contained task can't open it, so the
//!   module reads the directory once when it starts (`source_dir`), hashes each reference image
//!   then, and a site that changes the images restarts the pool. With no `source_dir` the module
//!   skips every image, as ace3 does when the directory is missing.
//! - ace3 scores the images in `os.listdir`'s order, which is the filesystem's; here they're in
//!   name order.
//! - A threshold is the `.score` file's text as a float, trimmed; Python's `float()` also takes
//!   `_` between digits.

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use ace_results::types::dhash::{DHashImageAnalysis, DHashScore};
use ace_results::{AnalysisType, Detection, ObservableKind, ResultEnvelope};
use ace_sdk::takes::{Condition, Takes};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, Resources, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<DHashImageAnalyzer>();

/// `DIRECTIVE_DHASH`.
pub const DIRECTIVE_DHASH: &str = "dhash";
/// ace3's built-in `DHASH_IMAGE_MATCH` signature.
pub const DHASH_IMAGE_MATCH: &str = "10d1e320-3b07-45f1-9bcf-078044643b7e";

/// The module's settings.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct DHashSettings {
    /// The analysts' dhash directory, ace3's `<analyst_data_dir>/dhash`: reference `.png`
    /// images, each with a `<name>.png.score` file holding its threshold in percent.
    pub source_dir: Option<PathBuf>,
}

/// A reference image, hashed.
#[derive(Debug, Clone)]
struct Reference {
    name: String,
    hash: ace_dhash::ImageHash,
    threshold: f64,
}

pub struct DHashImageAnalyzer {
    /// None when there's no directory, as ace3 finds none.
    references: Option<Vec<Reference>>,
}

/// The reference images of a directory, as ace3 takes them: `.png` names that open as images
/// and have a threshold that reads and a hash that computes. The others are left out, as ace3
/// logs and skips them.
fn references(dir: &std::path::Path) -> Option<Vec<Reference>> {
    let entries = fs::read_dir(dir).ok()?;
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|name| name.ends_with(".png"))
        .collect();
    names.sort();
    let mut out = Vec::new();
    for name in names {
        let Ok(data) = fs::read(dir.join(&name)) else {
            continue;
        };
        if !ace_dhash::is_image(&data) {
            tracing::debug!("skipping non image file {name}");
            continue;
        }
        let threshold = match fs::read_to_string(dir.join(format!("{name}.score")))
            .ok()
            .and_then(|text| text.trim().parse::<f64>().ok())
        {
            Some(threshold) => threshold,
            None => {
                tracing::warn!("unable to load score threshold for {name}");
                continue;
            }
        };
        match ace_dhash::image_hash(&data) {
            Ok(hash) => out.push(Reference {
                name,
                hash,
                threshold,
            }),
            Err(e) => tracing::warn!("unable to hash dhash source image {name}: {e}"),
        }
    }
    Some(out)
}

impl Module for DHashImageAnalyzer {
    const NAME: &'static str = DHashImageAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::File];
    const REQUIRED_DIRECTIVES: &'static [&'static str] = &[DIRECTIVE_DHASH];
    // ace3 has no limit of its own. A decoded image at Pillow's bomb limit is about 179 MB, with up
    // to 6 bytes a pixel more for a progressive JPEG's coefficients (crates/ace-dhash).
    const RESOURCES: Resources = Resources {
        timeout: Duration::from_secs(300),
        memory_mb: 2048,
        cpu_seconds: 300,
    };
    type Output = DHashImageAnalysis;
    type Settings = DHashSettings;

    fn init(settings: &DHashSettings) -> Result<Self, ModuleError> {
        Ok(DHashImageAnalyzer {
            references: settings
                .source_dir
                .as_deref()
                .filter(|dir| dir.is_dir())
                .and_then(references),
        })
    }

    fn takes(_: &DHashSettings) -> Takes {
        Takes::everything().and(Condition::not_empty(), "an empty file")
    }
}

/// `generate_summary`.
fn summary(scores: &[DHashScore]) -> Option<String> {
    if scores.is_empty() {
        return None;
    }
    let items: Vec<String> = scores
        .iter()
        .map(|s| {
            format!(
                "{} {}% of {}%",
                s.image_file,
                ace_dhash::format_percent(s.score),
                ace_dhash::format_percent(s.threshold)
            )
        })
        .collect();
    let mut list = items[..items.len().min(20)].join(", ");
    if items.len() > 20 {
        list.push_str(&format!(" + {} more", items.len() - 20));
    }
    Some(format!("DHash Image Analysis: {list}"))
}

impl Parser for DHashImageAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<DHashSettings>,
    ) -> Result<Outcome<DHashImageAnalysis>, ModuleError> {
        let file = ctx.input_file()?;
        let data = fs::read(&file.local_path)?;
        if !ace_dhash::is_image(&data) {
            return Ok(Outcome::Skipped("not an image".to_owned()));
        }
        let Some(references) = &self.references else {
            return Ok(Outcome::Skipped("no dhash source directory".to_owned()));
        };
        ctx.check_cancelled()?;
        let hash = match ace_dhash::image_hash(&data) {
            Ok(hash) => hash,
            // a truncated or corrupt image still opens, which reads only the header
            Err(e) => return Ok(Outcome::Skipped(format!("unable to hash the image: {e}"))),
        };
        let mut scores = Vec::new();
        let mut detections = Vec::new();
        for reference in references {
            let score = ace_dhash::percent_similar(hash.bits_different(&reference.hash));
            if score >= reference.threshold {
                detections.push(
                    Detection::new(format!(
                        "matches {} {}% (threshold {}%)",
                        reference.name,
                        ace_dhash::format_percent(score),
                        ace_dhash::format_percent(reference.threshold)
                    ))
                    .with_signature(DHASH_IMAGE_MATCH),
                );
            }
            scores.push(DHashScore {
                image_file: reference.name.clone(),
                score,
                threshold: reference.threshold,
            });
        }
        let mut result = ResultEnvelope::new(DHashImageAnalysis { scores });
        result.summary = summary(&result.details.scores);
        result.analyzed.detections = detections;
        Ok(Outcome::Done(result))
    }
}
