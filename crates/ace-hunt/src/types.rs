//! Hunt types: what a hunt's `type` adds to the model, and what its hunt class checks at load.
//!
//! In ace3 a hunt type is a `hunt_type_<name>` config section naming a Python class
//! (`saq/configuration/schema.py`, `HuntTypeConfig`), and an integration adds its own. Here a type
//! is a [`HuntType`], and a site adds its own through `ace_app::App::hunt_type` (2.31). ace3's
//! open-source configuration has one, Splunk (`etc/saq.splunk.default.yaml`); a site's integrations
//! add LogScale (`ace_endpoint_vendor`), Rapid7 (`ace_rapid7`) and MailFilter (`site_ace`, not schedulable,
//! so its hunts never load from a directory). The signatures repository has hunts for the first
//! three, so their types are here, ported from a site's `logscale_hunter.py` and
//! `rapid7_hunter.py`; they move to a site's workspace if 7.8 wants them there. MailFilter comes
//! with a site's port.
//!
//! What a type's class does at load beyond validating is the type's [`HuntType::on_load`]: Splunk
//! looks up the Splunk instance a hunt names. What it needs a client or credentials for, such as
//! Rapid7 resolving `log_names` to log ids, is 6.4's, with the query.

use serde_json::{Map as JsonMap, Value as Json};

use crate::HuntError;
use crate::model::{HuntConfig, all};
use crate::validate::{Errors, Obj, opt_string, string, string_list};

/// A hunt type.
pub trait HuntType: Send + Sync {
    /// The name hunts give in `type`, such as `splunk`.
    fn name(&self) -> &str;

    /// The name of ace3's pydantic model for the type's hunts, such as `SplunkHuntConfig`, which
    /// its validation errors carry.
    fn model(&self) -> &str;

    /// What `auto_append` is when a hunt leaves it out.
    fn auto_append(&self) -> &str {
        ""
    }

    /// Validates the type's own fields, which come after the shared ones.
    fn settings(
        &self,
        o: &mut Obj<'_>,
        errs: &mut Errors,
    ) -> Result<Option<JsonMap<String, Json>>, HuntError> {
        let _ = (o, errs);
        Ok(Some(JsonMap::new()))
    }

    /// The type's own check of a hunt whose fields are valid, after the shared ones: an Err is
    /// the model's `value_error`.
    fn check(&self, config: &HuntConfig) -> Result<(), String> {
        let _ = config;
        Ok(())
    }

    /// What the type's hunt class checks when a hunt of the type is made, outside its files.
    fn on_load(&self, config: &HuntConfig) -> Result<(), HuntError> {
        let _ = config;
        Ok(())
    }
}

/// Splunk hunts: `SplunkHuntConfig` and `SplunkHunt` (`saq/collectors/hunter/splunk_hunter.py`).
#[derive(Debug, Clone, Default)]
pub struct Splunk {
    /// The Splunk instances a hunt may name in `splunk_config`, which SplunkHunt looks up when
    /// it's made and fails without (`splunk config for NAME not found`). None checks nothing.
    pub instances: Option<Vec<String>>,
}

impl HuntType for Splunk {
    fn name(&self) -> &str {
        "splunk"
    }

    fn model(&self) -> &str {
        "SplunkHuntConfig"
    }

    /// Splunk returns every field only with `| fields *`.
    fn auto_append(&self) -> &str {
        "| fields *"
    }

    fn settings(
        &self,
        o: &mut Obj<'_>,
        errs: &mut Errors,
    ) -> Result<Option<JsonMap<String, Json>>, HuntError> {
        let splunk_config = o.default(errs, "splunk_config", "default".to_owned(), string)?;
        let user = o.default(errs, "splunk_user_context", None, opt_string)?;
        let app = o.default(errs, "splunk_app_context", None, opt_string)?;
        Ok(
            all!(splunk_config, user, app).map(|(splunk_config, user, app)| {
                JsonMap::from_iter([
                    ("splunk_config".to_owned(), Json::String(splunk_config)),
                    (
                        "splunk_user_context".to_owned(),
                        user.map_or(Json::Null, Json::String),
                    ),
                    (
                        "splunk_app_context".to_owned(),
                        app.map_or(Json::Null, Json::String),
                    ),
                ])
            }),
        )
    }

    fn on_load(&self, config: &HuntConfig) -> Result<(), HuntError> {
        let name = config
            .settings
            .get("splunk_config")
            .and_then(Json::as_str)
            .unwrap_or("default");
        match &self.instances {
            Some(instances) if !instances.iter().any(|i| i == name) => Err(HuntError::python(
                "ValueError",
                format!("splunk config for {name} not found"),
            )),
            _ => Ok(()),
        }
    }
}

/// LogScale hunts: a site's `LogscaleHuntConfig` (`ace_endpoint_vendor`).
#[derive(Debug, Clone, Default)]
pub struct Logscale;

impl HuntType for Logscale {
    fn name(&self) -> &str {
        "logscale"
    }

    fn model(&self) -> &str {
        "LogscaleHuntConfig"
    }

    fn settings(
        &self,
        o: &mut Obj<'_>,
        errs: &mut Errors,
    ) -> Result<Option<JsonMap<String, Json>>, HuntError> {
        Ok(o.required(errs, "repository", string)?.map(|repository| {
            JsonMap::from_iter([("repository".to_owned(), Json::String(repository))])
        }))
    }
}

/// Rapid7 hunts: a site's `Rapid7HuntConfig` (`ace_rapid7`).
#[derive(Debug, Clone, Default)]
pub struct Rapid7;

impl HuntType for Rapid7 {
    fn name(&self) -> &str {
        "rapid7"
    }

    fn model(&self) -> &str {
        "Rapid7HuntConfig"
    }

    fn settings(
        &self,
        o: &mut Obj<'_>,
        errs: &mut Errors,
    ) -> Result<Option<JsonMap<String, Json>>, HuntError> {
        Ok(o.required(errs, "log_names", string_list)?.map(|names| {
            JsonMap::from_iter([(
                "log_names".to_owned(),
                Json::Array(names.into_iter().map(Json::String).collect()),
            )])
        }))
    }

    fn check(&self, config: &HuntConfig) -> Result<(), String> {
        if config.use_index_time {
            Ok(())
        } else {
            Err(
                "use_index_time must be True for Rapid7 hunts. The Rapid7 Log Search API's \
                 from/to parameters filter by ingestion time, and LEQL does not support range \
                 filtering on event timestamps."
                    .to_owned(),
            )
        }
    }
}
