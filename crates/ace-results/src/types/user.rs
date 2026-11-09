//! `user_analysis`: a user's directory entry (ace3's `UserAnalysis`, `saq/modules/user.py`).
//! `ace-mod-user` writes it (PLAN.md 7.4).

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

use crate::envelope::AnalysisType;

/// The details of a `user_analysis` result: the entry's attributes as ace3's ldap3 formats them
/// by the server's schema and its JSON encoder writes them, with ace3's own keys added
/// (`manager_cn`, `on_prem`, `primary_email`, `entitlements`), and the manager's entry.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UserAnalysis {
    /// The user's attributes, by the names the server gave them.
    pub ldap: Option<Map<String, Value>>,
    /// The manager's attributes: absent when the user has no manager, null when the manager
    /// wasn't found.
    #[serde(
        default,
        deserialize_with = "present",
        skip_serializing_if = "Option::is_none"
    )]
    pub manager_ldap: Option<Option<Map<String, Value>>>,
}

/// A field that's there, as `Some`, even when it's null.
fn present<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Option<Map<String, Value>>>, D::Error> {
    Option::<Map<String, Value>>::deserialize(deserializer).map(Some)
}

impl AnalysisType for UserAnalysis {
    const NAME: &'static str = "user_analysis";
    const VERSION: u32 = 1;
    const MODULE: &'static str = "user_analyzer";
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_manager_not_found_is_null_and_no_manager_is_absent() {
        for details in [
            json!({"ldap": {"cn": "a"}, "manager_ldap": null}),
            json!({"ldap": {"cn": "a"}, "manager_ldap": {"cn": "b"}}),
            json!({"ldap": {"cn": "a"}}),
        ] {
            let read: UserAnalysis = serde_json::from_value(details.clone()).expect("reads");
            assert_eq!(serde_json::to_value(&read).expect("writes"), details);
        }
        assert!(serde_json::from_value::<UserAnalysis>(json!({"ldap": {}, "x": 1})).is_err());
    }
}
