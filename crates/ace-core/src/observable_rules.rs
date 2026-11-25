//! ace3's observable classes' rules (`ace_sdk::observable_rules`) over what lands in a root: the
//! observables a module's result adds (`Orchestrator::apply_result`, a task's end and a cache hit
//! alike) and a submission's (`submit::create`). ace3 builds every observable through its type's
//! class, a module's `add_observable_by_spec`, its API's submission and its hunter alike, so a
//! value the class refuses never reaches a root and one it changes is kept changed.
//!
//! A refused observable is left out with what of the result refers to it: the relationships to it,
//! a redirection to it and the additions to it (`ResultEnvelope::others`), as ace3's module gets
//! None for it and has nothing to relate, redirect to or add to. A reference to a changed one is
//! changed with it. The rest of the result lands.

use std::borrow::Cow;
use std::collections::BTreeMap;

use ace_results::{NewObservable, ObservableKind, ObservableRef, Relationship, ResultEnvelope};
use serde_json::Value;
use uuid::Uuid;

/// What the rules did to a set of observables: each one changed, with its new value, or refused
/// (None). One kept as it was isn't here.
#[derive(Debug, Default)]
pub struct Rewrites(BTreeMap<ObservableRef, Option<String>>);

impl Rewrites {
    /// Runs the rules over `observables`, calling `refused` with each one they refuse and why.
    pub fn of<'a>(
        observables: impl IntoIterator<Item = (ObservableKind, &'a str)>,
        mut refused: impl FnMut(ObservableKind, &str, &str),
    ) -> Self {
        let mut rewrites = BTreeMap::new();
        for (kind, value) in observables {
            match ace_sdk::observable_rules::value(kind, value) {
                Ok(kept) if kept == value => {}
                Ok(kept) => {
                    rewrites.insert(ObservableRef::new(kind, value), Some(kept.into_owned()));
                }
                Err(why) => {
                    refused(kind, value, why);
                    rewrites.insert(ObservableRef::new(kind, value), None);
                }
            }
        }
        Rewrites(rewrites)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The value kept of `kind`'s `value`, or None where it was refused.
    pub fn kept(&self, kind: ObservableKind, value: &str) -> Option<String> {
        match self.0.get(&ObservableRef::new(kind, value)) {
            Some(kept) => kept.clone(),
            None => Some(value.to_owned()),
        }
    }

    /// Changes a reference to a changed observable; false for one to a refused observable.
    fn reference(&self, reference: &mut ObservableRef) -> bool {
        match self.0.get(reference) {
            None => true,
            Some(Some(kept)) => {
                reference.value.clone_from(kept);
                true
            }
            Some(None) => false,
        }
    }

    fn relationships(&self, relationships: &mut Vec<Relationship>) {
        relationships.retain_mut(|r| self.reference(&mut r.target));
    }

    fn redirection(&self, redirection: &mut Option<ObservableRef>) {
        if redirection.as_mut().is_some_and(|r| !self.reference(r)) {
            *redirection = None;
        }
    }

    /// `observable` as the rules keep it, its references included; false where it was refused.
    pub fn observable(&self, observable: &mut NewObservable) -> bool {
        let Some(value) = self.kept(observable.kind, &observable.value) else {
            return false;
        };
        observable.value = value;
        self.relationships(&mut observable.relationships);
        self.redirection(&mut observable.redirection);
        true
    }
}

/// `result` as the rules keep it: borrowed where they keep every observable it adds as it is.
/// Each refused observable is logged at DEBUG, as ace3's `create_observable` logs it: a module
/// adds what its input holds, such as a certificate's common name as an fqdn, and relies on the
/// refusal, so it is no failure.
pub fn apply_to_result<'a>(
    root: Uuid,
    module: &str,
    result: &'a ResultEnvelope<Value>,
) -> Cow<'a, ResultEnvelope<Value>> {
    let rewrites = Rewrites::of(
        result
            .observables
            .iter()
            .map(|o| (o.kind, o.value.as_str())),
        |kind, value, why| {
            tracing::debug!(
                %root, %module, observable_type = %kind, observable_value = value,
                "the observable isn't added: {why}"
            );
        },
    );
    if rewrites.is_empty() {
        return Cow::Borrowed(result);
    }
    let mut result = result.clone();
    result
        .observables
        .retain_mut(|observable| rewrites.observable(observable));
    for file in &mut result.files {
        rewrites.relationships(&mut file.relationships);
        rewrites.redirection(&mut file.redirection);
    }
    rewrites.relationships(&mut result.analyzed.relationships);
    rewrites.relationships(&mut result.redirected.relationships);
    result.others.retain_mut(|other| {
        rewrites.relationships(&mut other.additions.relationships);
        rewrites.reference(&mut other.observable)
    });
    Cow::Owned(result)
}

#[cfg(test)]
mod tests {
    use ace_results::{OtherAdditions, RelationshipKind};

    use super::*;

    fn envelope() -> ResultEnvelope<Value> {
        serde_json::from_value(
            serde_json::json!({"analysis_type": "x509", "schema_version": 1, "details": {}}),
        )
        .expect("an envelope")
    }

    fn fqdn(value: &str) -> ObservableRef {
        ObservableRef::new(ObservableKind::Fqdn, value)
    }

    #[test]
    fn a_refused_observable_goes_with_what_refers_to_it_and_a_changed_one_is_followed() {
        let mut result = envelope();
        let mut good = NewObservable::new(ObservableKind::Fqdn, "example.com");
        good.relationships = vec![
            Relationship::new(RelationshipKind::RelatedTo, fqdn("GTS Root R1")),
            Relationship::new(RelationshipKind::RelatedTo, fqdn(" a@b ")),
            Relationship::new(
                RelationshipKind::RelatedTo,
                ObservableRef::new(ObservableKind::Hostname, " HOST "),
            ),
        ];
        good.redirection = Some(fqdn("GTS Root R1"));
        result.observables = vec![
            good,
            NewObservable::new(ObservableKind::Fqdn, "GTS Root R1"),
            NewObservable::new(ObservableKind::Hostname, " HOST "),
        ];
        result.analyzed.relationships = vec![Relationship::new(
            RelationshipKind::RelatedTo,
            fqdn("GTS Root R1"),
        )];
        result.others = vec![
            OtherAdditions {
                observable: fqdn("GTS Root R1"),
                additions: Default::default(),
            },
            OtherAdditions {
                observable: ObservableRef::new(ObservableKind::Hostname, " HOST "),
                additions: Default::default(),
            },
        ];
        let ruled = apply_to_result(Uuid::nil(), "x509_analyzer", &result);
        let values: Vec<&str> = ruled.observables.iter().map(|o| o.value.as_str()).collect();
        assert_eq!(values, ["example.com", "HOST"]);
        // a reference to what the result doesn't add is left for the core's other checks
        assert_eq!(
            ruled.observables[0].relationships,
            [
                Relationship::new(RelationshipKind::RelatedTo, fqdn(" a@b ")),
                Relationship::new(
                    RelationshipKind::RelatedTo,
                    ObservableRef::new(ObservableKind::Hostname, "HOST"),
                ),
            ]
        );
        assert_eq!(ruled.observables[0].redirection, None);
        assert!(ruled.analyzed.relationships.is_empty());
        assert_eq!(ruled.others.len(), 1);
        assert_eq!(ruled.others[0].observable.value, "HOST");
    }

    #[test]
    fn a_result_the_rules_keep_whole_is_borrowed() {
        let mut result = envelope();
        result.observables = vec![NewObservable::new(ObservableKind::Fqdn, "example.com")];
        assert!(matches!(
            apply_to_result(Uuid::nil(), "m", &result),
            Cow::Borrowed(_)
        ));
    }
}
