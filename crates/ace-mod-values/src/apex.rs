//! `apex_domain_analyzer`: ace3's `ApexDomainAnalyzer` (`saq/modules/apex_domain.py`, `d7436a48`).
//!
//! A subdomain's registrable domain (eTLD+1) becomes an `fqdn` observable of its own, shown as
//! "Apex Domain", so an analyst can pivot from `abc.example.com` to every alert with
//! `example.com`. The apex and whether it becomes an observable are `ace_sdk::domains::apex_of`,
//! which the RDAP module decides with too, on the public suffix list ace3's tldextract ships. A name
//! that is its own apex, or has no public suffix, gets no result.
//!
//! The RDAP module skips a subdomain this module gives an apex (`7265bb53`, `e871441c`). ace3
//! makes it wait for this module's result; ace4's RDAP module computes the same apex from the value
//! itself, since this module's result is a function of the value alone and a dependency in ace4
//! waits for a result this module doesn't store for a name that is its own apex
//! (`ace_mod_rdap`'s docs).

use ace_results::types::values::ApexDomainAnalysis;
use ace_results::{AnalysisType, NewObservable, ObservableKind, ResultEnvelope};
use ace_sdk::domains::apex_of;
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, TaskContext};

pub const MANIFEST: Manifest = Manifest::parser::<ApexDomainAnalyzer>();

/// What the alert view shows for the apex observable's type, as ace3's `DISPLAY_TYPE_APEX_DOMAIN`.
pub const DISPLAY_TYPE: &str = "Apex Domain";

pub struct ApexDomainAnalyzer;

impl Module for ApexDomainAnalyzer {
    const NAME: &'static str = ApexDomainAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Fqdn];
    type Output = ApexDomainAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(ApexDomainAnalyzer)
    }
}

impl Parser for ApexDomainAnalyzer {
    fn analyze(&self, ctx: &TaskContext<()>) -> Result<Outcome<ApexDomainAnalysis>, ModuleError> {
        let observable = ctx.observable();
        let Some(apex) = apex_of(&observable.value) else {
            return Ok(Outcome::Skipped(
                "its own apex, or no public suffix".to_owned(),
            ));
        };
        let mut result = ResultEnvelope::new(ApexDomainAnalysis {
            apex_domain: Some(apex.domain.clone()),
        });
        result.summary = Some(format!("Apex Domain: {}", apex.domain));
        // ace3 keeps its analysis when the fqdn check refuses the apex, which a name with a public
        // suffix passes
        if apex.observable {
            let mut o = NewObservable::new(ObservableKind::Fqdn, apex.domain);
            o.time = observable.time;
            o.display_type = Some(DISPLAY_TYPE.to_owned());
            result.observables.push(o);
        }
        Ok(Outcome::Done(result))
    }
}

#[cfg(test)]
mod tests {
    use ace_testkit::{Harness, fixed_now};

    use super::*;

    fn run(value: &str) -> Outcome<ApexDomainAnalysis> {
        let harness = Harness::<ApexDomainAnalyzer>::new().unwrap();
        let mut observable = harness.observable(ObservableKind::Fqdn, value);
        observable.time = Some(fixed_now());
        harness.run_parser(observable).unwrap()
    }

    #[test]
    fn a_subdomain_adds_its_apex() {
        let Outcome::Done(result) = run("Login.Example.co.uk") else {
            panic!("no result");
        };
        assert_eq!(result.details.apex_domain.as_deref(), Some("example.co.uk"));
        assert_eq!(
            result.summary.as_deref(),
            Some("Apex Domain: example.co.uk")
        );
        let [apex] = result.observables.as_slice() else {
            panic!("{:?}", result.observables);
        };
        assert_eq!(apex.kind, ObservableKind::Fqdn);
        assert_eq!(apex.value, "example.co.uk");
        assert_eq!(apex.display_type.as_deref(), Some(DISPLAY_TYPE));
        assert_eq!(apex.time, Some(fixed_now()));
    }

    #[test]
    fn an_apex_or_a_name_without_a_suffix_has_no_result() {
        for value in ["example.com", "localhost", "host.corp-internal"] {
            assert!(matches!(run(value), Outcome::Skipped(_)), "{value}");
        }
    }
}
