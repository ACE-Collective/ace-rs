//! `email_address_fqdn_analyzer`: ace3's `EmailAddressFQDNAnalyzer` (`saq/modules/email/address.py`).
//!
//! An email address, of any of its kinds, gives what follows its first `@` as an `fqdn`, when that
//! is a domain ace3's fqdn check takes. ace3 adds it volatile; ace4 has no volatile flag, which in
//! ace3 only the GUI's pruning and the analysis cache read.

use ace_results::types::values::EmailAddressFqdnAnalysis;
use ace_results::{AnalysisType, ObservableKind, ResultEnvelope};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, TaskContext};

use crate::observable;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<EmailAddressFqdnAnalyzer>();

pub struct EmailAddressFqdnAnalyzer;

impl Module for EmailAddressFqdnAnalyzer {
    const NAME: &'static str = EmailAddressFqdnAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::EmailAddress];
    type Output = EmailAddressFqdnAnalysis;
    type Settings = ();

    fn init(_: &()) -> Result<Self, ModuleError> {
        Ok(EmailAddressFqdnAnalyzer)
    }
}

impl Parser for EmailAddressFqdnAnalyzer {
    fn analyze(
        &self,
        ctx: &TaskContext<()>,
    ) -> Result<Outcome<EmailAddressFqdnAnalysis>, ModuleError> {
        // saq.email.get_email_domain: value.split('@', 1)[1]
        let domain = match ctx.observable().value.split_once('@') {
            Some((_, domain)) if !domain.is_empty() => domain,
            _ => return Ok(Outcome::Skipped("no domain in the address".to_owned())),
        };
        let mut result = ResultEnvelope::new(EmailAddressFqdnAnalysis {
            domain: Some(domain.to_owned()),
        });
        result
            .observables
            .extend(observable::new(ObservableKind::Fqdn, domain));
        result.summary = Some(format!("Email Address FQDN: {domain}"));
        Ok(Outcome::Done(result))
    }
}
