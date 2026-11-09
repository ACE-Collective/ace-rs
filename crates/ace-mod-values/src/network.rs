//! `network_identifier`: ace3's `NetworkIdentifier` (`saq/modules/asset/network_identifier.py`).
//!
//! An IP address in any of the site's networks gets the names of those it's in, and an `asset`
//! observable of the same address.
//!
//! Where ace4 departs:
//!
//! - ace3 reads the networks from a CSV file on its node, `data/etc/local_networks.csv`, once when
//!   the module starts, with the header `Indicator,Indicator_Type` and a row per network, and its
//!   shipped file has only the header. Here they are the overlay's `networks` setting, the same rows
//!   in the same order, read once when the pool starts as ace3's are. A network iptools can't read
//!   stops the module from starting, as it stops ace3's.

use ace_results::types::values::NetworkIdentifierAnalysis;
use ace_results::{AnalysisType, ObservableKind, ResultEnvelope};
use ace_sdk::{Manifest, Module, ModuleError, Outcome, Parser, TaskContext};
use schemars::JsonSchema;
use serde::Deserialize;

use crate::iptools::IpRange;
use crate::observable;

/// The module's manifest.
pub const MANIFEST: Manifest = Manifest::parser::<NetworkIdentifier>();

/// One row of ace3's CSV.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// The CSV's `Indicator`: CIDR notation, an address and a dotted netmask, or one address, as
    /// iptools' `IpRange` reads them.
    pub cidr: String,
    /// The CSV's `Indicator_Type`: the name the result gives the network.
    pub name: String,
}

/// ace3's `analysis_module_network_identifier` settings, with its CSV's rows in place of its path.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, default)]
pub struct NetworkIdentifierSettings {
    pub networks: Vec<Network>,
}

pub struct NetworkIdentifier {
    networks: Vec<(IpRange, String)>,
}

impl Module for NetworkIdentifier {
    const NAME: &'static str = NetworkIdentifierAnalysis::MODULE;
    const INPUTS: &'static [ObservableKind] = &[ObservableKind::Ip, ObservableKind::Ipv4];
    type Output = NetworkIdentifierAnalysis;
    type Settings = NetworkIdentifierSettings;

    fn init(settings: &NetworkIdentifierSettings) -> Result<Self, ModuleError> {
        let networks = settings
            .networks
            .iter()
            .map(|n| {
                IpRange::new(&n.cidr)
                    .map(|range| (range, n.name.clone()))
                    .ok_or_else(|| {
                        ModuleError::other(format!(
                            "network {:?} isn't a range iptools reads",
                            n.cidr
                        ))
                    })
            })
            .collect::<Result<_, _>>()?;
        Ok(NetworkIdentifier { networks })
    }
}

impl Parser for NetworkIdentifier {
    fn analyze(
        &self,
        ctx: &TaskContext<NetworkIdentifierSettings>,
    ) -> Result<Outcome<NetworkIdentifierAnalysis>, ModuleError> {
        let value = ctx.observable().value.as_str();
        let mut result = ResultEnvelope::new(NetworkIdentifierAnalysis::default());
        for (range, name) in &self.networks {
            match range.contains(value) {
                Some(true) => result.details.identified_networks.push(name.clone()),
                Some(false) => {}
                // iptools raises a TypeError for an address it can't read, such as one with a
                // scope, which ace3 logs before going on to the next network
                None => tracing::error!(
                    "invalid ipv4 {value}: expected ip address, 32-bit integer or 128-bit integer"
                ),
            }
        }
        let names = &result.details.identified_networks;
        if !names.is_empty() {
            result.summary = Some(format!(
                "Network Identification Analysis: {}",
                crate::py::format_item_list_for_summary(names)
            ));
            result
                .observables
                .extend(observable::new(ObservableKind::Asset, value));
        }
        Ok(Outcome::Done(result))
    }
}
