//! Registrable domains (eTLD+1), as ace3 finds them with tldextract.
//!
//! tldextract matches only the ICANN section of the public suffix list by default, so a name
//! under a private suffix such as `github.io` reduces to `<name>.github.io`'s ICANN registrable
//! domain, `github.io`. `public_suffix_list.dat` is the list tldextract 5.4.0 ships in ace3's
//! image, copied by `tools/ace3/dumps/public_suffix_list.sh`. ace3 downloads a fresh list when its
//! cache is empty, so a suffix added since that snapshot is the one difference.
//!
//! The list is in the binary only when a module calls one of these.

use std::sync::LazyLock;

use publicsuffix::{List, Psl};

const LIST: &str = include_str!("public_suffix_list.dat");

static ICANN: LazyLock<List> = LazyLock::new(|| {
    let end = LIST
        .find("// ===END ICANN DOMAINS===")
        .unwrap_or(LIST.len());
    LIST[..end]
        .parse()
        .unwrap_or_else(|e| panic!("the bundled public suffix list doesn't parse: {e}"))
});

/// tldextract's `top_domain_under_public_suffix`: the registrable domain of `value`, lowercased
/// and without a trailing dot, or None when the list has no known suffix for it or nothing comes
/// before the suffix.
pub fn top_domain_under_public_suffix(value: &str) -> Option<String> {
    let normalized = value.trim().to_lowercase();
    let normalized = normalized.trim_end_matches('.');
    if normalized.is_empty() {
        return None;
    }
    ICANN
        .domain(normalized.as_bytes())
        .filter(|domain| domain.suffix().is_known())
        .and_then(|domain| {
            std::str::from_utf8(domain.as_bytes())
                .ok()
                .map(str::to_owned)
        })
}

/// The RDAP module's `_registrable_domain`: the registrable domain of `value`, or `value`
/// lowercased and without its trailing dot when the list has no suffix for it.
pub fn registrable_domain(value: &str) -> String {
    let normalized = value.trim().to_lowercase();
    let normalized = normalized.trim_end_matches('.');
    if normalized.is_empty() {
        return value.to_owned();
    }
    top_domain_under_public_suffix(normalized).unwrap_or_else(|| normalized.to_owned())
}

/// ace3's `apex_domain_of` (`saq/modules/apex_domain.py`): the registrable domain of `fqdn`, or
/// None when `fqdn` is already its own registrable domain or the list has no suffix for it.
/// `apex_domain_analyzer` adds it as an observable, and the RDAP module looks it up in place of the
/// subdomain.
pub fn apex_domain_of(fqdn: &str) -> Option<String> {
    let lowered = ace_pycompat::pystr::lower(ace_pycompat::pystr::strip(fqdn));
    let normalized = lowered.trim_end_matches('.');
    if normalized.is_empty() {
        return None;
    }
    let apex = registrable_domain(normalized);
    (!apex.is_empty() && apex != normalized).then_some(apex)
}

/// A subdomain's apex, as `apex_domain_analyzer` finds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Apex {
    /// Its registrable domain (`apex_domain_of`), which the apex module's result records.
    pub domain: String,
    /// ace3's fqdn check (`validators.domain`) takes `domain`, so the apex module adds it as an
    /// `fqdn` observable, and the RDAP module looks that up in place of the subdomain.
    pub observable: bool,
}

/// The apex `apex_domain_analyzer` finds for `fqdn`, or None when `fqdn` is its own apex or has no
/// public suffix. The apex module and the RDAP module both decide with this, so RDAP skips exactly the
/// subdomains whose apex the apex module adds as an observable (ace3 `7265bb53`, `e871441c`).
pub fn apex_of(fqdn: &str) -> Option<Apex> {
    let domain = apex_domain_of(fqdn)?;
    let observable = ace_pycompat::validators::domain(&domain);
    Some(Apex { domain, observable })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_apex_is_an_observable_when_the_fqdn_check_takes_it() {
        assert_eq!(
            apex_of("Login.Example.co.uk"),
            Some(Apex {
                domain: "example.co.uk".to_owned(),
                observable: true
            })
        );
        // a label may not start with a hyphen, so the apex is recorded and not added
        assert_eq!(
            apex_of("www.-bad.com"),
            Some(Apex {
                domain: "-bad.com".to_owned(),
                observable: false
            })
        );
        for own in ["example.com", "localhost", "host.corp-internal", ""] {
            assert_eq!(apex_of(own), None, "{own}");
        }
    }

    #[test]
    fn domains_reduce_to_their_registrable_domain() {
        assert_eq!(registrable_domain("www.Example.com."), "example.com");
        assert_eq!(registrable_domain("a.b.example.co.uk"), "example.co.uk");
        // the private section isn't used, as in tldextract's default
        assert_eq!(registrable_domain("someone.github.io"), "github.io");
        assert_eq!(registrable_domain("localhost"), "localhost");
        assert_eq!(registrable_domain("x.not-a-real-tld"), "x.not-a-real-tld");
    }

    #[test]
    fn a_subdomain_has_an_apex_and_an_apex_has_none() {
        assert_eq!(
            apex_domain_of(" WWW.Example.COM. "),
            Some("example.com".to_owned())
        );
        assert_eq!(
            apex_domain_of("a.b.example.co.uk"),
            Some("example.co.uk".to_owned())
        );
        assert_eq!(apex_domain_of("example.com"), None);
        assert_eq!(apex_domain_of("Example.com."), None);
        // no public suffix: registrable_domain gives the name back
        assert_eq!(apex_domain_of("x.not-a-real-tld"), None);
        assert_eq!(apex_domain_of("localhost"), None);
        assert_eq!(apex_domain_of("co.uk"), None);
        assert_eq!(apex_domain_of(" . "), None);
        assert_eq!(apex_domain_of(""), None);
        // the private section isn't used, so a name under github.io has github.io as its apex
        assert_eq!(
            apex_domain_of("someone.github.io"),
            Some("github.io".to_owned())
        );
    }

    #[test]
    fn a_name_without_a_registrable_domain_has_no_top_domain() {
        assert_eq!(
            top_domain_under_public_suffix("WWW.example.com"),
            Some("example.com".to_owned())
        );
        assert_eq!(top_domain_under_public_suffix("com"), None);
        assert_eq!(top_domain_under_public_suffix("co.uk"), None);
        assert_eq!(top_domain_under_public_suffix("localhost"), None);
        assert_eq!(top_domain_under_public_suffix(""), None);
    }
}
