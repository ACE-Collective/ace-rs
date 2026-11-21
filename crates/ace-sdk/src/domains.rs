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

#[cfg(test)]
mod tests {
    use super::*;

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
