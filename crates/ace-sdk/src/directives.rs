//! The directives an analyst may add to an observable (PLAN.md decision 31).
//!
//! A directive is a word on an observable that a module reads, such as `extract_urls`, which
//! `url_extraction` requires (`Module::REQUIRED_DIRECTIVES`). Modules add most of them. An analyst adds
//! one from the alert page's observable menu or the JSON API, and the root then runs again in
//! correlation mode, so a module that requires it is queued.
//!
//! ace3 keeps every directive in `saq/constants.py`'s `DIRECTIVE_DESCRIPTIONS` and offers a subset in its
//! GUI, `GUI_DIRECTIVES`. An integration adds its own with `register_directive(name, description,
//! gui=True)` when it is imported. Here the list holds only the directives an analyst may add: the
//! open-source ones are `BUILTIN`, those of ace3's `GUI_DIRECTIVES` an ace4 module reads, and a site adds its
//! own through `ace_app::App::directives`. `directive_list` checks the whole list when the binary
//! starts, and an analyst's request for a directive it doesn't hold is refused.

use std::fmt;

/// A directive an analyst may add: its name, and what it asks for, which the menu shows beside it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Directive {
    pub name: &'static str,
    pub description: &'static str,
}

impl Directive {
    pub const fn new(name: &'static str, description: &'static str) -> Directive {
        Directive { name, description }
    }
}

/// The directives of ace3's `GUI_DIRECTIVES` that an ace4 module reads, in name order, with ace3's
/// descriptions (`saq/constants.py` at `fe6da632`). ace3 offers eleven more that nothing here reads:
/// `analyze_activity`, `extract_email`, `extract_pcap`, `no_cache`, `scan_urlscan`, `triage`,
/// `force_download` and `phishkit` are read by no module in ace3 either, and `sandbox`, `no_sandbox`
/// and `sandbox_force` only by ace3's `SandboxAnalysisModule`, whose one user is a site's ExampleSandbox module,
/// which registers them when it is ported (the owner's decision of 2026-11-20).
pub const BUILTIN: &[Directive] = &[
    Directive::new("collect_file", "collect the file from the remote endpoint"),
    Directive::new("crawl", "crawl the URL"),
    Directive::new("crawl_extracted_urls", "crawl all extracted URLs"),
    Directive::new("extract_iocs", "extract IOCs from the file"),
    Directive::new("extract_urls", "extract URLs from the given file"),
];

/// The longest name a directive may have.
pub const MAX_NAME_CHARS: usize = 64;

/// The longest description a directive may have.
pub const MAX_DESCRIPTION_CHARS: usize = 512;

/// Why a binary's list of directives is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DirectiveListError {
    #[error(
        "directive {0:?} isn't 1 to {MAX_NAME_CHARS} lowercase letters, digits and _, starting with a letter"
    )]
    BadName(&'static str),
    #[error(
        "directive {0} has no description, or one longer than {MAX_DESCRIPTION_CHARS} characters"
    )]
    BadDescription(&'static str),
    #[error("directive {0} is listed twice")]
    Duplicate(&'static str),
}

fn valid_name(name: &str) -> bool {
    name.len() <= MAX_NAME_CHARS
        && name.starts_with(|c: char| c.is_ascii_lowercase())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn valid_description(description: &str) -> bool {
    !description.trim().is_empty()
        && description.chars().count() <= MAX_DESCRIPTION_CHARS
        && !description.chars().any(char::is_control)
}

/// The directives an analyst may add, in name order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectiveList(Vec<Directive>);

impl Default for DirectiveList {
    fn default() -> Self {
        DirectiveList::builtin()
    }
}

impl DirectiveList {
    /// The open-source directives alone.
    pub fn builtin() -> DirectiveList {
        directive_list(&[]).expect("the built-in directives are a valid list")
    }

    /// The directive named `name`, if the list holds it.
    pub fn get(&self, name: &str) -> Option<&Directive> {
        self.0.iter().find(|directive| directive.name == name)
    }

    pub fn contains(&self, name: &str) -> bool {
        self.get(name).is_some()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Directive> {
        self.0.iter()
    }

    pub fn names(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.0.iter().map(|directive| directive.name)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// The built-in directives and `extra`, in name order, after checking that every name and description
/// is valid and every name listed once. A site's directive with a built-in's name is refused, as a file
/// role is, rather than quietly replacing the built-in's description.
pub fn directive_list(extra: &[Directive]) -> Result<DirectiveList, DirectiveListError> {
    let mut list: Vec<Directive> = Vec::with_capacity(BUILTIN.len() + extra.len());
    for directive in BUILTIN.iter().chain(extra) {
        if !valid_name(directive.name) {
            return Err(DirectiveListError::BadName(directive.name));
        }
        if !valid_description(directive.description) {
            return Err(DirectiveListError::BadDescription(directive.name));
        }
        if list.iter().any(|d| d.name == directive.name) {
            return Err(DirectiveListError::Duplicate(directive.name));
        }
        list.push(*directive);
    }
    list.sort_by_key(|directive| directive.name);
    Ok(DirectiveList(list))
}

impl fmt::Display for Directive {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_builtin_list_is_ace3s_gui_directives_ace4_reads_in_name_order() {
        let list = DirectiveList::builtin();
        let names: Vec<&str> = list.names().collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
        assert_eq!(list.len(), 5);
        assert_eq!(
            list.get("extract_urls").map(|d| d.description),
            Some("extract URLs from the given file")
        );
        // ace3 offers none of the directives only ACE sets
        for internal in [
            "exclude_all",
            "ignore_automation_limits",
            "original_email",
            "archive",
        ] {
            assert!(!list.contains(internal), "{internal}");
        }
    }

    #[test]
    fn a_site_adds_its_own_and_a_bad_one_is_refused() {
        const SITE: Directive = Directive::new("locate_file", "find where the file is on disk");
        let list = directive_list(&[SITE]).expect("a valid list");
        assert_eq!(list.len(), BUILTIN.len() + 1);
        assert_eq!(list.get("locate_file"), Some(&SITE));
        assert_eq!(
            directive_list(&[Directive::new("crawl", "again")]),
            Err(DirectiveListError::Duplicate("crawl"))
        );
        assert_eq!(
            directive_list(&[SITE, SITE]),
            Err(DirectiveListError::Duplicate("locate_file"))
        );
        for bad in ["", "Crawl", "1st", "a-b", "a b", "yara_meta:x"] {
            assert_eq!(
                directive_list(&[Directive::new(bad, "x")]),
                Err(DirectiveListError::BadName(bad)),
                "{bad:?}"
            );
        }
        let long: &'static str = Box::leak("a".repeat(MAX_NAME_CHARS + 1).into_boxed_str());
        assert!(directive_list(&[Directive::new(long, "x")]).is_err());
        assert_eq!(
            directive_list(&[Directive::new("quiet", " ")]),
            Err(DirectiveListError::BadDescription("quiet"))
        );
        assert_eq!(
            directive_list(&[Directive::new("bell", "ring\u{7}")]),
            Err(DirectiveListError::BadDescription("bell"))
        );
    }
}
