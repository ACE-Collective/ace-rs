//! What a permission is, and the one case rule (PLAN.md 5.2, ace3 #831).
//!
//! As in ace3, a permission has a major and a minor, such as `alert:write`. A code path checks a
//! `PermissionName`. A row grants or denies a `PermissionPattern`, whose parts can hold fnmatch
//! wildcards: `*`, `?`, `[seq]` and `[!seq]`. There's no admin flag: an admin holds `*:*`.
//!
//! The case rule is in `normalize`: a part is ASCII and lowercase. Both types make their parts with
//! it and keep them private, so an unnormalized value can't be stored or compared. Non-ASCII is
//! refused, not folded, because folding can turn another character into a name: U+212A, the Kelvin
//! sign, lowercases to `k`. ace3's columns are ASCII too. Wildcards fold with the rest, so `[A-Z]`
//! and `[a-z]` are one pattern, as they are in ace3. Migration 0020 holds a stored part to the same
//! rule.
//!
//! Left out of ace3's parsing: a part holding `:` or whitespace is refused, where ace3 can store one
//! that then never matches, or strips it in some paths and not others. ace3's shorthand of a bare
//! `major` meaning `major:*` belongs to whatever parses an operator's input, which isn't here yet.

use std::borrow::Cow;
use std::fmt;

/// ace3's columns are `String(512)`.
const MAX_PART: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} isn't a permission part: use ASCII letters, digits and _ . -, up to 512 of them")]
pub struct InvalidPermission(String);

/// The one case rule. Everything that makes a part comes through here.
fn normalize(part: &str, allowed: impl Fn(u8) -> bool) -> Result<String, InvalidPermission> {
    let part = part.to_ascii_lowercase();
    if part.is_empty() || part.len() > MAX_PART || !part.bytes().all(allowed) {
        return Err(InvalidPermission(part));
    }
    Ok(part)
}

const fn in_name(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'.' | b'-')
}

fn in_pattern(byte: u8) -> bool {
    in_name(byte) || matches!(byte, b'*' | b'?' | b'[' | b']' | b'!')
}

/// A permission as a code path checks it. It holds no wildcards: `*` isn't something to ask for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PermissionName {
    major: Cow<'static, str>,
    minor: Cow<'static, str>,
}

impl PermissionName {
    /// A name from anywhere, in any case. `Alert:WRITE` and `alert:write` are one name.
    pub fn new(major: &str, minor: &str) -> Result<Self, InvalidPermission> {
        Ok(PermissionName {
            major: Cow::Owned(normalize(major, in_name)?),
            minor: Cow::Owned(normalize(minor, in_name)?),
        })
    }

    /// A name written in code. It has to be normalized already, or the build fails.
    pub const fn known(major: &'static str, minor: &'static str) -> Self {
        assert!(
            is_normal_name(major) && is_normal_name(minor),
            "a known permission must be lowercase"
        );
        PermissionName {
            major: Cow::Borrowed(major),
            minor: Cow::Borrowed(minor),
        }
    }

    pub fn major(&self) -> &str {
        &self.major
    }

    pub fn minor(&self) -> &str {
        &self.minor
    }
}

const fn is_normal_name(part: &str) -> bool {
    let bytes = part.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if !in_name(bytes[i]) {
            return false;
        }
        i += 1;
    }
    !bytes.is_empty() && bytes.len() <= MAX_PART
}

impl fmt::Display for PermissionName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.major, self.minor)
    }
}

/// What a row grants or denies.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PermissionPattern {
    major: String,
    minor: String,
}

impl PermissionPattern {
    pub fn new(major: &str, minor: &str) -> Result<Self, InvalidPermission> {
        Ok(PermissionPattern {
            major: normalize(major, in_pattern)?,
            minor: normalize(minor, in_pattern)?,
        })
    }

    pub fn major(&self) -> &str {
        &self.major
    }

    pub fn minor(&self) -> &str {
        &self.minor
    }

    pub fn matches(&self, name: &PermissionName) -> bool {
        fnmatch(self.major.as_bytes(), name.major.as_bytes())
            && fnmatch(self.minor.as_bytes(), name.minor.as_bytes())
    }
}

impl fmt::Display for PermissionPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.major, self.minor)
    }
}

/// Python's `fnmatchcase`, which ace3 matches with. Parts are ASCII, so bytes will do. It agreed with
/// Python on 199,998 of 200,000 random patterns. Those two hit a Python quirk: a reversed range whose
/// removal leaves `!` first, as in `[[-!!]`, turns the class into a negated one there.
fn fnmatch(pattern: &[u8], value: &[u8]) -> bool {
    let (mut p, mut v) = (0, 0);
    // where to resume after the last `*`: the pattern after it, and how much it has taken
    let mut star = None;
    while v < value.len() {
        let next = match pattern.get(p) {
            Some(b'*') => {
                p += 1;
                star = Some((p, v));
                continue;
            }
            Some(b'?') => Some(p + 1),
            Some(b'[') => match class_end(pattern, p) {
                Some(end) => class_matches(&pattern[p + 1..end], value[v]).then_some(end + 1),
                // an unclosed `[` is a literal one
                None => (value[v] == b'[').then_some(p + 1),
            },
            Some(&literal) => (literal == value[v]).then_some(p + 1),
            None => None,
        };
        match (next, star) {
            (Some(next), _) => {
                p = next;
                v += 1;
            }
            (None, Some((after, taken))) => {
                p = after;
                v = taken + 1;
                star = Some((after, v));
            }
            (None, None) => return false,
        }
    }
    pattern[p..].iter().all(|&byte| byte == b'*')
}

/// The index of the `]` that closes the class opening at `open`. A `]` straight after the opening
/// is a member.
fn class_end(pattern: &[u8], open: usize) -> Option<usize> {
    let mut first = open + 1;
    if pattern.get(first) == Some(&b'!') {
        first += 1;
    }
    if pattern.get(first) == Some(&b']') {
        first += 1;
    }
    let tail = pattern.get(first..)?;
    tail.iter()
        .position(|&byte| byte == b']')
        .map(|at| first + at)
}

fn class_matches(class: &[u8], byte: u8) -> bool {
    let (negated, members) = match class.split_first() {
        Some((b'!', members)) => (true, members),
        _ => (false, class),
    };
    let mut found = false;
    let mut i = 0;
    while i < members.len() {
        if members.get(i + 1) == Some(&b'-') && i + 2 < members.len() {
            // a reversed range is empty
            found |= (members[i]..=members[i + 2]).contains(&byte);
            i += 3;
        } else {
            found |= members[i] == byte;
            i += 1;
        }
    }
    found != negated
}

/// What a row does when its pattern matches. A deny wins over any allow, whichever row it's on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, sqlx::Type)]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "service.permission_effect", rename_all = "snake_case")]
pub enum Effect {
    Allow,
    Deny,
}

/// True when something allows the name and nothing denies it. No match is a refusal.
pub(crate) fn allows<'g>(
    grants: impl IntoIterator<Item = &'g (PermissionPattern, Effect)>,
    name: &PermissionName,
) -> bool {
    let mut allowed = false;
    for (pattern, effect) in grants {
        if pattern.matches(name) {
            match effect {
                Effect::Deny => return false,
                Effect::Allow => allowed = true,
            }
        }
    }
    allowed
}

/// Delete what the bucket's index no longer keeps: objects nothing has held for their pool's grace, expired
/// holds, and bytes with no index row (PLAN.md 6.7). ace3 has no such permission: `ace cas gc` and `ace cas
/// orphans` run from cron with the database's credentials. Only the scheduler's components hold it.
pub const BUCKET_GC: PermissionName = PermissionName::known("bucket", "gc");
/// Re-hash a sample of the bucket's objects and record when each was found intact, as ace3's `ace cas
/// verify` does. Only the scheduler's `scheduler:bucket_verify` holds it.
pub const BUCKET_VERIFY: PermissionName = PermissionName::known("bucket", "verify");
/// Rebuild the newly registered domains list from its feeds, as ace3's `ace nrd refresh` does. Only
/// the scheduler's `scheduler:nrd_refresh` holds it.
pub const NRD_REFRESH: PermissionName = PermissionName::known("nrd", "refresh");
/// Enter the GUI's administration area: ace3's `admin:read`, its umbrella gate. Each page there needs its
/// own permission too, such as `user:read` for Users & Roles.
pub const ADMIN_READ: PermissionName = PermissionName::known("admin", "read");
/// Read an alert and its files: ace3's `alert:read`.
pub const ALERT_READ: PermissionName = PermissionName::known("alert", "read");
/// Change an alert: ace3's `alert:write`, which its disposition route requires.
pub const ALERT_WRITE: PermissionName = PermissionName::known("alert", "write");
/// Move an alert to another queue (PLAN.md 7.13). ace3 has no such permission: its routers move alerts with
/// no check. Only ACE's routing, the component `alert_routing`, holds it.
pub const ALERT_QUEUE: PermissionName = PermissionName::known("alert", "queue");
/// Submit analysis: ace3's `alert:create`, which its submit route requires.
pub const ALERT_CREATE: PermissionName = PermissionName::known("alert", "create");
/// Read an archived email, decrypted, by its Message-ID: ace3's `email:read`.
pub const EMAIL_READ: PermissionName = PermissionName::known("email", "read");
/// Make the email archive's weeks ahead and drop those past retention, as ace3's `ace partitions
/// maintain` does. ace3 has no such permission. Only the scheduler's
/// `scheduler:email_archive_partitions` holds it.
pub const EMAIL_ARCHIVE_MAINTAIN: PermissionName =
    PermissionName::known("email_archive", "maintain");
/// List the observables ACE detects wherever they appear, and the types they're of: ace3's
/// `detection:read`.
pub const DETECTION_READ: PermissionName = PermissionName::known("detection", "read");
/// Add and remove the observables ACE detects, and set when each expires: ace3's `detection:write`.
pub const DETECTION_WRITE: PermissionName = PermissionName::known("detection", "write");
/// Ask a collector for a file through the API: ace3's `file_collection:create`, which ace3's integrations
/// check on their own request routes. A collector may run a script on the host to produce the file.
pub const FILE_COLLECTION_CREATE: PermissionName =
    PermissionName::known("file_collection", "create");
/// Read file collection requests and their tries: ace3's `file_collection:read`.
pub const FILE_COLLECTION_READ: PermissionName = PermissionName::known("file_collection", "read");
/// Stop, retry and delete file collection requests: ace3's `file_collection:write`.
pub const FILE_COLLECTION_WRITE: PermissionName = PermissionName::known("file_collection", "write");
/// Let go of the files of collections past their retention, as ace3's `ace file-collection prune` does.
/// ace3 has no such permission. Only the scheduler's `scheduler:file_collection_prune` holds it.
pub const FILE_COLLECTION_PRUNE: PermissionName = PermissionName::known("file_collection", "prune");
/// Read remediations, their tries, the remediation targets of alerts and observables, and alerts'
/// remediation coverage: ace3's `remediation:read`.
pub const REMEDIATION_READ: PermissionName = PermissionName::known("remediation", "read");
/// Queue, stop, retry, restore and delete remediations: ace3's `remediation:write`.
pub const REMEDIATION_WRITE: PermissionName = PermissionName::known("remediation", "write");
/// Read events, their alerts, malware and threat types, and export them: ace3's `event:read`.
pub const EVENT_READ: PermissionName = PermissionName::known("event", "read");
/// Change events, and the threat types and malware's threats they record: ace3's `event:write`.
pub const EVENT_WRITE: PermissionName = PermissionName::known("event", "write");
/// List the hunts the hunter loaded and read a hunt's state (PLAN.md 6.4). ace3 has no such permission:
/// its hunts were files, and their state pickles on the node.
pub const HUNT_READ: PermissionName = PermissionName::known("hunt", "read");
/// Validate a hunt through the `hunt` router, and, for the hunter, record the hunts it loaded: ace3's
/// `hunt:write`.
pub const HUNT_WRITE: PermissionName = PermissionName::known("hunt", "write");
/// Read the analyst-edited lists, such as the email whitelists (PLAN.md 5.14). ace3 has no such
/// permission: its lists were files on the node.
pub const LIST_READ: PermissionName = PermissionName::known("list", "read");
/// Add, change and delete entries on the analyst-edited lists. ace3's nearest is the `whitelist:write`
/// it removed with its Whitelist action (its migration `e28c9d0a6154`).
pub const LIST_WRITE: PermissionName = PermissionName::known("list", "write");
/// Look observables up across alerts, list the observable types, and read observables' comments:
/// ace3's `observable:read`.
pub const OBSERVABLE_READ: PermissionName = PermissionName::known("observable", "read");
/// Comment on observables, and change or delete your own comments: ace3's `observable:write`.
pub const OBSERVABLE_WRITE: PermissionName = PermissionName::known("observable", "write");
/// Run `ace` commands from the GUI's CLI page, cancel them, and read every run and its output: ace3's
/// `cli:execute`.
pub const CLI_EXECUTE: PermissionName = PermissionName::known("cli", "execute");
/// List failed tasks and download them with their inputs: ace3's `crash:read`.
pub const CRASH_READ: PermissionName = PermissionName::known("crash", "read");
/// See the rules in QA mode, their matches and the matches' records: ace3's `signature:read`.
pub const SIGNATURE_READ: PermissionName = PermissionName::known("signature", "read");
/// Download the files rules in QA mode matched: ace3's `signature:download`.
pub const SIGNATURE_DOWNLOAD: PermissionName = PermissionName::known("signature", "download");
/// Purge the matches of rules in QA mode: ace3's `signature:qa_purge`.
pub const SIGNATURE_QA_PURGE: PermissionName = PermissionName::known("signature", "qa_purge");
/// Change SVS's test hosts, and later batches of 7.10 its other settings, global ignores and samples:
/// ace3's `svs:admin`.
pub const SVS_ADMIN: PermissionName = PermissionName::known("svs", "admin");
/// Read SVS's runs, tests, test hosts and coverage: ace3's `svs:run_read`.
pub const SVS_RUN_READ: PermissionName = PermissionName::known("svs", "run_read");
/// Request YARA validations of a rule repository's commits and read their status: ace3's `svs:validate`,
/// the CI key's permission.
pub const SVS_VALIDATE: PermissionName = PermissionName::known("svs", "validate");
/// Remove the finished YARA validations past their retention, as ace3's `ace svs yara prune` does. ace3
/// has no such permission. Only the scheduler's `scheduler:svs_validations_prune` holds it.
pub const SVS_VALIDATION_PRUNE: PermissionName = PermissionName::known("svs", "validation_prune");
/// Read the Atomic Red Team catalog's repositories into the catalog, as ace3's `service_svs` and
/// `ace svs catalog refresh` do. ace3 has no such permission. Only the scheduler's
/// `scheduler:svs_catalog_refresh` holds it.
pub const SVS_CATALOG_REFRESH: PermissionName = PermissionName::known("svs", "catalog_refresh");
/// Register SVS test runs, make a launcher's calls on them, and open and end a test host's maintenance
/// windows: ace3's `svs:run_register`.
pub const SVS_RUN_REGISTER: PermissionName = PermissionName::known("svs", "run_register");
/// A person's changes to SVS test runs: ace3's `svs:run_manage`.
pub const SVS_RUN_MANAGE: PermissionName = PermissionName::known("svs", "run_manage");
/// Move SVS test runs and maintenance windows on by time, as ace3's `service_svs` does. ace3 has no such
/// permission. Only the scheduler's `scheduler:svs_run_timers` holds it.
pub const SVS_RUN_TIMERS: PermissionName = PermissionName::known("svs", "run_timers");
/// Recompute SVS's ATT&CK coverage and its worklist, as ace3's `service_svs` and `ace svs coverage
/// refresh` do. ace3 has no such permission. Only the scheduler's `scheduler:svs_coverage_refresh` and
/// `scheduler:svs_coverage_snapshot` hold it.
pub const SVS_COVERAGE_REFRESH: PermissionName = PermissionName::known("svs", "coverage_refresh");
/// File the day's snapshot of SVS's coverage, as ace3's `ace svs coverage snapshot` does. ace3 has no
/// such permission. Only the scheduler's `scheduler:svs_coverage_snapshot` holds it.
pub const SVS_COVERAGE_SNAPSHOT: PermissionName = PermissionName::known("svs", "coverage_snapshot");
/// See users, groups, grants and keys: ace3's `user:read`.
pub const USER_READ: PermissionName = PermissionName::known("user", "read");
/// Change users, groups and grants: ace3's `user:write`.
pub const USER_WRITE: PermissionName = PermissionName::known("user", "write");
/// Manage your own API keys: ace3's `user:self`.
pub const USER_SELF: PermissionName = PermissionName::known("user", "self");

/// A permission ACE checks, and what it lets its holder do.
#[derive(Debug)]
pub struct CatalogEntry {
    pub name: PermissionName,
    pub description: &'static str,
}

/// Every permission this workspace checks, as ace3's `PERMISSION_CATALOG` is for ace3. It holds only
/// what ace4 enforces, so a router that brings a permission adds it here, and `tests/service.rs` fails
/// when a `PermissionName::known` in this crate isn't listed. ace3 keeps a copy in a table for its
/// management page; the GUI here is in the same binary, so it reads this. A grant whose pattern covers
/// nothing here is logged as a likely typo, as ace3 warns, and a key's own scope must cover something.
pub static CATALOG: &[CatalogEntry] = &[
    CatalogEntry {
        name: ADMIN_READ,
        description: "Enter the administration area. Each page there needs its own permission too.",
    },
    CatalogEntry {
        name: ALERT_CREATE,
        description: "Submit analysis, which may become alerts.",
    },
    CatalogEntry {
        name: ALERT_QUEUE,
        description: "Move alerts to the queue their routers decide. ACE's alert routing holds it.",
    },
    CatalogEntry {
        name: ALERT_READ,
        description: "Read alerts, their observables, results and files.",
    },
    CatalogEntry {
        name: ALERT_WRITE,
        description: "Change alerts, such as their disposition.",
    },
    CatalogEntry {
        name: BUCKET_GC,
        description: "Delete what the bucket's index no longer keeps: objects nothing has held for their pool's \
                      grace, expired holds, and bytes with no index row. The scheduler holds it.",
    },
    CatalogEntry {
        name: BUCKET_VERIFY,
        description: "Re-hash a sample of the bucket's objects and record when each was found intact. The \
                      scheduler holds it.",
    },
    CatalogEntry {
        name: CLI_EXECUTE,
        description: "Run ace commands from Administration's CLI page, each contained on a parser pool until \
                      its deadline, cancel any run, and read every run and its output.",
    },
    CatalogEntry {
        name: CRASH_READ,
        description: "List failed tasks and download them; the archive holds the file the module failed on.",
    },
    CatalogEntry {
        name: DETECTION_READ,
        description: "List the observables ACE detects in every alert, with their expiry and context.",
    },
    CatalogEntry {
        name: DETECTION_WRITE,
        description: "Add and remove the observables ACE detects, and set when each expires. A detection \
                      applies to the next task that checks an observable: every alert holding it gets a \
                      detection point.",
    },
    CatalogEntry {
        name: EMAIL_ARCHIVE_MAINTAIN,
        description: "Make the email archive's weeks ahead and drop those past retention. The scheduler \
                      holds it.",
    },
    CatalogEntry {
        name: EMAIL_READ,
        description: "Read an archived email, decrypted, by its Message-ID: any email the archive kept, \
                      from any alert (audited).",
    },
    CatalogEntry {
        name: EVENT_READ,
        description: "View events, their alerts and details, the threat types and malware's threats, \
                      and export events.",
    },
    CatalogEntry {
        name: EVENT_WRITE,
        description: "Make events, add alerts to them and change them, and add, rename and delete threat \
                      types and malware's threats.",
    },
    CatalogEntry {
        name: FILE_COLLECTION_CREATE,
        description: "Request file collections from hosts through the API; a collector may run a script on the \
                      host to produce the file.",
    },
    CatalogEntry {
        name: FILE_COLLECTION_PRUNE,
        description: "Let go of the files of collections that completed past their retention; the alerts that \
                      asked for a file keep it. The scheduler holds it.",
    },
    CatalogEntry {
        name: FILE_COLLECTION_READ,
        description: "Read file collection requests and their history.",
    },
    CatalogEntry {
        name: FILE_COLLECTION_WRITE,
        description: "Stop, retry and delete file collection requests on the File Collections page.",
    },
    CatalogEntry {
        name: HUNT_READ,
        description: "List the hunts the hunter loaded, and read a hunt's state: when it last ran, the window \
                      it last searched and when it last alerted.",
    },
    CatalogEntry {
        name: HUNT_WRITE,
        description: "Validate a hunt, running it over events given with it.",
    },
    CatalogEntry {
        name: LIST_READ,
        description: "Read the analyst-edited lists, such as the email whitelists, and their entries.",
    },
    CatalogEntry {
        name: LIST_WRITE,
        description: "Add, change and delete entries on the analyst-edited lists. An entry applies to the \
                      next task that reads its list: a whitelist entry stops the analysis of what it matches.",
    },
    CatalogEntry {
        name: NRD_REFRESH,
        description: "Rebuild the newly registered domains list from its feeds. The scheduler holds it.",
    },
    CatalogEntry {
        name: OBSERVABLE_READ,
        description: "Look observables up across alerts, list the observable types, and read the \
                      comments on observables.",
    },
    CatalogEntry {
        name: OBSERVABLE_WRITE,
        description: "Comment on observables, and change or delete your own comments. Only the author \
                      changes a comment.",
    },
    CatalogEntry {
        name: REMEDIATION_READ,
        description: "View remediation actions and history, the remediation targets of alerts and \
                      observables, and alerts' remediation coverage.",
    },
    CatalogEntry {
        name: REMEDIATION_WRITE,
        description: "Queue, stop, retry, restore and clear remediations: the event page's remediation \
                      links and the Remediations page. A remediator acts outside ACE, such as removing an \
                      email from a mailbox.",
    },
    CatalogEntry {
        name: SIGNATURE_DOWNLOAD,
        description: "Download the files YARA rules in QA mode matched: live malware, in zips with the \
                      password infected.",
    },
    CatalogEntry {
        name: SIGNATURE_QA_PURGE,
        description: "Purge the matches kept for YARA rules in QA mode, by version or by match (audited). \
                      A file a root still holds stays.",
    },
    CatalogEntry {
        name: SIGNATURE_READ,
        description: "Read the YARA rules in QA mode, their match counts, their matches and the matches' \
                      records.",
    },
    CatalogEntry {
        name: SVS_ADMIN,
        description: "Add, change and remove the SVS test hosts runs may target (audited).",
    },
    CatalogEntry {
        name: SVS_RUN_READ,
        description: "Read the SVS test hosts, the Atomic Red Team tests runs may be registered for, the \
                      catalog's repositories, the test runs, ATT&CK coverage and the worklist.",
    },
    CatalogEntry {
        name: SVS_VALIDATE,
        description: "Request SVS YARA validations of a rule repository's commits and read their status \
                      (counts, rule names and uuids only; the CI key's permission).",
    },
    CatalogEntry {
        name: SVS_VALIDATION_PRUNE,
        description: "Remove the finished SVS YARA validations past their retention, with their reports. The \
                      scheduler holds it.",
    },
    CatalogEntry {
        name: SVS_CATALOG_REFRESH,
        description: "Read the SVS catalog repositories' tests into the catalog (audited). The scheduler \
                      holds it.",
    },
    CatalogEntry {
        name: SVS_RUN_REGISTER,
        description: "Register SVS test runs, start, report on and cancel them, and open and end a test \
                      host's maintenance windows (audited). A launcher's key holds it.",
    },
    CatalogEntry {
        name: SVS_RUN_MANAGE,
        description: "A person's changes to SVS test runs and what's decided about them, and the \
                      coverage worklist's resolutions (audited).",
    },
    CatalogEntry {
        name: SVS_RUN_TIMERS,
        description: "Move SVS test runs and maintenance windows on by time (audited). The scheduler \
                      holds it.",
    },
    CatalogEntry {
        name: SVS_COVERAGE_REFRESH,
        description: "Recompute SVS's ATT&CK coverage and its worklist (audited). The scheduler holds \
                      it.",
    },
    CatalogEntry {
        name: SVS_COVERAGE_SNAPSHOT,
        description: "File the day's snapshot of SVS's ATT&CK coverage (audited). The scheduler holds \
                      it.",
    },
    CatalogEntry {
        name: USER_READ,
        description: "See users, groups, their grants, and API keys.",
    },
    CatalogEntry {
        name: USER_SELF,
        description: "Create, change and revoke your own API keys, limited to permissions you hold. \
                      Only a person holds it, never a key.",
    },
    CatalogEntry {
        name: USER_WRITE,
        description: "Create and change users, groups, memberships, grants and API keys.",
    },
];

/// The catalog's names a pattern covers.
pub(crate) fn covered_by(
    pattern: &PermissionPattern,
) -> impl Iterator<Item = &'static PermissionName> {
    CATALOG
        .iter()
        .map(|entry| &entry.name)
        .filter(move |name| pattern.matches(name))
}

/// True for a permission only a person can hold, whatever a key's or a component's rows say. A key
/// holding `user:self` could widen its own scope up to all its owner holds, as ace3's
/// `SESSION_ONLY_PAIRS` says.
pub(crate) fn is_people_only(name: &PermissionName) -> bool {
    *name == USER_SELF
}
