//! Observable kinds.
//!
//! A kind is one entry of a list that is fixed when the binary is built, so nothing registers a
//! type at run time (ace3 #1030). The open-source kinds, `ObservableKind::BUILTIN`, are ace3's
//! observable types: `fixtures/ace3_observable_types.json` is ace3's list, dumped by
//! `tools/ace3/dumps/observable_types.py`, and a test checks them against it: names, parents,
//! deprecated flags, default display types and descriptions.
//!
//! A site defines its own kinds as constants with `ObservableKind::define`, and its binary's
//! list is the built-in kinds plus those (PLAN.md 2.31). `ace-app` hands that list to
//! `install_types` first thing in `main`, before anything reads a type name, and it can't change
//! after. A name is looked up in the installed list, or in `BUILTIN` in a process that installed
//! none, such as a library's tests.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, OnceLock, RwLock};

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// What an observable kind is: its name and where it sits among the others.
#[derive(Debug, PartialEq, Eq)]
pub struct ObservableType {
    /// The kind's name, as ace3 spells it: lowercase letters, digits and `_`.
    pub name: &'static str,
    /// The kind this one extends, from ace3's `etc/observable_types.yaml` for the built-in kinds.
    /// A module that accepts the parent also accepts this kind.
    pub parent: Option<ObservableKind>,
    /// Recognized, but not offered to analysts.
    pub deprecated: bool,
    /// The label shown when nothing sets one on the observable.
    pub default_display_type: Option<&'static str>,
    pub description: Option<&'static str>,
}

/// The type of an observable, named as in ace3 (`ipv4`, `email_address`, `file`). Two kinds are
/// equal when their names are, and they sort by name.
#[derive(Clone, Copy)]
pub struct ObservableKind(&'static ObservableType);

macro_rules! observable_kinds {
    ($(
        $variant:ident = $name:literal, parent $parent:expr, deprecated $deprecated:literal,
            display $display:expr, description $description:expr;
    )+) => {
        #[allow(non_upper_case_globals)]
        impl ObservableKind {
            $(
                pub const $variant: ObservableKind = ObservableKind::define(&ObservableType {
                    name: $name,
                    parent: $parent,
                    deprecated: $deprecated,
                    default_display_type: $display,
                    description: $description,
                });
            )+

            /// The open-source kinds, ace3's, in name order.
            pub const BUILTIN: &'static [ObservableKind] = &[$(ObservableKind::$variant),+];
        }
    };
}

observable_kinds! {
    Asset = "asset", parent None, deprecated false, display None,
        description Some("a F_IPV4 identified to be a managed asset");
    AvStreetname = "av_streetname", parent None, deprecated false, display None,
        description Some("anti-virus vendor name for a malware family");
    AwsAccessKeyId = "aws_access_key_id", parent None, deprecated false, display None,
        description Some("an access key ID assigned to a user identity");
    AwsAccountId = "aws_account_id", parent None, deprecated false, display None,
        description Some("id of an AWS account");
    AwsAmiId = "aws_ami_id", parent None, deprecated false, display None,
        description Some("id of an AWS AMI");
    AwsInstanceId = "aws_instance_id", parent None, deprecated false, display None,
        description Some("id of an AWS instance");
    AwsNetworkInterfaceId = "aws_network_interface_id", parent None, deprecated false, display None,
        description Some("eni id");
    AwsPrincipalId = "aws_principal_id", parent None, deprecated false, display None,
        description Some("principal ID for an aws user");
    AwsPrivateDnsName = "aws_private_dns_name", parent None, deprecated false, display None,
        description Some("private DNS Name for an AWS entity");
    AwsSecurityGroupId = "aws_security_group_id", parent None, deprecated false, display None,
        description Some("id of an AWS security group");
    AwsSubnetId = "aws_subnet_id", parent None, deprecated false, display None,
        description Some("AWS subnet id");
    AwsUsername = "aws_username", parent None, deprecated false, display None,
        description Some("username associated with an AWS account");
    AwsVpcId = "aws_vpc_id", parent None, deprecated false, display None,
        description Some("virtual private cloud (VPC) id");
    Cidr = "cidr", parent None, deprecated true, display None,
        description Some("IPv4 range in CIDR notation");
    CommandLine = "command_line", parent None, deprecated false, display None,
        description Some("command line options to a command that was executed");
    CompromisedAccount = "compromised_account", parent None, deprecated false, display None,
        description Some("a username + password that may have been compromised");
    Contact = "contact", parent None, deprecated false, display None,
        description Some("email contact e.g. \"Last, First <email@domain.com>\"");
    Cookie = "cookie", parent None, deprecated false, display None,
        description Some("cookie");
    EmailAddress = "email_address", parent None, deprecated false, display None,
        description Some("email address");
    EmailBody = "email_body", parent None, deprecated false, display None,
        description Some("string from an email body");
    EmailCc = "email_cc", parent Some(ObservableKind::EmailAddress), deprecated false, display Some("Mail CC"),
        description Some("email Cc: header address");
    EmailConversation = "email_conversation", parent None, deprecated false, display None,
        description Some("a conversation between a source email address (MAIL FROM) and a destination email address (RCPT TO)");
    EmailDelivery = "email_delivery", parent None, deprecated false, display None,
        description Some("a delivery of a an email to a target mailbox");
    EmailDkimSigningDomain = "email_dkim_signing_domain", parent Some(ObservableKind::Fqdn), deprecated false, display Some("DKIM Signing Domain"),
        description Some("signing domain (d= tag) from a DKIM-Signature header on the message");
    EmailEnvelopeMailFrom = "email_envelope_mail_from", parent Some(ObservableKind::EmailAddress), deprecated false, display Some("Envelope Mail From"),
        description Some("envelope MAIL FROM address from the SMTP transaction");
    EmailEnvelopeRcptTo = "email_envelope_rcpt_to", parent Some(ObservableKind::EmailAddress), deprecated false, display Some("Envelope Recipient"),
        description Some("envelope RCPT TO address from the SMTP transaction");
    EmailFirstHopFrom = "email_first_hop_from", parent None, deprecated false, display Some("First Hop From"),
        description Some("reverse-DNS host name of the first external Received: hop (the parenthesized rDNS in `from HELO (rdns [ip])`, not the RFC5322 From:); often absent when the hop records only an IP");
    EmailFirstHopHelo = "email_first_hop_helo", parent None, deprecated false, display Some("First Hop HELO/EHLO"),
        description Some("HELO/EHLO string the client presented on the first external Received: hop (the token after `from`, or an explicit helo= tag); may be a host name or an address literal like 127.0.0.1");
    EmailFirstHopIp = "email_first_hop_ip", parent Some(ObservableKind::Ip), deprecated false, display Some("First Hop IP"),
        description Some("sending IP of the first external hop of an RFC822 message (from the configured provider first-hop headers, default Microsoft 365; else the Received: hop accepted by a local domain)");
    EmailFrom = "email_from", parent Some(ObservableKind::EmailAddress), deprecated false, display Some("Mail From"),
        description Some("email From: header address");
    EmailHeader = "email_header", parent None, deprecated false, display None,
        description Some("string from an email header");
    EmailReplyTo = "email_reply_to", parent Some(ObservableKind::EmailAddress), deprecated false, display Some("Mail Reply To"),
        description Some("email Reply-To: header address");
    EmailReturnPath = "email_return_path", parent Some(ObservableKind::EmailAddress), deprecated false, display Some("Mail Return Path"),
        description Some("email Return-Path address");
    EmailSenderTenantId = "email_sender_tenant_id", parent None, deprecated false, display Some("Sender Tenant ID"),
        description Some("tenant GUID of the sending organization (from the configured sender-tenant headers, default Microsoft 365 cross-tenant headers); useful for detecting tenant-relay laundering");
    EmailSubject = "email_subject", parent None, deprecated false, display None,
        description Some("the subject of an email");
    EmailTo = "email_to", parent Some(ObservableKind::EmailAddress), deprecated false, display Some("Mail To"),
        description Some("email To: header address");
    EmailXAuthId = "email_x_auth_id", parent Some(ObservableKind::EmailAddress), deprecated false, display Some("Mail X-Auth ID"),
        description Some("email X-Auth-Id: header address");
    EmailXMailer = "email_x_mailer", parent None, deprecated false, display None,
        description Some("email x-mailer");
    EmailXOriginalSender = "email_x_original_sender", parent Some(ObservableKind::EmailAddress), deprecated false, display Some("Mail X-Original Sender"),
        description Some("email X-Original-Sender: header address");
    EmailXSender = "email_x_sender", parent Some(ObservableKind::EmailAddress), deprecated false, display Some("Mail X-Sender"),
        description Some("email X-Sender: header address");
    EmailXSenderId = "email_x_sender_id", parent Some(ObservableKind::EmailAddress), deprecated false, display Some("Mail X-Sender ID"),
        description Some("email X-Sender-Id: header address");
    ExternalUid = "external_uid", parent None, deprecated false, display None,
        description Some("unique identifier for something that is stored in an external tool. Format: tool_name:uid");
    File = "file", parent None, deprecated false, display None,
        description Some("path to an attached file");
    FileLocation = "file_location", parent None, deprecated false, display None,
        description Some("the location of file with format hostname@full_path");
    FileName = "file_name", parent None, deprecated false, display None,
        description Some("a file name (no directory path)");
    FilePath = "file_path", parent None, deprecated false, display None,
        description Some("a file path");
    FireeyeUuid = "fireeye_uuid", parent None, deprecated false, display None,
        description Some("UUID used to identify a FireEye alert");
    ForumAuthor = "forum_author", parent None, deprecated false, display None,
        description Some("author of forum post (used for intel tracking)");
    ForumChannel = "forum_channel", parent None, deprecated false, display None,
        description Some("channel of forum post (used for intel tracking)");
    ForumChatType = "forum_chat_type", parent None, deprecated false, display None,
        description Some("type of forum post (used for intel tracking)");
    Fqdn = "fqdn", parent None, deprecated false, display None,
        description Some("fully qualified domain name");
    Hostname = "hostname", parent None, deprecated false, display None,
        description Some("host or workstation name");
    HttpRequest = "http_request", parent None, deprecated true, display None,
        description Some("a single HTTP request");
    Hunt = "hunt", parent None, deprecated false, display None,
        description Some("the name of a hunt");
    IdsStreetname = "ids_streetname", parent None, deprecated false, display None,
        description None;
    Imphash = "imphash", parent None, deprecated false, display None,
        description Some("hash of the imported functions of a PE file");
    Indicator = "indicator", parent None, deprecated false, display None,
        description Some("indicator id");
    Ip = "ip", parent None, deprecated false, display None,
        description Some("IP address (version 4 or 6)");
    IpConversation = "ip_conversation", parent None, deprecated false, display None,
        description Some("two F_IP that were communicating formatted as src_dst");
    IpFullConversation = "ip_full_conversation", parent None, deprecated false, display None,
        description Some("two F_IP that were communicating formatted as src_ip!src_port!dest_ip!dest_port");
    Ipv4 = "ipv4", parent None, deprecated false, display None,
        description Some("IP address (version 4)");
    Ipv4Conversation = "ipv4_conversation", parent None, deprecated false, display None,
        description Some("two F_IPV4 that were communicating formatted as aaa.bbb.ccc.ddd_aaa.bbb.ccc.ddd");
    Ipv4FullConversation = "ipv4_full_conversation", parent None, deprecated false, display None,
        description Some("two F_IPV4 that were communicating formatted as src_ipv4:src_port:dest_ipv4:dest_port");
    Ja3 = "ja3", parent None, deprecated false, display None,
        description Some("JA3 TLS client fingerprint hash");
    Ja3s = "ja3s", parent None, deprecated false, display None,
        description Some("JA3S TLS server fingerprint hash");
    Ja4 = "ja4", parent None, deprecated false, display None,
        description Some("JA4 TLS client fingerprint");
    JarmHash = "jarm_hash", parent None, deprecated false, display None,
        description Some("JARM TLS server fingerprint hash");
    MacAddress = "mac_address", parent None, deprecated false, display None,
        description Some("network card mac address");
    Md5 = "md5", parent None, deprecated false, display None,
        description Some("MD5 hash");
    MessageId = "message_id", parent None, deprecated false, display None,
        description Some("email Message-ID");
    Mutex = "mutex", parent None, deprecated false, display None,
        description Some("mutex created during sample execution");
    O365File = "o365_file", parent None, deprecated false, display None,
        description Some("graph api path to a file in o365");
    O365FileConversation = "o365_file_conversation", parent None, deprecated false, display None,
        description Some("two users sharing o365 files");
    O365Group = "o365_group", parent None, deprecated false, display None,
        description Some("graph api id of a group in o365");
    O365SecurityAlert = "o365_security_alert", parent None, deprecated false, display None,
        description Some("The alert uuID");
    PanPcapId = "pan_pcap_id", parent None, deprecated false, display None,
        description Some("PaloAlto PCAP identification");
    Pcap = "pcap", parent None, deprecated true, display None,
        description Some("path to a pcap formatted file *** DEPRECATED (use F_FILE instead)");
    PpCampaignId = "pp_campaign_id", parent None, deprecated false, display None,
        description Some("Proofpoint Campaign ID");
    PpGuid = "pp_guid", parent None, deprecated false, display None,
        description Some("Proofpoint Email GUID");
    PpThreatId = "pp_threat_id", parent None, deprecated false, display None,
        description Some("Proofpoint Threat ID");
    PpTrapIncidentId = "pp_trap_incident_id", parent None, deprecated false, display None,
        description Some("Proofpoint TRAP Incident ID");
    Printer = "printer", parent None, deprecated false, display None,
        description Some("name of a printer");
    ProcessGuid = "process_guid", parent None, deprecated false, display None,
        description Some("globally unique identifier for a process on an endpoint");
    ScanId = "scan_id", parent None, deprecated false, display None,
        description Some("an identifer for a scan by some remote system");
    Sha1 = "sha1", parent None, deprecated false, display None,
        description Some("SHA1 hash");
    Sha256 = "sha256", parent None, deprecated false, display None,
        description Some("SHA256 hash");
    SharepointFile = "sharepoint_file", parent None, deprecated false, display None,
        description Some("sharepoint file path");
    SignatureId = "signature_id", parent None, deprecated false, display None,
        description Some("the UUID of a signature");
    SnortSig = "snort_sig", parent None, deprecated false, display None,
        description Some("snort signature ID");
    StringEps = "string_eps", parent None, deprecated false, display None,
        description Some("string in an eps file");
    StringHtml = "string_html", parent None, deprecated false, display None,
        description Some("string in an html file");
    StringJava = "string_java", parent None, deprecated false, display None,
        description Some("string in java source code");
    StringJs = "string_js", parent None, deprecated false, display None,
        description Some("string in javascript code");
    StringOffice = "string_office", parent None, deprecated false, display None,
        description Some("string in a microsoft office file");
    StringPdf = "string_pdf", parent None, deprecated false, display None,
        description Some("string in a pdf file");
    StringPe = "string_pe", parent None, deprecated false, display None,
        description Some("string in a portable executable file");
    StringRtf = "string_rtf", parent None, deprecated false, display None,
        description Some("string in an rtf file");
    StringSwf = "string_swf", parent None, deprecated false, display None,
        description Some("string in a shockwave/flash file");
    StringUnixShell = "string_unix_shell", parent None, deprecated false, display None,
        description Some("string from unix command line");
    StringVbs = "string_vbs", parent None, deprecated false, display None,
        description Some("string in a vbs file");
    StringWindowsShell = "string_windows_shell", parent None, deprecated false, display None,
        description Some("string from windows command line");
    SuspectFile = "suspect_file", parent None, deprecated true, display None,
        description Some("path to an attached file that might be malicious *** DEPRECATED (use directives instead)");
    Test = "test", parent None, deprecated false, display None,
        description Some("unit testing observable");
    UriPath = "uri_path", parent None, deprecated false, display None,
        description Some("URI path from a URL");
    Url = "url", parent None, deprecated false, display None,
        description Some("a URL");
    User = "user", parent None, deprecated false, display None,
        description Some("an NT user ID identified to have used a given asset in the given period of time");
    UserAgent = "user_agent", parent None, deprecated false, display None,
        description Some("user agent used in web requests");
    WindowsRegistry = "windows_registry", parent None, deprecated false, display None,
        description Some("a windows registry key");
    WindowsService = "windows_service", parent None, deprecated false, display None,
        description Some("name of a windows service");
    Yara = "yara", parent None, deprecated true, display None,
        description Some("yara scan result *** DEPRECATED (use F_YARA_RULE instead)");
    YaraRule = "yara_rule", parent None, deprecated false, display None,
        description Some("yara rule name");
    YaraString = "yara_string", parent None, deprecated false, display None,
        description Some("yara rule and string name");
}

impl ObservableKind {
    /// A kind of a site's own, for its binary's list (`install_types`).
    pub const fn define(info: &'static ObservableType) -> ObservableKind {
        ObservableKind(info)
    }

    /// The kind's name, as ace3 spells it.
    pub const fn as_str(self) -> &'static str {
        self.0.name
    }

    /// The kind this one extends. A module that accepts the parent also accepts this kind.
    pub const fn parent(self) -> Option<ObservableKind> {
        self.0.parent
    }

    /// Recognized, but not offered to analysts.
    pub const fn is_deprecated(self) -> bool {
        self.0.deprecated
    }

    /// The label shown when nothing sets one on the observable.
    pub const fn default_display_type(self) -> Option<&'static str> {
        self.0.default_display_type
    }

    pub const fn description(self) -> Option<&'static str> {
        self.0.description
    }

    /// The kinds this one extends, nearest first.
    pub fn ancestors(self) -> impl Iterator<Item = ObservableKind> {
        std::iter::successors(self.parent(), |kind| kind.parent())
    }

    /// True when `self` is `other` or extends it, directly or through other kinds.
    pub fn is_subtype_of(self, other: ObservableKind) -> bool {
        self == other || self.ancestors().any(|kind| kind == other)
    }

    /// This process's kinds in name order: the list `install_types` installed, or `BUILTIN`, with
    /// what a types file added (`merge_file_types`), as they are now.
    pub fn all() -> Arc<Vec<ObservableKind>> {
        let current = CURRENT
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        current.unwrap_or_else(|| builtin().clone())
    }

    /// How many times this process's kinds changed since it started, for what is made of them (a
    /// result's schema) to be made again when they do.
    pub fn generation() -> u64 {
        GENERATION.load(AtomicOrdering::Acquire)
    }
}

/// The list `install_types` installed: the binary's own, which a types file never changes.
static INSTALLED: OnceLock<Vec<ObservableKind>> = OnceLock::new();
/// The binary's list and a types file's, as they are now; None until either is set.
static CURRENT: RwLock<Option<Arc<Vec<ObservableKind>>>> = RwLock::new(None);
static GENERATION: AtomicU64 = AtomicU64::new(0);

fn builtin() -> &'static Arc<Vec<ObservableKind>> {
    static BUILTIN_LIST: OnceLock<Arc<Vec<ObservableKind>>> = OnceLock::new();
    BUILTIN_LIST.get_or_init(|| Arc::new(ObservableKind::BUILTIN.to_vec()))
}

fn set_current(list: Vec<ObservableKind>) {
    *CURRENT
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(list));
    GENERATION.fetch_add(1, AtomicOrdering::AcqRel);
}

/// One type as ace3's `observable_types.yaml` writes it under `types:`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct FileType {
    pub extends: Option<String>,
    pub default_display_type: Option<String>,
    pub description: Option<String>,
    pub deprecated: bool,
}

/// What `merge_file_types` did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileTypesMerged {
    /// Types the file added.
    pub added: Vec<String>,
    /// Types the file had added before whose entry changed.
    pub changed: Vec<String>,
    /// Entries left out, with why: a bad name, or a parent that isn't a type.
    pub refused: Vec<(String, String)>,
}

/// A types file's entries, as ace3's type hierarchy reads them, merged into this process's kinds:
/// each type the binary lacks is added, with its parent, display type, description and deprecated
/// flag, and a type the file added before takes its entry's new values. A type the binary has is the
/// binary's: the file can't change it. A type the file no longer lists stays, since rows may hold it,
/// until the process restarts. An entry whose name isn't lowercase letters, digits and `_`, or whose
/// parent is neither a type nor another entry, is left out. Each new or changed definition lives for
/// the process (they are few, and change rarely).
pub fn merge_file_types(entries: &BTreeMap<String, FileType>) -> FileTypesMerged {
    let base: Vec<ObservableKind> = INSTALLED
        .get()
        .cloned()
        .unwrap_or_else(|| ObservableKind::BUILTIN.to_vec());
    let current = ObservableKind::all();
    let mut list: Vec<ObservableKind> = current.as_ref().clone();
    let mut merged = FileTypesMerged::default();
    let valid = |name: &str| {
        name.starts_with(|c: char| c.is_ascii_lowercase())
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    };
    let mut pending: Vec<(&String, &FileType)> = Vec::new();
    for (name, entry) in entries {
        if base.iter().any(|k| k.as_str() == name) {
            continue;
        }
        if !valid(name) {
            merged.refused.push((
                name.clone(),
                "isn't lowercase letters, digits and _".to_owned(),
            ));
            continue;
        }
        pending.push((name, entry));
    }
    // a parent first: each round places the entries whose parent is placed, until none is left or
    // a round places nothing (an unknown parent, or a cycle)
    loop {
        let before = pending.len();
        pending.retain(|&(name, entry)| {
            let parent = match &entry.extends {
                None => None,
                // a parent that is the type itself, or has it among its ancestors, would make a
                // cycle that `ancestors` never leaves
                Some(parent) => match list.iter().find(|k| k.as_str() == parent) {
                    Some(&kind)
                        if kind.as_str() != name.as_str()
                            && !kind
                                .ancestors()
                                .take(64)
                                .any(|a| a.as_str() == name.as_str()) =>
                    {
                        Some(kind)
                    }
                    _ => return true,
                },
            };
            let wanted = ObservableType {
                name: "",
                parent,
                deprecated: entry.deprecated,
                default_display_type: None,
                description: None,
            };
            let known = list.iter().position(|k| k.as_str() == name.as_str());
            let same = known.is_some_and(|i| {
                let k = list[i];
                k.parent() == wanted.parent
                    && k.is_deprecated() == wanted.deprecated
                    && k.default_display_type() == entry.default_display_type.as_deref()
                    && k.description() == entry.description.as_deref()
            });
            if !same {
                let leak = |text: &Option<String>| -> Option<&'static str> {
                    text.clone().map(|t| &*Box::leak(t.into_boxed_str()))
                };
                let kind = ObservableKind::define(Box::leak(Box::new(ObservableType {
                    name: Box::leak(name.clone().into_boxed_str()),
                    parent,
                    deprecated: entry.deprecated,
                    default_display_type: leak(&entry.default_display_type),
                    description: leak(&entry.description),
                })));
                match known {
                    Some(i) => {
                        list[i] = kind;
                        merged.changed.push(name.clone());
                    }
                    None => {
                        list.push(kind);
                        merged.added.push(name.clone());
                    }
                }
            }
            false
        });
        if pending.is_empty() || pending.len() == before {
            break;
        }
    }
    for (name, entry) in pending {
        merged.refused.push((
            name.clone(),
            format!(
                "extends {}, which is neither a type nor another of the file's (or a cycle)",
                entry.extends.as_deref().unwrap_or("?")
            ),
        ));
    }
    if !merged.added.is_empty() || !merged.changed.is_empty() {
        list.sort();
        set_current(list);
    }
    merged
}

/// Why a binary's list of kinds is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TypeListError {
    #[error("observable type {0:?} isn't lowercase letters, digits and _")]
    BadName(&'static str),
    #[error("observable type {0} is listed twice")]
    Duplicate(&'static str),
    #[error("observable type {kind} extends {parent}, which isn't in the list")]
    UnknownParent {
        kind: &'static str,
        parent: &'static str,
    },
    #[error("this process already installed a different list of observable types")]
    AlreadyInstalled,
}

/// The built-in kinds and `extra`, in name order, after checking that every name is valid and
/// listed once and every parent is in the list.
pub fn type_list(extra: &[ObservableKind]) -> Result<Vec<ObservableKind>, TypeListError> {
    let mut list: Vec<ObservableKind> = ObservableKind::BUILTIN.to_vec();
    for kind in extra {
        let name = kind.as_str();
        let valid = name.starts_with(|c: char| c.is_ascii_lowercase())
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
        if !valid {
            return Err(TypeListError::BadName(name));
        }
        if list.contains(kind) {
            return Err(TypeListError::Duplicate(name));
        }
        list.push(*kind);
    }
    for kind in &list {
        if let Some(parent) = kind.parent()
            && !list.contains(&parent)
        {
            return Err(TypeListError::UnknownParent {
                kind: kind.as_str(),
                parent: parent.as_str(),
            });
        }
    }
    list.sort();
    Ok(list)
}

/// Makes this process's kinds the built-in ones plus `extra`. `ace-app` calls it once, first
/// thing in `main`; calling it again with the same list does nothing, and with another fails.
pub fn install_types(extra: &[ObservableKind]) -> Result<(), TypeListError> {
    let list = type_list(extra)?;
    let mut fresh = false;
    let installed = INSTALLED.get_or_init(|| {
        fresh = true;
        list.clone()
    });
    if fresh {
        set_current(list);
        return Ok(());
    }
    if *installed == list {
        Ok(())
    } else {
        Err(TypeListError::AlreadyInstalled)
    }
}

impl PartialEq for ObservableKind {
    fn eq(&self, other: &Self) -> bool {
        self.0.name == other.0.name
    }
}

impl Eq for ObservableKind {}

impl PartialOrd for ObservableKind {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ObservableKind {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0.name.cmp(other.0.name)
    }
}

impl Hash for ObservableKind {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.name.hash(state);
    }
}

impl fmt::Debug for ObservableKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ObservableKind").field(&self.0.name).finish()
    }
}

impl fmt::Display for ObservableKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for ObservableKind {
    type Err = UnknownObservableKind;

    /// The kind of this binary's list with this name.
    fn from_str(name: &str) -> Result<Self, Self::Err> {
        ObservableKind::all()
            .iter()
            .find(|kind| kind.as_str() == name)
            .copied()
            .ok_or_else(|| UnknownObservableKind(name.to_owned()))
    }
}

impl Serialize for ObservableKind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ObservableKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = Cow::<'de, str>::deserialize(deserializer)?;
        name.parse().map_err(serde::de::Error::custom)
    }
}

impl JsonSchema for ObservableKind {
    fn schema_name() -> Cow<'static, str> {
        "ObservableKind".into()
    }

    /// A string naming one of this binary's kinds.
    fn json_schema(_: &mut SchemaGenerator) -> Schema {
        let names: Vec<&str> = ObservableKind::all().iter().map(|k| k.as_str()).collect();
        json_schema!({
            "description": "The type of an observable, named as in ace3 (`ipv4`, `email_address`, `file`).",
            "type": "string",
            "enum": names,
        })
    }
}

/// A name that isn't one of this binary's observable types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownObservableKind(pub String);

impl fmt::Display for UnknownObservableKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown observable type {:?}", self.0)
    }
}

impl std::error::Error for UnknownObservableKind {}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_type(extends: Option<&str>, display: Option<&str>) -> FileType {
        FileType {
            extends: extends.map(str::to_owned),
            default_display_type: display.map(str::to_owned),
            description: None,
            deprecated: false,
        }
    }

    /// PLAN.md decision 66: a types file adds the types the binary lacks, a parent before its
    /// child, takes a changed entry, leaves the binary's own as they are and refuses what can't be
    /// a type, a cycle included; each change moves the generation.
    #[test]
    fn a_types_file_adds_and_changes_its_own_types() {
        let before = ObservableKind::generation();
        let entries: BTreeMap<String, FileType> = [
            (
                "zz_file_child".to_owned(),
                file_type(Some("zz_file_parent"), None),
            ),
            (
                "zz_file_parent".to_owned(),
                file_type(Some("fqdn"), Some("Parent")),
            ),
            ("fqdn".to_owned(), file_type(None, Some("not the binary's"))),
            ("Bad-Name".to_owned(), file_type(None, None)),
            (
                "zz_file_orphan".to_owned(),
                file_type(Some("zz_no_such_type"), None),
            ),
            (
                "zz_file_loop_a".to_owned(),
                file_type(Some("zz_file_loop_b"), None),
            ),
            (
                "zz_file_loop_b".to_owned(),
                file_type(Some("zz_file_loop_a"), None),
            ),
        ]
        .into_iter()
        .collect();
        let merged = merge_file_types(&entries);
        assert_eq!(merged.added, ["zz_file_parent", "zz_file_child"]);
        let refused: Vec<&str> = merged.refused.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(
            refused,
            [
                "Bad-Name",
                "zz_file_loop_a",
                "zz_file_loop_b",
                "zz_file_orphan"
            ]
        );
        assert!(ObservableKind::generation() > before);
        let child: ObservableKind = "zz_file_child".parse().expect("a type now");
        assert!(
            child.is_subtype_of(ObservableKind::Fqdn),
            "through its parent"
        );
        assert_eq!(
            ObservableKind::Fqdn.default_display_type(),
            ObservableKind::BUILTIN
                .iter()
                .find(|k| k.as_str() == "fqdn")
                .and_then(|k| k.default_display_type()),
            "the binary's own type is the binary's"
        );
        // the same file again changes nothing; a changed entry is taken
        let again = merge_file_types(&entries);
        assert!(again.added.is_empty() && again.changed.is_empty());
        let mut changed = entries.clone();
        changed.insert(
            "zz_file_parent".to_owned(),
            file_type(Some("fqdn"), Some("Renamed")),
        );
        assert_eq!(merge_file_types(&changed).changed, ["zz_file_parent"]);
        let parent: ObservableKind = "zz_file_parent".parse().expect("a type");
        assert_eq!(parent.default_display_type(), Some("Renamed"));
        // a type the file no longer lists stays, since rows may hold it
        let none = merge_file_types(&BTreeMap::new());
        assert!(none.added.is_empty() && none.changed.is_empty());
        assert!("zz_file_child".parse::<ObservableKind>().is_ok());
    }
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Fixture {
        types: Vec<FixtureType>,
    }

    #[derive(Deserialize)]
    struct FixtureType {
        name: String,
        extends: Option<String>,
        description: Option<String>,
        deprecated: bool,
        default_display_type: Option<String>,
    }

    fn fixture() -> Vec<FixtureType> {
        let text = include_str!("../fixtures/ace3_observable_types.json");
        let fixture: Fixture = serde_json::from_str(text).expect("the fixture is valid JSON");
        fixture.types
    }

    #[test]
    fn builtin_kinds_match_ace3_fixture() {
        let fixture = fixture();
        let fixture_names: Vec<&str> = fixture.iter().map(|t| t.name.as_str()).collect();
        let enum_names: Vec<&str> = ObservableKind::BUILTIN.iter().map(|k| k.as_str()).collect();
        assert_eq!(
            enum_names, fixture_names,
            "the enum's kinds differ from ace3's"
        );

        for expected in &fixture {
            let kind: ObservableKind = expected.name.parse().expect("every fixture name parses");
            assert_eq!(kind.as_str(), expected.name);
            assert_eq!(
                kind.parent().map(ObservableKind::as_str),
                expected.extends.as_deref(),
                "parent of {kind}"
            );
            assert_eq!(
                kind.is_deprecated(),
                expected.deprecated,
                "deprecated flag of {kind}"
            );
            assert_eq!(
                kind.default_display_type(),
                expected.default_display_type.as_deref(),
                "default display type of {kind}"
            );
            assert_eq!(
                kind.description(),
                expected.description.as_deref(),
                "description of {kind}"
            );
            // serde uses the same names
            let json = serde_json::to_value(kind).expect("a kind serializes");
            assert_eq!(json, serde_json::Value::String(expected.name.clone()));
            let back: ObservableKind = serde_json::from_value(json).expect("a kind deserializes");
            assert_eq!(back, kind);
        }
    }

    #[test]
    fn unknown_names_are_rejected() {
        assert_eq!(
            "not_a_type".parse::<ObservableKind>(),
            Err(UnknownObservableKind("not_a_type".to_owned()))
        );
        let err = serde_json::from_str::<ObservableKind>("\"IPV4\"").unwrap_err();
        assert!(
            err.to_string().contains("unknown observable type \"IPV4\""),
            "{err}"
        );
    }

    #[test]
    fn subtypes_follow_parents() {
        type K = ObservableKind;
        assert!(K::EmailFrom.is_subtype_of(K::EmailAddress));
        assert!(K::EmailFirstHopIp.is_subtype_of(K::Ip));
        assert!(K::EmailDkimSigningDomain.is_subtype_of(K::Fqdn));
        assert!(K::Fqdn.is_subtype_of(K::Fqdn));
        assert!(!K::EmailAddress.is_subtype_of(K::EmailFrom));
        assert!(
            !K::Ipv4.is_subtype_of(K::Ip),
            "ace3 doesn't make ipv4 extend ip"
        );
    }

    const SITE_ACCOUNT: ObservableKind = ObservableKind::define(&ObservableType {
        name: "site_account",
        parent: None,
        deprecated: false,
        default_display_type: Some("Site Account"),
        description: Some("an account in a site's own system"),
    });

    const SITE_ADMIN: ObservableKind = ObservableKind::define(&ObservableType {
        name: "site_admin",
        parent: Some(SITE_ACCOUNT),
        deprecated: false,
        default_display_type: None,
        description: None,
    });

    const fn named(name: &'static str, parent: Option<ObservableKind>) -> ObservableType {
        ObservableType {
            name,
            parent,
            deprecated: false,
            default_display_type: None,
            description: None,
        }
    }

    #[test]
    fn a_sites_kinds_join_the_builtin_ones_in_name_order() {
        let list = type_list(&[SITE_ADMIN, SITE_ACCOUNT]).expect("a valid list");
        assert_eq!(list.len(), ObservableKind::BUILTIN.len() + 2);
        assert!(list.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(list.contains(&SITE_ACCOUNT) && list.contains(&ObservableKind::Fqdn));
        assert!(SITE_ADMIN.is_subtype_of(SITE_ACCOUNT));
        assert_eq!(SITE_ADMIN.parent(), Some(SITE_ACCOUNT));
        // a parent from the built-in list is fine too
        static DOMAIN: ObservableType = named("site_domain", Some(ObservableKind::Fqdn));
        assert!(type_list(&[ObservableKind::define(&DOMAIN)]).is_ok());
    }

    #[test]
    fn a_bad_list_is_refused() {
        assert_eq!(
            type_list(&[SITE_ADMIN]),
            Err(TypeListError::UnknownParent {
                kind: "site_admin",
                parent: "site_account",
            })
        );
        assert_eq!(
            type_list(&[SITE_ACCOUNT, SITE_ACCOUNT]),
            Err(TypeListError::Duplicate("site_account"))
        );
        static FQDN: ObservableType = named("fqdn", None);
        assert_eq!(
            type_list(&[ObservableKind::define(&FQDN)]),
            Err(TypeListError::Duplicate("fqdn"))
        );
        static UPPER: ObservableType = named("Site", None);
        assert_eq!(
            type_list(&[ObservableKind::define(&UPPER)]),
            Err(TypeListError::BadName("Site"))
        );
    }
}
