//! Observable kinds.
//!
//! The kinds are a closed enum built from ace3's observable types, so nothing registers a type at
//! run time (ace3 #1030). `fixtures/ace3_observable_types.json` is ace3's list, dumped by
//! `tools/ace3/dumps/observable_types.py`, and a test checks this enum against it: names, parents,
//! deprecated flags, default display types and descriptions.

use std::fmt;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

macro_rules! observable_kinds {
    ($(
        $variant:ident = $name:literal, parent $parent:expr, deprecated $deprecated:literal,
            display $display:expr, description $description:expr;
    )+) => {
        /// The type of an observable, named as in ace3 (`ipv4`, `email_address`, `file`).
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
        )]
        pub enum ObservableKind {
            $(
                #[serde(rename = $name)]
                $variant,
            )+
        }

        impl ObservableKind {
            /// Every kind, in name order.
            pub const ALL: &'static [ObservableKind] = &[$(ObservableKind::$variant),+];

            /// The kind's name, as ace3 spells it.
            pub const fn as_str(self) -> &'static str {
                match self {
                    $(ObservableKind::$variant => $name,)+
                }
            }

            /// The kind this one extends, from ace3's `etc/observable_types.yaml`. A module that
            /// accepts the parent also accepts this kind.
            pub const fn parent(self) -> Option<ObservableKind> {
                use ObservableKind::*;
                match self {
                    $($variant => $parent,)+
                }
            }

            /// Recognized, but not offered to analysts.
            pub const fn is_deprecated(self) -> bool {
                match self {
                    $(ObservableKind::$variant => $deprecated,)+
                }
            }

            /// The label shown when nothing sets one on the observable.
            pub const fn default_display_type(self) -> Option<&'static str> {
                match self {
                    $(ObservableKind::$variant => $display,)+
                }
            }

            pub const fn description(self) -> Option<&'static str> {
                match self {
                    $(ObservableKind::$variant => $description,)+
                }
            }
        }

        impl FromStr for ObservableKind {
            type Err = UnknownObservableKind;

            fn from_str(name: &str) -> Result<Self, Self::Err> {
                match name {
                    $($name => Ok(ObservableKind::$variant),)+
                    _ => Err(UnknownObservableKind(name.to_owned())),
                }
            }
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
    EmailCc = "email_cc", parent Some(EmailAddress), deprecated false, display Some("Mail CC"),
        description Some("email Cc: header address");
    EmailConversation = "email_conversation", parent None, deprecated false, display None,
        description Some("a conversation between a source email address (MAIL FROM) and a destination email address (RCPT TO)");
    EmailDelivery = "email_delivery", parent None, deprecated false, display None,
        description Some("a delivery of a an email to a target mailbox");
    EmailDkimSigningDomain = "email_dkim_signing_domain", parent Some(Fqdn), deprecated false, display Some("DKIM Signing Domain"),
        description Some("signing domain (d= tag) from a DKIM-Signature header on the message");
    EmailEnvelopeMailFrom = "email_envelope_mail_from", parent Some(EmailAddress), deprecated false, display Some("Envelope Mail From"),
        description Some("envelope MAIL FROM address from the SMTP transaction");
    EmailEnvelopeRcptTo = "email_envelope_rcpt_to", parent Some(EmailAddress), deprecated false, display Some("Envelope Recipient"),
        description Some("envelope RCPT TO address from the SMTP transaction");
    EmailFirstHopFrom = "email_first_hop_from", parent None, deprecated false, display Some("First Hop From"),
        description Some("reverse-DNS host name of the first external Received: hop (the parenthesized rDNS in `from HELO (rdns [ip])`, not the RFC5322 From:); often absent when the hop records only an IP");
    EmailFirstHopHelo = "email_first_hop_helo", parent None, deprecated false, display Some("First Hop HELO/EHLO"),
        description Some("HELO/EHLO string the client presented on the first external Received: hop (the token after `from`, or an explicit helo= tag); may be a host name or an address literal like 127.0.0.1");
    EmailFirstHopIp = "email_first_hop_ip", parent Some(Ip), deprecated false, display Some("First Hop IP"),
        description Some("sending IP of the first external hop of an RFC822 message (from the configured provider first-hop headers, default Microsoft 365; else the Received: hop accepted by a local domain)");
    EmailFrom = "email_from", parent Some(EmailAddress), deprecated false, display Some("Mail From"),
        description Some("email From: header address");
    EmailHeader = "email_header", parent None, deprecated false, display None,
        description Some("string from an email header");
    EmailReplyTo = "email_reply_to", parent Some(EmailAddress), deprecated false, display Some("Mail Reply To"),
        description Some("email Reply-To: header address");
    EmailReturnPath = "email_return_path", parent Some(EmailAddress), deprecated false, display Some("Mail Return Path"),
        description Some("email Return-Path address");
    EmailSenderTenantId = "email_sender_tenant_id", parent None, deprecated false, display Some("Sender Tenant ID"),
        description Some("tenant GUID of the sending organization (from the configured sender-tenant headers, default Microsoft 365 cross-tenant headers); useful for detecting tenant-relay laundering");
    EmailSubject = "email_subject", parent None, deprecated false, display None,
        description Some("the subject of an email");
    EmailTo = "email_to", parent Some(EmailAddress), deprecated false, display Some("Mail To"),
        description Some("email To: header address");
    EmailXAuthId = "email_x_auth_id", parent Some(EmailAddress), deprecated false, display Some("Mail X-Auth ID"),
        description Some("email X-Auth-Id: header address");
    EmailXMailer = "email_x_mailer", parent None, deprecated false, display None,
        description Some("email x-mailer");
    EmailXOriginalSender = "email_x_original_sender", parent Some(EmailAddress), deprecated false, display Some("Mail X-Original Sender"),
        description Some("email X-Original-Sender: header address");
    EmailXSender = "email_x_sender", parent Some(EmailAddress), deprecated false, display Some("Mail X-Sender"),
        description Some("email X-Sender: header address");
    EmailXSenderId = "email_x_sender_id", parent Some(EmailAddress), deprecated false, display Some("Mail X-Sender ID"),
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
    /// The kinds this one extends, nearest first.
    pub fn ancestors(self) -> impl Iterator<Item = ObservableKind> {
        std::iter::successors(self.parent(), |kind| kind.parent())
    }

    /// True when `self` is `other` or extends it, directly or through other kinds.
    pub fn is_subtype_of(self, other: ObservableKind) -> bool {
        self == other || self.ancestors().any(|kind| kind == other)
    }
}

impl fmt::Display for ObservableKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A name that isn't one of ace3's observable types.
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
    fn enum_matches_ace3_fixture() {
        let fixture = fixture();
        let fixture_names: Vec<&str> = fixture.iter().map(|t| t.name.as_str()).collect();
        let enum_names: Vec<&str> = ObservableKind::ALL.iter().map(|k| k.as_str()).collect();
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
        assert!(err.to_string().contains("unknown variant"), "{err}");
    }

    #[test]
    fn subtypes_follow_parents() {
        use ObservableKind::*;
        assert!(EmailFrom.is_subtype_of(EmailAddress));
        assert!(EmailFirstHopIp.is_subtype_of(Ip));
        assert!(EmailDkimSigningDomain.is_subtype_of(Fqdn));
        assert!(Fqdn.is_subtype_of(Fqdn));
        assert!(!EmailAddress.is_subtype_of(EmailFrom));
        assert!(!Ipv4.is_subtype_of(Ip), "ace3 doesn't make ipv4 extend ip");
    }
}
