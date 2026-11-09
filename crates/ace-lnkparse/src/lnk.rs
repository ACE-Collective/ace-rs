//! `LnkParse3.lnk_file`, `get_json(get_all=True)` and `lnk_command`, step by step as LnkParse3
//! 1.6.0 runs them, so each `struct.error`, `IndexError` or `RuntimeError` comes from the same
//! read. Python slices clamp to the data, so every read here goes through [`sl`].

use sha2::{Digest, Sha256};

use crate::PyError;
use crate::text::{read_string, read_strings, read_unicode_string, unicode_len};
use crate::time::{dostime, filetime};
use crate::value::{Dict, PyValue};

const OPEN: u64 = u64::MAX;

/// The decoded text, in bytes scanned, that the property store of one file may produce before
/// the crate gives up with `MemoryError`. Overlapping property values can make Python decode
/// the same bytes over and over, which grows with the square of the input.
const METADATA_TEXT_BUDGET: u64 = 256 << 20;

/// `b[start:end]` with Python's clamping.
fn sl(b: &[u8], start: u64, end: u64) -> &[u8] {
    let len = b.len() as u64;
    let s = start.min(len);
    let e = end.min(len);
    if s >= e {
        &[]
    } else {
        // Both are at most b.len().
        #[allow(clippy::cast_possible_truncation)]
        &b[s as usize..e as usize]
    }
}

fn take<const N: usize>(b: &[u8]) -> Result<[u8; N], PyError> {
    b.try_into().map_err(|_| PyError::struct_error(N))
}

fn u8_at(b: &[u8], s: u64) -> Result<u8, PyError> {
    Ok(take::<1>(sl(b, s, s + 1))?[0])
}

fn u16_at(b: &[u8], s: u64) -> Result<u16, PyError> {
    Ok(u16::from_le_bytes(take(sl(b, s, s + 2))?))
}

fn u32_at(b: &[u8], s: u64) -> Result<u32, PyError> {
    Ok(u32::from_le_bytes(take(sl(b, s, s + 4))?))
}

fn i16_at(b: &[u8], s: u64) -> Result<i16, PyError> {
    Ok(i16::from_le_bytes(take(sl(b, s, s + 2))?))
}

fn i32_at(b: &[u8], s: u64) -> Result<i32, PyError> {
    Ok(i32::from_le_bytes(take(sl(b, s, s + 4))?))
}

fn hex(v: u32) -> String {
    format!("{v:#x}")
}

/// `utils.parse_uuid`.
fn parse_uuid(b: &[u8]) -> Result<String, PyError> {
    let a: [u8; 8] = take(sl(b, 0, 8))?;
    let c: [u8; 8] = take(sl(b, 8, 16))?;
    let d1 = u32::from_le_bytes([a[0], a[1], a[2], a[3]]);
    let d2 = u16::from_le_bytes([a[4], a[5]]);
    let d3 = u16::from_le_bytes([a[6], a[7]]);
    let d4 = u16::from_be_bytes([c[0], c[1]]);
    let d51 = u16::from_be_bytes([c[2], c[3]]);
    let d52 = u32::from_be_bytes([c[4], c[5], c[6], c[7]]);
    Ok(format!(
        "{d1:08X}-{d2:04X}-{d3:04X}-{d4:04X}-{d51:04X}{d52:08X}"
    ))
}

fn sha256_hex(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

struct Ctx {
    metadata_text: u64,
}

impl Ctx {
    fn charge(&mut self, n: usize) -> Result<(), PyError> {
        self.metadata_text = self.metadata_text.saturating_add(n as u64 + 1);
        if self.metadata_text > METADATA_TEXT_BUDGET {
            return Err(PyError::new("MemoryError", ""));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// Header

const LINK_FLAGS: [&str; 27] = [
    "HasTargetIDList",
    "HasLinkInfo",
    "HasName",
    "HasRelativePath",
    "HasWorkingDir",
    "HasArguments",
    "HasIconLocation",
    "IsUnicode",
    "ForceNoLinkInfo",
    "HasExpString",
    "RunInSeparateProcess",
    "Reserved0",
    "HasDarwinID",
    "RunAsUser",
    "HasExpIcon",
    "NoPidlAlias",
    "Reserved1",
    "RunWithShimLayer",
    "ForceNoLinkTrack",
    "EnableTargetMetadata",
    "DisableLinkPathTracking",
    "DisableKnownFolderTracking",
    "DisableKnownFolderAlias",
    "AllowLinkToLink",
    "UnaliasOnSave",
    "PreferEnvironmentPath",
    "KeepLocalIDListForUNCTarget",
];

const FILE_FLAGS: [&str; 18] = [
    "FILE_ATTRIBUTE_READONLY",
    "FILE_ATTRIBUTE_HIDDEN",
    "FILE_ATTRIBUTE_SYSTEM",
    "Reserved, not used by the LNK format",
    "FILE_ATTRIBUTE_DIRECTORY",
    "FILE_ATTRIBUTE_ARCHIVE",
    "FILE_ATTRIBUTE_DEVICE",
    "FILE_ATTRIBUTE_NORMAL",
    "FILE_ATTRIBUTE_TEMPORARY",
    "FILE_ATTRIBUTE_SPARSE_FILE",
    "FILE_ATTRIBUTE_REPARSE_POINT",
    "FILE_ATTRIBUTE_COMPRESSED",
    "FILE_ATTRIBUTE_OFFLINE",
    "FILE_ATTRIBUTE_NOT_CONTENT_INDEXED",
    "FILE_ATTRIBUTE_ENCRYPTED",
    "FILE_ATTRIBUTE_INTEGRITY_STREAM",
    "FILE_ATTRIBUTE_VIRTUAL",
    "FILE_ATTRIBUTE_NO_SCRUB_DATA",
];

fn flag_names(flags: u32, names: &[&str]) -> PyValue {
    PyValue::List(
        names
            .iter()
            .enumerate()
            .filter(|(i, _)| flags & (1 << i) != 0)
            .map(|(_, n)| PyValue::from(*n))
            .collect(),
    )
}

fn hotkey_low(b: u8) -> Option<String> {
    Some(match b {
        0x00 => "UNSET".to_owned(),
        0x30..=0x39 | 0x41..=0x5A => char::from(b).to_string(),
        0x70..=0x87 => format!("F{}", b - 0x6F),
        0x90 => "NUM_LOCK".to_owned(),
        0x91 => "SCROLL_LOCK".to_owned(),
        _ => return None,
    })
}

fn hotkey_high(b: u8) -> Option<&'static str> {
    Some(match b {
        0 => "UNSET",
        1 => "SHIFT",
        2 => "CONTROL",
        4 => "ALT",
        _ => return None,
    })
}

struct Header<'a> {
    raw: &'a [u8],
}

impl<'a> Header<'a> {
    fn new(data: &'a [u8]) -> Result<Self, PyError> {
        if data.is_empty() {
            return Err(PyError::new(
                "LnkParserError",
                "Both `LnkHeader` arguments `fhandle` and `indata` are evalued as `None`",
            ));
        }
        let size = u32_at(data, 0)?;
        Ok(Self {
            raw: sl(data, 0, u64::from(size)),
        })
    }

    fn size(&self) -> Result<u32, PyError> {
        u32_at(self.raw, 0)
    }

    fn r_link_flags(&self) -> Result<u32, PyError> {
        u32_at(self.raw, 20)
    }

    fn filetime(&self, s: u64) -> Result<PyValue, PyError> {
        let t = i64::from_le_bytes(take(sl(self.raw, s, s + 8))?);
        Ok(filetime(t).into())
    }

    fn hot_key(&self) -> Result<String, PyError> {
        let [low, high] = take::<2>(sl(self.raw, 64, 66))?;
        let text = format!("{low:02x}{high:02x}");
        Ok(match (hotkey_high(high), hotkey_low(low)) {
            (Some(h), Some(l)) => format!("{h} - {l} {{0x{text}}}"),
            _ => text,
        })
    }

    fn as_dict(&self) -> Result<Dict, PyError> {
        let r = self.raw;
        let mut d = Dict::new();
        d.set("guid", parse_uuid(sl(r, 4, 20))?.into());
        d.set("r_link_flags", self.r_link_flags()?.into());
        d.set("r_file_flags", u32_at(r, 24)?.into());
        d.set("creation_time", self.filetime(28)?);
        d.set("accessed_time", self.filetime(36)?);
        d.set("modified_time", self.filetime(44)?);
        d.set("file_size", u32_at(r, 52)?.into());
        d.set("icon_index", i32_at(r, 56)?.into());
        let style = match i32_at(r, 60)? {
            3 => "SW_SHOWMAXIMIZED",
            7 => "SW_SHOWMINNOACTIVE",
            _ => "SW_SHOWNORMAL",
        };
        d.set("windowstyle", style.into());
        d.set("hotkey", self.hot_key()?.into());
        d.set("r_hotkey", u16_at(r, 64)?.into());
        d.set("link_flags", flag_names(self.r_link_flags()?, &LINK_FLAGS));
        d.set("file_flags", flag_names(u32_at(r, 24)?, &FILE_FLAGS));
        d.set("header_size", self.size()?.into());
        d.set("reserved0", u16_at(r, 66)?.into());
        d.set("reserved1", u32_at(r, 68)?.into());
        d.set("reserved2", u32_at(r, 72)?.into());
        Ok(d)
    }
}

// ---------------------------------------------------------------------------------------------
// Shell items (LinkTargetIDList and the ShellItem extra block)

#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    ControlPanelCpl,
    ControlPanelCategory,
    RootFolder,
    MyComputer,
    ShellFsFolder,
    NetworkLocation,
    CompressedFolder,
    Internet,
    ControlPanel,
    Printers,
    CommonPlacesFolder,
    UsersFilesFolder,
    Unknown,
}

fn target_class(item_type: u8) -> Target {
    let masked = item_type & 0x70;
    let t = if matches!(masked, 0x20 | 0x30 | 0x40) {
        masked
    } else {
        item_type
    };
    match t {
        0x00 => Target::ControlPanelCpl,
        0x01 => Target::ControlPanelCategory,
        0x1E | 0x1F => Target::RootFolder,
        0x20 => Target::MyComputer,
        0x30 => Target::ShellFsFolder,
        0x40 => Target::NetworkLocation,
        0x52 => Target::CompressedFolder,
        0x61 => Target::Internet,
        0x70 | 0x71 => Target::ControlPanel,
        0x72 => Target::Printers,
        0x73 => Target::CommonPlacesFolder,
        0x74 => Target::UsersFilesFolder,
        _ => Target::Unknown,
    }
}

fn shell_fs_folder_name(flags: u8) -> &'static str {
    const NAMES: [(u8, &str); 8] = [
        (0x05, "Is Unicode directory"),
        (0x06, "Is Unicode file"),
        (0x07, "Is Unicode share"),
        (0x03, "Is share"),
        (0x01, "Is directory"),
        (0x02, "Is file"),
        (0x04, "Has Unicode strings"),
        (0x80, "Has CLSID"),
    ];
    NAMES
        .iter()
        .find(|(f, _)| flags & f == *f)
        .map_or("Unknown", |(_, n)| n)
}

fn sort_index_name(v: u8) -> &'static str {
    match v {
        0x00 | 0x68 => "Internet Explorer",
        0x42 => "Libraries",
        0x44 => "Users",
        0x4C => "Public Folder",
        0x48 => "My Documents",
        0x50 => "My Computer",
        0x54 => "UsersLibraries",
        0x58 => "My Networs Places/Network",
        0x60 | 0x78 => "Recycle Bin",
        0x80 => "My Games",
        _ => "Unknown",
    }
}

fn category_name(v: u32) -> &'static str {
    const NAMES: [&str; 12] = [
        "All Control Panel Items",
        "Appearance and Personalization",
        "Hardware and Sound",
        "Network and Internet",
        "Sounds, Speech, and Audio Devices",
        "System and Security",
        "Clock, Language, and Region",
        "Ease of Access",
        "Programs",
        "User Accounts",
        "Security Center",
        "Mobile PC",
    ];
    usize::try_from(v)
        .ok()
        .and_then(|i| NAMES.get(i))
        .copied()
        .unwrap_or("Unknown")
}

/// `LnkTargets.as_list` and `ShellItem.id_list`: the items of an IDList, in order.
fn id_list(mut rest: &[u8]) -> Result<Vec<PyValue>, PyError> {
    let mut out = Vec::new();
    while !rest.is_empty() {
        let size = u16_at(rest, 0)?;
        if size == 0 {
            break;
        }
        let class = target_class(u8_at(rest, 2)?);
        let raw_target = sl(rest, 2, 2 + u64::from(size));
        // NetworkLocation reads its strings when it is made, inside the generator.
        let netloc = if class == Target::NetworkLocation {
            Some(network_location_init(raw_target)?)
        } else {
            None
        };
        rest = sl(rest, u64::from(size), OPEN);
        out.push(PyValue::Dict(target_as_item(
            class, raw_target, size, netloc,
        )?));
    }
    Ok(out)
}

type NetLoc = (String, Option<String>, Option<String>);

fn network_location_init(rt: &[u8]) -> Result<NetLoc, PyError> {
    let stop = || PyError::new("RuntimeError", "generator raised StopIteration");
    let mut it = read_strings(sl(rt, 3, OPEN));
    let location = it.next().ok_or_else(stop)?;
    let mut description = None;
    if u8_at(rt, 2)? & 0x80 != 0 {
        description = Some(it.next().ok_or_else(stop)?);
    }
    let mut comments = None;
    if u8_at(rt, 2)? & 0x40 != 0 {
        comments = Some(it.next().ok_or_else(stop)?);
    }
    Ok((location, description, comments))
}

fn shell_fs_folder_item(rt: &[u8]) -> Result<Dict, PyError> {
    let mut d = Dict::new();
    d.set("class", "File entry".into());
    d.set("flags", shell_fs_folder_name(u8_at(rt, 0)? & 0x0F).into());
    d.set("file_size", u32_at(rt, 2)?.into());
    d.set("modification_time", dostime(u32_at(rt, 6)?).into());
    d.set("file_attribute_flags", u16_at(rt, 10)?.into());
    let name = if u8_at(rt, 0)? & 0x04 != 0 {
        read_unicode_string(sl(rt, 12, OPEN))
    } else {
        read_string(sl(rt, 12, OPEN))
    };
    d.set("primary_name", name.into());
    Ok(d)
}

fn cpl_item(rt: &[u8], d: &mut Dict) -> Result<(), PyError> {
    let unicode = rt.len() >= 22 && rt[10] == 0;
    let start: u64 = if unicode { 22 } else { 10 };
    let read_at = |off: u64| {
        if unicode {
            read_unicode_string(sl(rt, start + off * 2, OPEN))
        } else {
            read_string(sl(rt, start + off, OPEN))
        }
    };
    d.set("signature", format!("0x{:08X}", u32_at(rt, 2)?).into());
    d.set("cpl_file_path", read_at(0).into());
    let name_off = u16_at(rt, if unicode { 18 } else { 6 })?;
    d.set("name", read_at(u64::from(name_off)).into());
    let comments_off = u16_at(rt, if unicode { 20 } else { 8 })?;
    let comments = if comments_off == 0 {
        String::new()
    } else {
        read_at(u64::from(comments_off))
    };
    d.set("comments", comments.into());
    Ok(())
}

fn target_as_item(
    class: Target,
    rt: &[u8],
    size: u16,
    netloc: Option<NetLoc>,
) -> Result<Dict, PyError> {
    let mut d = Dict::new();
    let name = match class {
        Target::ControlPanelCpl => "Control panel CPL file",
        Target::ControlPanelCategory => "Control panel category",
        Target::RootFolder => "Root Folder",
        Target::MyComputer => "Volume Item",
        Target::ShellFsFolder => return shell_fs_folder_item(rt),
        Target::NetworkLocation => "Network location",
        Target::CompressedFolder => "Compressed folder",
        Target::Internet => "Internet",
        Target::ControlPanel => "Control panel",
        Target::Printers => "Printers",
        Target::CommonPlacesFolder => "Common places folder",
        Target::UsersFilesFolder => "Users files folder",
        Target::Unknown => "Unknown",
    };
    d.set("class", name.into());
    match class {
        Target::ControlPanelCpl => cpl_item(rt, &mut d)?,
        Target::ControlPanelCategory => {
            let id = u32_at(rt, 6)?;
            d.set("category_id", id.into());
            d.set("category", category_name(u32_at(rt, 6)?).into());
        }
        Target::RootFolder => {
            let v = u8_at(rt, 1)?;
            d.set("sort_index", sort_index_name(v).into());
            d.set("sort_index_value", v.into());
            d.set("guid", parse_uuid(sl(rt, 2, 18))?.into());
        }
        Target::MyComputer => {
            let flags = u8_at(rt, 0)? & 0x0F;
            d.set("flags", hex(u32::from(flags)).into());
            if flags & 0x01 != 0 {
                d.set("volume_name", read_string(sl(rt, 1, 21)).into());
            } else {
                d.set("volume_identifier", parse_uuid(sl(rt, 2, 18))?.into());
            }
        }
        Target::NetworkLocation => {
            let (location, description, comments) = netloc.unwrap_or_default();
            d.set("flags", shell_fs_folder_name(u8_at(rt, 0)? & 0x0F).into());
            d.set("content_flags", u8_at(rt, 2)?.into());
            d.set("location", location.into());
            d.set("description", description.into());
            d.set("comments", comments.into());
        }
        Target::ControlPanel => {
            d.set("item_identifier", parse_uuid(sl(rt, 14, 30))?.into());
        }
        Target::UsersFilesFolder => {
            let sig: String = sl(rt, 4, 8)
                .iter()
                .map(|&b| if b < 0x80 { char::from(b) } else { '\u{FFFD}' })
                .collect();
            d.set("signature", sig.into());
            // ShellFSFolder(indata=raw_target[8:]): its own size field, then its raw target.
            let inner = sl(rt, 8, OPEN);
            let inner_size = u16_at(inner, 0)?;
            let inner_rt = sl(inner, 2, 2 + u64::from(inner_size));
            d.set("file_entry", shell_fs_folder_item(inner_rt)?.into());
            let off = 4 + u64::from(u16_at(rt, 2)?);
            d.set(
                "delegate_class_id",
                parse_uuid(sl(rt, off, off + 16))?.into(),
            );
            let off = 4 + u64::from(u16_at(rt, 2)?) + 16;
            d.set(
                "delegate_folder_id",
                parse_uuid(sl(rt, off, off + 16))?.into(),
            );
        }
        Target::Unknown => d.set("size", (2 + u32::from(size)).into()),
        Target::ShellFsFolder
        | Target::CompressedFolder
        | Target::Internet
        | Target::Printers
        | Target::CommonPlacesFolder => {}
    }
    Ok(d)
}

// ---------------------------------------------------------------------------------------------
// LinkInfo

#[derive(Clone, Copy, PartialEq, Eq)]
enum InfoKind {
    Local,
    Network,
}

struct Info<'a> {
    kind: InfoKind,
    /// The file from the LinkInfo's start to its end, as LnkParse3 keeps it.
    raw: &'a [u8],
}

const DRIVE_TYPES: [&str; 7] = [
    "DRIVE_UNKNOWN",
    "DRIVE_NO_ROOT_DIR",
    "DRIVE_REMOVABLE",
    "DRIVE_FIXED",
    "DRIVE_REMOTE",
    "DRIVE_CDROM",
    "DRIVE_RAMDISK",
];

fn network_provider_name(hex_text: &str) -> Option<&'static str> {
    // Network.NETWORK_PROVIDER_TYPES keys as LnkParse3 writes them. Python's hex() is
    // lowercase, so the keys with a capital X or capital hex digits never match.
    const TYPES: [(&str, &str); 41] = [
        ("0x1A000", "WNNC_NET_AVID"),
        ("0x1B000", "WNNC_NET_DOCUSPACE"),
        ("0x1C000", "WNNC_NET_MANGOSOFT"),
        ("0x1D000", "WNNC_NET_SERNET"),
        ("0X1E000", "WNNC_NET_RIVERFRONT1"),
        ("0x1F000", "WNNC_NET_RIVERFRONT2"),
        ("0x20000", "WNNC_NET_DECORB"),
        ("0x21000", "WNNC_NET_PROTSTOR"),
        ("0x22000", "WNNC_NET_FJ_REDIR"),
        ("0x23000", "WNNC_NET_DISTINCT"),
        ("0x24000", "WNNC_NET_TWINS"),
        ("0x25000", "WNNC_NET_RDR2SAMPLE"),
        ("0x26000", "WNNC_NET_CSC"),
        ("0x27000", "WNNC_NET_3IN1"),
        ("0x29000", "WNNC_NET_EXTENDNET"),
        ("0x2A000", "WNNC_NET_STAC"),
        ("0x2B000", "WNNC_NET_FOXBAT"),
        ("0x2C000", "WNNC_NET_YAHOO"),
        ("0x2D000", "WNNC_NET_EXIFS"),
        ("0x2E000", "WNNC_NET_DAV"),
        ("0x2F000", "WNNC_NET_KNOWARE"),
        ("0x30000", "WNNC_NET_OBJECT_DIRE"),
        ("0x31000", "WNNC_NET_MASFAX"),
        ("0x32000", "WNNC_NET_HOB_NFS"),
        ("0x33000", "WNNC_NET_SHIVA"),
        ("0x34000", "WNNC_NET_IBMAL"),
        ("0x35000", "WNNC_NET_LOCK"),
        ("0x36000", "WNNC_NET_TERMSRV"),
        ("0x37000", "WNNC_NET_SRT"),
        ("0x38000", "WNNC_NET_QUINCY"),
        ("0x39000", "WNNC_NET_OPENAFS"),
        ("0X3A000", "WNNC_NET_AVID1"),
        ("0x3B000", "WNNC_NET_DFS"),
        ("0x3C000", "WNNC_NET_KWNP"),
        ("0x3D000", "WNNC_NET_ZENWORKS"),
        ("0x3E000", "WNNC_NET_DRIVEONWEB"),
        ("0x3F000", "WNNC_NET_VMWARE"),
        ("0x40000", "WNNC_NET_RSFX"),
        ("0x41000", "WNNC_NET_MFILES"),
        ("0x42000", "WNNC_NET_MS_NFS"),
        ("0x43000", "WNNC_NET_GOOGLE"),
    ];
    TYPES.iter().find(|(k, _)| *k == hex_text).map(|(_, v)| *v)
}

impl Info<'_> {
    fn u32(&self, off: u64) -> Result<u32, PyError> {
        u32_at(self.raw, off)
    }

    fn as_dict(&self) -> Result<Dict, PyError> {
        let raw = self.raw;
        let mut d = Dict::new();
        d.set("link_info_size", self.u32(0)?.into());
        d.set("link_info_header_size", self.u32(4)?.into());
        d.set("link_info_flags", self.u32(8)?.into());
        d.set("volume_id_offset", self.u32(12)?.into());
        d.set("local_base_path_offset", self.u32(16)?.into());
        d.set("common_network_relative_link_offset", self.u32(20)?.into());
        d.set("common_path_suffix_offset", self.u32(24)?.into());
        let lbpo = self.u32(16)?;
        if lbpo != 0 {
            d.set(
                "local_base_path",
                read_string(sl(raw, u64::from(lbpo), OPEN)).into(),
            );
        }
        let cpso = self.u32(24)?;
        if cpso != 0 {
            d.set(
                "common_path_suffix",
                read_string(sl(raw, u64::from(cpso), OPEN)).into(),
            );
        }
        let has_opt = self.u32(4)? >= 0x24;
        if has_opt {
            let off = self.u32(28)?;
            if off != 0 {
                d.set("local_base_path_offset_unicode", off.into());
                let text = read_unicode_string(sl(raw, u64::from(off), OPEN));
                d.set("local_base_path_unicode", text.into());
            }
            let off = self.u32(32)?;
            if off != 0 {
                d.set("common_path_suffix_offset_unicode", off.into());
                let text = read_unicode_string(sl(raw, u64::from(off) + 4, OPEN));
                d.set("common_path_suffix_unicode", text.into());
            }
        }
        d.set("location_info", Dict::new().into());
        let loc = match self.kind {
            InfoKind::Local => {
                d.set("location", "Local".into());
                self.local()?
            }
            InfoKind::Network => {
                d.set("location", "Network".into());
                self.network()?
            }
        };
        d.set("location_info", loc.into());
        Ok(d)
    }

    fn local(&self) -> Result<Dict, PyError> {
        let raw = self.raw;
        let vo = u64::from(self.u32(12)?);
        let mut d = Dict::new();
        d.set("volume_id_size", self.u32(vo)?.into());
        let drive = self.u32(vo + 4)?;
        d.set("r_drive_type", drive.into());
        let vlo = self.u32(vo + 12)?;
        d.set("volume_label_offset", vlo.into());
        d.set("drive_serial_number", hex(self.u32(vo + 8)?).into());
        let drive_type = usize::try_from(drive)
            .ok()
            .and_then(|i| DRIVE_TYPES.get(i))
            .map_or(PyValue::None, |s| (*s).into());
        d.set("drive_type", drive_type);
        let label = if vlo == 0x14 {
            PyValue::None
        } else {
            read_string(sl(raw, vo + u64::from(vlo), OPEN)).into()
        };
        d.set("volume_label", label);
        if vlo == 0x14 {
            let vluo = self.u32(vo + 16)?;
            if vluo != 0 {
                d.set("volume_label_unicode_offset", vluo.into());
                let text = read_unicode_string(sl(raw, vo + u64::from(vluo), OPEN));
                d.set("volume_label_unicode", text.into());
            }
        }
        Ok(d)
    }

    fn network(&self) -> Result<Dict, PyError> {
        let raw = self.raw;
        let co = u64::from(self.u32(20)?);
        let mut d = Dict::new();
        d.set("common_network_relative_link_size", self.u32(co)?.into());
        let flags = self.u32(co + 4)?;
        d.set("common_network_relative_link_flags", flags.into());
        let nno = self.u32(co + 8)?;
        d.set("net_name_offset", nno.into());
        let dno = self.u32(co + 12)?;
        d.set("device_name_offset", dno.into());
        let provider = hex(self.u32(co + 16)?);
        d.set("r_network_provider_type", provider.clone().into());
        if flags & 0x0002 != 0
            && let Some(name) = network_provider_name(&provider)
        {
            d.set("network_provider_type", name.into());
        }
        if nno > 20 {
            let off = self.u32(co + 20)?;
            if off != 0 {
                d.set("net_name_offset_unicode", off.into());
                let text = read_unicode_string(sl(raw, co + u64::from(off), OPEN));
                d.set("net_name_unicode", text.into());
            }
            let off = self.u32(co + 24)?;
            if off != 0 {
                d.set("device_name_offset_unicode", off.into());
                let text = read_unicode_string(sl(raw, co + u64::from(off), OPEN));
                d.set("device_name_unicode", text.into());
            }
        } else {
            let net = read_string(sl(raw, co + u64::from(nno), OPEN));
            if !net.is_empty() {
                d.set("net_name", net.into());
            }
            let dev = read_string(sl(raw, co + u64::from(dno), OPEN));
            if !dev.is_empty() {
                d.set("device_name", dev.into());
            }
        }
        Ok(d)
    }
}

// ---------------------------------------------------------------------------------------------
// ExtraData

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExtraKind {
    Environment,
    Console,
    DistributedTracker,
    CodePage,
    SpecialFolder,
    Darwin,
    Icon,
    ShimLayer,
    Metadata,
    KnownFolder,
    ShellItem,
    Unknown,
    Terminal,
}

impl ExtraKind {
    fn from_signature(sig: u32) -> Self {
        match sig {
            0xA000_0001 => Self::Environment,
            0xA000_0002 => Self::Console,
            0xA000_0003 => Self::DistributedTracker,
            0xA000_0004 => Self::CodePage,
            0xA000_0005 => Self::SpecialFolder,
            0xA000_0006 => Self::Darwin,
            0xA000_0007 => Self::Icon,
            0xA000_0008 => Self::ShimLayer,
            0xA000_0009 => Self::Metadata,
            0xA000_000B => Self::KnownFolder,
            0xA000_000C => Self::ShellItem,
            _ => Self::Unknown,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Environment => "ENVIRONMENTAL_VARIABLES_LOCATION_BLOCK",
            Self::Console => "CONSOLE_PROPERTIES_BLOCK",
            Self::DistributedTracker => "DISTRIBUTED_LINK_TRACKER_BLOCK",
            Self::CodePage => "CONSOLE_CODEPAGE_BLOCK",
            Self::SpecialFolder => "SPECIAL_FOLDER_LOCATION_BLOCK",
            Self::Darwin => "DARWIN_BLOCK",
            Self::Icon => "ICON_LOCATION_BLOCK",
            Self::ShimLayer => "SHIM_LAYER_BLOCK",
            Self::Metadata => "METADATA_PROPERTIES_BLOCK",
            Self::KnownFolder => "KNOWN_FOLDER_LOCATION_BLOCK",
            Self::ShellItem => "SHELL_ITEM_IDENTIFIER_BLOCK",
            Self::Unknown => "UNKNOWN_BLOCK",
            Self::Terminal => "TERMINAL_BLOCK",
        }
    }
}

struct Extra<'a> {
    kind: ExtraKind,
    raw: &'a [u8],
}

impl Extra<'_> {
    fn size(&self) -> Result<u64, PyError> {
        if self.kind == ExtraKind::Terminal {
            return Ok(4 + sl(self.raw, 4, OPEN).len() as u64);
        }
        u32_at(self.raw, 0).map(u64::from)
    }

    fn as_dict(&self, ctx: &mut Ctx) -> Result<Dict, PyError> {
        let r = self.raw;
        let mut d = Dict::new();
        d.set(
            "size",
            self.size()?.try_into().map_or(PyValue::None, PyValue::Int),
        );
        match self.kind {
            ExtraKind::Environment | ExtraKind::Icon => {
                d.set("target_ansi", read_string(sl(r, 8, 268)).into());
                d.set(
                    "target_unicode",
                    read_unicode_string(sl(r, 268, 788)).into(),
                );
            }
            ExtraKind::Console => console(r, &mut d)?,
            ExtraKind::DistributedTracker => {
                d.set("length", u32_at(r, 8)?.into());
                d.set("version", u32_at(r, 12)?.into());
                d.set("machine_identifier", read_string(sl(r, 16, 32)).into());
                d.set("droid_volume_identifier", parse_uuid(sl(r, 32, 48))?.into());
                d.set("droid_file_identifier", parse_uuid(sl(r, 48, 64))?.into());
                d.set(
                    "birth_droid_volume_identifier",
                    parse_uuid(sl(r, 64, 80))?.into(),
                );
                d.set(
                    "birth_droid_file_identifier",
                    parse_uuid(sl(r, 80, 96))?.into(),
                );
            }
            ExtraKind::CodePage => d.set("code_page", u32_at(r, 8)?.into()),
            ExtraKind::SpecialFolder => {
                d.set("special_folder_id", u32_at(r, 8)?.into());
                d.set("offset", u32_at(r, 12)?.into());
            }
            ExtraKind::Darwin => darwin(r, &mut d)?,
            ExtraKind::ShimLayer => d.set("layer_name", read_string(sl(r, 8, OPEN)).into()),
            ExtraKind::Metadata => metadata(r, &mut d, ctx)?,
            ExtraKind::KnownFolder => {
                d.set("known_folder_id", parse_uuid(sl(r, 8, 24))?.into());
                d.set("offset", u32_at(r, 24)?.into());
            }
            ExtraKind::ShellItem => {
                let end = u64::from(u32_at(r, 0)?);
                d.set("id_list", PyValue::List(id_list(sl(r, 8, end))?));
            }
            ExtraKind::Unknown => {
                d.set("extra_data_sha256", sha256_hex(sl(r, 4, OPEN)).into());
            }
            ExtraKind::Terminal => {
                d.set("appended_data_sha256", sha256_hex(sl(r, 4, OPEN)).into());
            }
        }
        Ok(d)
    }
}

fn console(r: &[u8], d: &mut Dict) -> Result<(), PyError> {
    d.set("fill_attributes", u16_at(r, 8)?.into());
    d.set("popup_fill_attributes", u16_at(r, 10)?.into());
    for (key, off) in [
        ("screen_buffer_size_x", 12),
        ("screen_buffer_size_y", 14),
        ("window_size_x", 16),
        ("window_size_y", 18),
        ("window_origin_x", 20),
        ("window_origin_y", 22),
    ] {
        d.set(key, i16_at(r, off)?.into());
    }
    d.set("font_size", u32_at(r, 32)?.into());
    d.set("font_family", u32_at(r, 36)?.into());
    d.set("font_weight", u32_at(r, 40)?.into());
    d.set("face_name", read_unicode_string(sl(r, 44, 108)).into());
    for (key, off) in [
        ("cursor_size", 108),
        ("full_screen", 112),
        ("quick_edit", 116),
        ("insert_mode", 120),
        ("auto_position", 124),
        ("history_buffer_size", 128),
        ("number_of_history_buffers", 132),
        ("history_no_dup", 136),
        ("color_table", 140),
    ] {
        d.set(key, u32_at(r, off)?.into());
    }
    Ok(())
}

/// Python's `s[start:end]` on code points, for a start and end that may be negative.
fn py_slice(s: &[char], start: i64, end: i64) -> &[char] {
    let len = i64::try_from(s.len()).unwrap_or(i64::MAX);
    let norm = |i: i64| if i < 0 { (i + len).max(0) } else { i.min(len) };
    let (a, b) = (norm(start), norm(end));
    if a >= b {
        &[]
    } else {
        #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
        &s[a as usize..b as usize]
    }
}

fn py_find(s: &[char], c: char) -> i64 {
    s.iter()
        .position(|&x| x == c)
        .map_or(-1, |i| i64::try_from(i).unwrap_or(i64::MAX))
}

fn index_error() -> PyError {
    PyError::new("IndexError", "string index out of range")
}

/// `utils._quad_to_hex`.
fn quad_to_hex(quad: &[char]) -> Result<String, PyError> {
    const BASE_85: &str =
        "!$%&'()*+,-.0123456789=?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`abcdefghijklmnopqrstuvwxyz{}~";
    let mut ddec: i64 = 0;
    for i in (1..=5).rev() {
        let c = *quad.get(i - 1).ok_or_else(index_error)?;
        let b85 = BASE_85
            .chars()
            .position(|x| x == c)
            .map_or(-1, |p| i64::try_from(p).unwrap_or(-1));
        ddec += b85;
        if i > 1 {
            ddec *= 85;
        }
    }
    Ok(if ddec < 0 {
        format!("-{:07X}", -ddec)
    } else {
        format!("{ddec:08X}")
    })
}

/// `utils.parse_packed_uuid`.
fn parse_packed_uuid(text: &[char]) -> Result<String, PyError> {
    let quads = [
        quad_to_hex(py_slice(text, 0, 5))?,
        quad_to_hex(py_slice(text, 5, 10))?,
        quad_to_hex(py_slice(text, 10, 15))?,
        quad_to_hex(py_slice(text, 15, 20))?,
    ]
    .concat();
    // quads is ASCII.
    let q = |a: u64, b: u64| String::from_utf8_lossy(sl(quads.as_bytes(), a, b)).into_owned();
    Ok(format!(
        "{}-{}-{}-{}{}-{}{}{}{}{}{}",
        q(0, 8),
        q(12, 16),
        q(8, 12),
        q(22, 24),
        q(20, 22),
        q(18, 20),
        q(16, 18),
        q(30, 32),
        q(28, 30),
        q(26, 28),
        q(24, 26)
    ))
}

fn darwin(r: &[u8], d: &mut Dict) -> Result<(), PyError> {
    d.set("darwin_data_ansi", read_string(sl(r, 8, 268)).into());
    let unicode = read_unicode_string(sl(r, 268, 788));
    let data: Vec<char> = unicode.chars().collect();
    d.set("darwin_data_unicode", unicode.into());
    d.set(
        "product_code_id",
        parse_packed_uuid(py_slice(&data, 0, 20))?.into(),
    );
    let terminator = py_find(&data, '>').max(py_find(&data, '<'));
    let feature = if terminator == 20 {
        PyValue::None
    } else {
        py_slice(&data, 20, terminator)
            .iter()
            .collect::<String>()
            .into()
    };
    d.set("feature_name", feature);
    let gt = py_find(&data, '>');
    let component = if gt == -1 {
        PyValue::None
    } else {
        parse_packed_uuid(py_slice(&data, gt + 1, i64::MAX))?.into()
    };
    d.set("component_id", component);
    Ok(())
}

fn property_type_name(vt: u16) -> Option<&'static str> {
    Some(match vt {
        0x0000 => "VT_EMPTY",
        0x0001 => "VT_NULL",
        0x0002 => "VT_I2",
        0x0003 => "VT_I4",
        0x0004 => "VT_R4",
        0x0005 => "VT_R8",
        0x0006 => "VT_CY",
        0x0007 => "VT_DATE",
        0x0008 => "VT_BSTR",
        0x000A => "VT_ERROR",
        0x000B => "VT_BOOL",
        0x000E => "VT_DECIMAL",
        0x0010 => "VT_I1",
        0x0011 => "VT_UI1",
        0x0012 => "VT_UI2",
        0x0013 => "VT_UI4",
        0x0014 => "VT_I8",
        0x0015 => "VT_UI8",
        0x0016 => "VT_INT",
        0x0017 => "VT_UINT",
        0x001E => "VT_LPSTR",
        0x001F => "VT_LPWSTR",
        0x0040 => "VT_FILETIME",
        0x0041 => "VT_BLOB",
        0x0042 => "VT_STREAM",
        0x0043 => "VT_STORAGE",
        0x0044 => "VT_STREAMED_Object",
        0x0045 => "VT_STORED_Object",
        0x0046 => "VT_BLOB_Object",
        0x0047 => "VT_CF",
        0x0048 => "VT_CLSID",
        0x0049 => "VT_VERSIONED_STREAM",
        0x1002 => "VT_VECTOR_I2",
        0x1003 => "VT_VECTOR_I4",
        0x1004 => "VT_VECTOR_R4",
        0x1005 => "VT_VECTOR_R8",
        0x1006 => "VT_VECTOR_CY",
        0x1007 => "VT_VECTOR_DATE",
        0x1008 => "VT_VECTOR_BSTR",
        0x100A => "VT_VECTOR_ERROR",
        0x100B => "VT_VECTOR_BOOL",
        0x100C => "VT_VECTOR_VARIANT",
        0x1010 => "VT_VECTOR_I1",
        0x1011 => "VT_VECTOR_UI1",
        0x1012 => "VT_VECTOR_UI2",
        0x1013 => "VT_VECTOR_UI4",
        0x1014 => "VT_VECTOR_I8",
        0x1015 => "VT_VECTOR_UI8",
        0x101E => "VT_VECTOR_LPSTR",
        0x101F => "VT_VECTOR_LPWSTR",
        0x1040 => "VT_VECTOR_FILETIME",
        0x1047 => "VT_VECTOR_CF",
        0x1048 => "VT_VECTOR_CLSID",
        0x2002 => "VT_ARRAY_I2",
        0x2003 => "VT_ARRAY_I4",
        0x2004 => "VT_ARRAY_R4",
        0x2005 => "VT_ARRAY_R8",
        0x2006 => "VT_ARRAY_CY",
        0x2007 => "VT_ARRAY_DATE",
        0x2008 => "VT_ARRAY_BSTR",
        0x200A => "VT_ARRAY_ERROR",
        0x200B => "VT_ARRAY_BOOL",
        0x200C => "VT_ARRAY_VARIANT",
        0x200E => "VT_ARRAY_DECIMAL",
        0x2010 => "VT_ARRAY_I1",
        0x2011 => "VT_ARRAY_UI1",
        0x2012 => "VT_ARRAY_UI2",
        0x2013 => "VT_ARRAY_UI4",
        0x2016 => "VT_ARRAY_INT",
        0x2017 => "VT_ARRAY_UINT",
        _ => return None,
    })
}

fn charged_unicode(b: &[u8], ctx: &mut Ctx) -> Result<String, PyError> {
    ctx.charge(unicode_len(b))?;
    Ok(read_unicode_string(b))
}

/// `TypedPropertyValue.value()` and the `PropertyType(...).name` beside it.
fn typed_value(raw: &[u8], ctx: &mut Ctx) -> Result<(PyValue, PyValue), PyError> {
    let value = if u16_at(raw, 2)? != 0 {
        PyValue::None
    } else {
        match u16_at(raw, 0)? {
            // unpack("<i", raw[4:6]): two bytes at most, never the four "<i" needs.
            0x0002 => return Err(PyError::struct_error(4)),
            0x001F => {
                let n = u64::from(u32_at(raw, 4)?) * 2;
                charged_unicode(sl(raw, 8, 8 + n), ctx)?.into()
            }
            _ => PyValue::None,
        }
    };
    let vt = u16_at(raw, 0)?;
    let name = property_type_name(vt)
        .ok_or_else(|| PyError::new("ValueError", format!("{vt} is not a valid PropertyType")))?;
    Ok((value, name.into()))
}

fn storage_as_dict(raw: &[u8], ctx: &mut Ctx) -> Result<Dict, PyError> {
    let mut d = Dict::new();
    d.set("storage_size", u32_at(raw, 0)?.into());
    d.set("version", hex(u32_at(raw, 4)?).into());
    let format_id = parse_uuid(sl(raw, 8, 24))?;
    d.set("format_id", format_id.clone().into());
    let string_names = format_id == "D5CDD505-2E9C-101B-9397-08002B2CF9AE";
    let mut values = Vec::new();
    let mut start = 24u64;
    loop {
        let v = sl(raw, start, OPEN);
        let size = u32_at(v, 0)?;
        if size == 0 {
            break;
        }
        ctx.charge(0)?;
        values.push(v);
        start += u64::from(size);
    }
    let mut out = Vec::with_capacity(values.len());
    for v in values {
        let mut vd = Dict::new();
        vd.set("value_size", u32_at(v, 0)?.into());
        let typed = if string_names {
            let name_size = u32_at(v, 4)?;
            vd.set("name_size", name_size.into());
            let end = 9 + u64::from(name_size);
            vd.set("name", charged_unicode(sl(v, 9, end), ctx)?.into());
            sl(v, end, OPEN)
        } else {
            vd.set("id", u32_at(v, 4)?.into());
            sl(v, 9, OPEN)
        };
        let (value, value_type) = typed_value(typed, ctx)?;
        vd.set("value", value);
        vd.set("value_type", value_type);
        out.push(PyValue::Dict(vd));
    }
    d.set("serialized_property_values", PyValue::List(out));
    Ok(d)
}

fn metadata(r: &[u8], d: &mut Dict, ctx: &mut Ctx) -> Result<(), PyError> {
    let mut storages = Vec::new();
    let mut start = 8u64;
    loop {
        let s = sl(r, start, OPEN);
        let size = u32_at(s, 0)?;
        if size == 0 {
            break;
        }
        ctx.charge(0)?;
        storages.push(s);
        start += u64::from(size);
    }
    let mut out = Vec::with_capacity(storages.len());
    for s in storages {
        out.push(PyValue::Dict(storage_as_dict(s, ctx)?));
    }
    d.set("property_store", PyValue::List(out));
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// The file

/// A parsed shortcut: what `LnkParse3.lnk_file(fp)` holds once its constructor returns.
pub struct LnkFile<'a> {
    header: Header<'a>,
    size: u64,
    target_index: u64,
    targets: Option<(u16, &'a [u8])>,
    info: Option<Info<'a>>,
    strings: Vec<(&'static str, String)>,
    link_flags: u32,
    extras: Vec<Extra<'a>>,
}

impl<'a> LnkFile<'a> {
    /// `LnkParse3.lnk_file(fp)` on a file holding `data`.
    pub fn parse(data: &'a [u8]) -> Result<Self, PyError> {
        let header = Header::new(data)?;
        let mut index = u64::from(header.size()?);
        let target_index = index + 2;
        let flags = header.r_link_flags()?;

        let mut targets = None;
        if flags & 0x01 != 0 {
            let raw = sl(data, index, OPEN);
            let size = u16_at(raw, 0)?;
            targets = Some((size, sl(raw, 2, u64::from(size) + 2)));
            index += u64::from(size) + 2;
        }

        let mut info = None;
        if flags & 0x02 != 0 && flags & 0x100 == 0 {
            let raw = sl(data, index, OPEN);
            // InfoFactory.info_class: a struct.error here means no LinkInfo.
            if let Ok(f) = u32_at(raw, 8) {
                let kind = if f & 1 != 0 {
                    Some(InfoKind::Local)
                } else if f & 2 != 0 {
                    Some(InfoKind::Network)
                } else {
                    None
                };
                if let Some(kind) = kind {
                    index += u64::from(u32_at(raw, 0)?);
                    info = Some(Info { kind, raw });
                }
            }
        }

        let (strings, used) = string_data(sl(data, index, OPEN), flags);
        index += used;

        let extras = extra_data(sl(data, index, OPEN));
        for e in &extras {
            index += e.size()?;
        }
        index += sl(data, index, OPEN).len().min(4) as u64;

        Ok(Self {
            header,
            size: index,
            target_index,
            targets,
            info,
            strings,
            link_flags: flags,
            extras,
        })
    }

    /// `lnk.get_json(get_all=True)`.
    pub fn get_json(&self) -> Result<PyValue, PyError> {
        let int = |v: u64| PyValue::Int(i64::try_from(v).unwrap_or(i64::MAX));
        let mut res = Dict::new();
        res.set("size", int(self.size));
        res.set("header", self.header.as_dict()?.into());
        if let Some((size, raw)) = self.targets {
            let mut t = Dict::new();
            t.set("size", size.into());
            t.set("items", PyValue::List(id_list(raw)?));
            t.set("index", int(self.target_index));
            res.set("target", t.into());
        }
        let info = match &self.info {
            Some(info) => info.as_dict()?,
            None => Dict::new(),
        };
        res.set("link_info", info.into());
        let mut data = Dict::new();
        for (k, v) in &self.strings {
            data.set(k, v.as_str().into());
        }
        res.set("data", data.into());
        res.set("extra", self.extras_as_dict()?.into());
        Ok(PyValue::Dict(res))
    }

    fn extras_as_dict(&self) -> Result<Dict, PyError> {
        let mut ctx = Ctx { metadata_text: 0 };
        let mut res = Dict::new();
        for e in &self.extras {
            let name = e.kind.name();
            if e.kind == ExtraKind::Unknown && res.get(name).is_none() {
                res.set(name, PyValue::List(Vec::new()));
            }
            match e.as_dict(&mut ctx) {
                Ok(d) => {
                    if e.kind == ExtraKind::Unknown {
                        if let Some(PyValue::List(l)) = res.get_mut(name) {
                            l.push(d.into());
                        }
                    } else {
                        res.set(name, d.into());
                    }
                }
                Err(err) if err.kind == "error" || err.kind == "ValueError" => {}
                Err(err) => return Err(err),
            }
        }
        Ok(res)
    }

    fn string(&self, key: &str) -> Option<&str> {
        self.strings
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
    }

    /// `lnk.lnk_command`.
    pub fn lnk_command(&self) -> Result<String, PyError> {
        let mut out: Vec<String> = Vec::new();
        if self.link_flags & 0x08 != 0 {
            let rel = self.string("relative_path").ok_or_else(|| {
                PyError::new(
                    "TypeError",
                    "expected str, bytes or os.PathLike object, not NoneType",
                )
            })?;
            out.push(list2cmdline(rel));
        }
        if self.link_flags & 0x20 != 0 {
            match self.string("command_line_arguments") {
                Some(a) => out.push(a.to_owned()),
                None => {
                    return Err(PyError::new(
                        "TypeError",
                        format!(
                            "sequence item {}: expected str instance, NoneType found",
                            out.len()
                        ),
                    ));
                }
            }
        }
        Ok(out.join(" "))
    }
}

/// `subprocess.list2cmdline([arg])`.
fn list2cmdline(arg: &str) -> String {
    let mut result = String::new();
    let mut bs = 0usize;
    let needquote = arg.contains(' ') || arg.contains('\t') || arg.is_empty();
    if needquote {
        result.push('"');
    }
    for c in arg.chars() {
        match c {
            '\\' => bs += 1,
            '"' => {
                result.extend(std::iter::repeat_n('\\', bs * 2));
                bs = 0;
                result.push_str("\\\"");
            }
            _ => {
                result.extend(std::iter::repeat_n('\\', bs));
                bs = 0;
                result.push(c);
            }
        }
    }
    result.extend(std::iter::repeat_n('\\', bs));
    if needquote {
        result.extend(std::iter::repeat_n('\\', bs));
        result.push('"');
    }
    result
}

fn string_data(raw: &[u8], flags: u32) -> (Vec<(&'static str, String)>, u64) {
    let unicode = flags & 0x80 != 0;
    let mut out = Vec::new();
    let mut start = 0u64;
    for (mask, key, limit) in [
        (0x04, "description", true),
        (0x08, "relative_path", true),
        (0x10, "working_directory", true),
        (0x20, "command_line_arguments", false),
        (0x40, "icon_location", false),
    ] {
        if flags & mask == 0 {
            continue;
        }
        let b = sl(raw, start, OPEN);
        // A struct.error ends the string data with a warning.
        let Ok(count) = u16_at(b, 0) else { break };
        let mut length = u64::from(if limit && count > 260 { 260 } else { count });
        let text = if unicode {
            length *= 2;
            read_unicode_string(sl(b, 2, 2 + length))
        } else {
            read_string(sl(b, 2, 2 + length))
        };
        out.push((key, text));
        start += 2 + length;
    }
    (out, start)
}

fn extra_data(mut rest: &[u8]) -> Vec<Extra<'_>> {
    let mut out = Vec::new();
    while !rest.is_empty() {
        let Ok(size) = u32_at(rest, 0) else { break };
        if size == 0 {
            break;
        }
        let size = u64::from(size);
        let block = sl(rest, 0, size);
        // The signature comes from the bytes after the size, even past a short block.
        if let Ok(sig) = u32_at(rest, 4) {
            out.push(Extra {
                kind: ExtraKind::from_signature(sig),
                raw: block,
            });
        }
        rest = sl(rest, size, OPEN);
    }
    if rest.len() > 4 && u32_at(rest, 0).is_ok_and(|v| v < 4) {
        out.push(Extra {
            kind: ExtraKind::Terminal,
            raw: rest,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list2cmdline_matches_python() {
        // subprocess.list2cmdline([x]) in Python 3.14.
        for (arg, want) in [
            ("C:\\Program Files\\x.exe", "\"C:\\Program Files\\x.exe\""),
            ("", "\"\""),
            ("q\"uote", "q\\\"uote"),
            ("back\\\\", "back\\\\"),
            ("tr\\\"x\\", "tr\\\\\\\"x\\"),
            ("a b\\", "\"a b\\\\\""),
        ] {
            assert_eq!(list2cmdline(arg), want, "{arg}");
        }
    }

    #[test]
    fn packed_uuid() {
        let text: Vec<char> = "w_1^VX!!!!!!!!!MKKSk".chars().collect();
        assert_eq!(
            parse_packed_uuid(&text).unwrap(),
            "91120000-0030-0000-0000-0000000FF1CE"
        );
    }
}
