"""Build .lnk cases, mutate them, and record what ace3's lnk_parser module gets from LnkParse3.

Run in ace-dev-1:  /venv/bin/python3 -I oracle.py OUT.json [FULL.json]

Every case runs the module's steps: LnkParse3.lnk_file(fp), lnk.get_json(get_all=True),
lnk.lnk_command, then json.dump(info, indent=4, default=_datetime_to_str, sort_keys=True).
For each it records the exception text (and type), analysis.info as ace3's _JSONEncoder
serializes it, the command, and the text the module writes to {file}.lnkparser.json.

Cases are hand-built from MS-SHLLINK and MS-PROPSTORE with struct, plus mutations of them
made with a seeded random generator. A mutation is stored as a list of edits on its base case,
so the Rust test rebuilds the input. OUT keeps sha256 digests for mutations and full outputs
for the base cases; FULL (optional) keeps full outputs for everything, for debugging.
"""

import base64
import datetime
import hashlib
import io
import json
import random
import struct
import sys
import warnings

sys.path.insert(0, "/opt/ace")
from saq.json_encoding import _JSONEncoder  # noqa: E402

warnings.filterwarnings("ignore")
import LnkParse3  # noqa: E402

p8 = lambda v: struct.pack("<B", v)  # noqa: E731
p16 = lambda v: struct.pack("<H", v)  # noqa: E731
p32 = lambda v: struct.pack("<I", v)  # noqa: E731
CLSID = bytes.fromhex("0114020000000000C000000000000046")


def guid(text):
    import uuid

    return uuid.UUID(text).bytes_le


def header(flags, attrs=0x20, ct=132514720000000000, at=132514720123456789, wt=0, size=1234,
           icon=0, show=1, hotkey=0x0241, r0=0, r1=0, r2=0, hsize=0x4C, clsid=CLSID):
    return struct.pack("<I16sIIqqqIiIHHII", hsize, clsid, flags, attrs, ct, at, wt, size, icon,
                       show, hotkey, r0, r1, r2)


def item(body):
    return p16(len(body) + 2) + body


def idlist(*items):
    body = b"".join(items) + b"\x00\x00"
    return p16(len(body)) + body


def dos(y, mo, d, h, mi, s):
    date = ((y - 1980) << 9) | (mo << 5) | d
    time = (h << 11) | (mi << 5) | (s // 2)
    return p32(date | (time << 16))


def root_folder(sort=0x50, g="20D04FE0-3AEA-1069-A2D8-08002B30309D"):
    return item(b"\x1f" + p8(sort) + guid(g))


def volume(name=b"C:\\"):
    return item(b"\x2f" + name.ljust(22, b"\x00"))


def volume_guid(g="12345678-1234-5678-9ABC-DEF012345678"):
    return item(b"\x2e\x00" + guid(g) + b"\x00" * 4)


def file_entry(name, kind=0x32, size=4096, mtime=None, attrs=0x20, unicode_name=None, extra=b""):
    mtime = mtime if mtime is not None else dos(2021, 3, 4, 5, 6, 8)
    body = p8(kind) + b"\x00" + p32(size) + mtime + p16(attrs)
    if unicode_name is not None:
        body += unicode_name.encode("utf-16le") + b"\x00\x00"
    else:
        body += name + b"\x00"
        if len(body) % 2:
            body += b"\x00"
    return item(body + extra)


def network_location(kind=0x41, flags=0x80 | 0x40, loc=b"\\\\server\\share",
                     desc=b"Microsoft Network", comm=b"comment"):
    body = p8(kind) + b"\x00" + p8(flags) + loc + b"\x00"
    if flags & 0x80:
        body += desc + b"\x00"
    if flags & 0x40:
        body += comm + b"\x00"
    return item(body + b"\x00\x00")


def control_panel(kind=0x71, g="26EE0668-A00A-44D7-9371-BEB064C98683"):
    return item(p8(kind) + b"\x00" * 13 + guid(g) + b"\x00\x00")


def control_panel_category(cat=5):
    return item(b"\x01\x00" + p32(0x39DE2184) + p32(cat))


def cpl_unicode(path="C:\\Windows\\system32\\desk.cpl", name="Display", comments="Change"):
    strings = (path + "\x00").encode("utf-16le")
    name_off = len(path) + 1
    strings += (name + "\x00").encode("utf-16le")
    comm_off = name_off + len(name) + 1
    strings += (comments + "\x00").encode("utf-16le")
    body = b"\x00\x00" + p32(0xFFFFFF38) + b"\x00" * 12 + p16(name_off) + p16(comm_off) + strings
    return item(body)


def cpl_ascii(path=b"main.cpl", name=b"Mouse", comments=b""):
    name_off = len(path) + 1
    comm_off = (name_off + len(name) + 1) if comments else 0
    body = b"\x00\x00" + p32(0xFFFFFF9C) + p16(name_off) + p16(comm_off)
    body += path + b"\x00" + name + b"\x00" + comments + b"\x00"
    return item(body)


def users_files_folder(name="Documents"):
    fe =file_entry(name.encode(), kind=0x31)
    inner = b"CFSF" + fe
    body = b"\x74\x00" + p16(len(inner)) + inner
    body += guid("5E591A74-DF96-48D3-8D67-1733BCEE28BA") + guid("FDD39AD0-238F-46AF-ADB4-6C85480369C7")
    return item(body)


def simple(kind, n=6):
    return item(p8(kind) + bytes(range(1, n)))


def link_info_local(base=b"C:\\Windows\\notepad.exe", suffix=b"", label=b"OS", serial=0x1234ABCD,
                    drive=3, unicode=False, ubase="C:\\Windows\\notepad.exe", usuffix="",
                    label_unicode=None, hsize=None):
    hsize = hsize if hsize is not None else (0x24 if unicode else 0x1C)
    if label_unicode is not None:
        vol = p32(0) + p32(drive) + p32(serial) + p32(0x14) + p32(0x14) + (label_unicode + "\x00").encode("utf-16le")
    else:
        vol = p32(0) + p32(drive) + p32(serial) + p32(0x10) + label + b"\x00"
    vol = p32(len(vol)) + vol[4:]
    vol_off = hsize
    base_off = vol_off + len(vol)
    suffix_off = base_off + len(base) + 1
    tail = vol + base + b"\x00" + suffix + b"\x00"
    ubase_off = usuffix_off = 0
    if unicode:
        ubase_off = hsize + len(tail)
        tail += (ubase + "\x00").encode("utf-16le")
        usuffix_off = hsize + len(tail) - 4
        tail += (usuffix + "\x00").encode("utf-16le")
    hdr = p32(hsize) + p32(1) + p32(vol_off) + p32(base_off) + p32(0) + p32(suffix_off)
    if hsize >= 0x24:
        hdr += p32(ubase_off) + p32(usuffix_off)
    total = 4 + len(hdr) + len(tail)
    return p32(total) + hdr + tail


def link_info_network(net=b"\\\\SERVER\\SHARE", dev=b"Z:", flags=3, provider=0x20000, suffix=b"doc.txt",
                      unicode=False, unet="\\\\SERVER\\SHARE", udev="Z:"):
    if unicode:
        cn_hdr_len = 28
        net_off = cn_hdr_len
        dev_off = net_off + len(net) + 1
        unet_off = dev_off + len(dev) + 1
        udev_off = unet_off + 2 * (len(unet) + 1)
        cn = p32(0) + p32(flags) + p32(net_off) + p32(dev_off) + p32(provider) + p32(unet_off) + p32(udev_off)
        cn += net + b"\x00" + dev + b"\x00" + (unet + "\x00").encode("utf-16le") + (udev + "\x00").encode("utf-16le")
    else:
        net_off = 20
        dev_off = net_off + len(net) + 1
        cn = p32(0) + p32(flags) + p32(net_off) + p32(dev_off) + p32(provider) + net + b"\x00" + dev + b"\x00"
    cn = p32(len(cn)) + cn[4:]
    hsize = 0x1C
    cn_off = hsize
    suffix_off = cn_off + len(cn)
    tail = cn + suffix + b"\x00"
    hdr = p32(hsize) + p32(2) + p32(0) + p32(0) + p32(cn_off) + p32(suffix_off)
    return p32(4 + len(hdr) + len(tail)) + hdr + tail


def sdata(text, unicode=True, count=None):
    if unicode:
        raw = text.encode("utf-16le")
        n = len(raw) // 2
    else:
        raw = text if isinstance(text, bytes) else text.encode("cp1252")
        n = len(raw)
    return p16(n if count is None else count) + raw


def block(sig, body):
    return p32(len(body) + 8) + p32(sig) + body


def env_block(sig=0xA0000001, ansi=b"%windir%\\system32\\cmd.exe", uni="%windir%\\system32\\cmd.exe"):
    return block(sig, ansi.ljust(260, b"\x00") + uni.encode("utf-16le").ljust(520, b"\x00"))


def console_block(face="Consolas"):
    body = p16(7) + p16(0xF5) + struct.pack("<hhhhhh", 120, 9001, 120, 30, -1, 5) + p32(0) + p32(0)
    body += p32(0x100000) + p32(0x36) + p32(400) + face.encode("utf-16le").ljust(64, b"\x00")
    body += p32(25) + p32(0) + p32(1) + p32(1) + p32(1) + p32(50) + p32(4) + p32(0)
    body += b"".join(p32(0x00C0C0C0 + i) for i in range(16))
    return block(0xA0000002, body)


def tracker_block(machine=b"desktop-abc", length=0x58, version=0):
    body = p32(length) + p32(version) + machine.ljust(16, b"\x00")
    body += guid("11111111-2222-3333-4444-555555555555") + guid("66666666-7777-8888-9999-AAAAAAAAAAAA")
    body += guid("BBBBBBBB-CCCC-DDDD-EEEE-FFFFFFFFFFFF") + guid("01234567-89AB-CDEF-0123-456789ABCDEF")
    return block(0xA0000003, body)


def darwin_block(text="w_1^VX!!!!!!!!!MKKSkEXCELFiles>tW{~$4Q]c@II=l2xaTO5Z", ansi=None):
    a = (ansi if ansi is not None else text.encode("latin-1", "replace")).ljust(260, b"\x00")
    return block(0xA0000006, a + text.encode("utf-16le").ljust(520, b"\x00"))


def shim_block(name=b"WinXPSp3"):
    return block(0xA0000008, name.ljust(128, b"\x00"))


def known_folder_block(g="FDD39AD0-238F-46AF-ADB4-6C85480369C7", off=0x56):
    return block(0xA000000B, guid(g) + p32(off))


def special_folder_block(fid=0x24, off=0xDD):
    return block(0xA0000005, p32(fid) + p32(off))


def codepage_block(cp=1252):
    return block(0xA0000004, p32(cp))


def shell_item_block(*items):
    return block(0xA000000C, b"".join(items) + b"\x00\x00")


def typed(vt, value=b"", padding=0):
    return p16(vt) + p16(padding) + value


def lpwstr(text):
    raw = (text + "\x00").encode("utf-16le")
    return typed(0x1F, p32(len(raw) // 2) + raw)


def int_value(pid, tv):
    body = p32(pid) + b"\x00" + tv
    return p32(len(body) + 4) + body


def str_value(name, tv):
    nm = (name + "\x00").encode("utf-16le")
    body = p32(len(nm)) + b"\x00" + nm + tv
    return p32(len(body) + 4) + body


def storage(fmt, values):
    body = p32(0x53505331) + guid(fmt) + b"".join(values) + p32(0)
    return p32(len(body) + 4) + body


def metadata_block(*storages):
    return block(0xA0000009, b"".join(storages) + p32(0))


def unknown_block(sig=0xA00000FF, body=b"hidden payload"):
    return block(sig, body)


TERM = p32(0)

F_IDLIST, F_INFO, F_NAME, F_REL, F_WD, F_ARGS, F_ICON, F_UNI = 1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80
F_FORCENOINFO = 0x100


def strings(flags, uni=True, name="A shortcut", rel="..\\..\\Windows\\notepad.exe", wd="C:\\Windows",
            args="/c echo hi", icon="%SystemRoot%\\system32\\shell32.dll"):
    out = b""
    for f, v in ((F_NAME, name), (F_REL, rel), (F_WD, wd), (F_ARGS, args), (F_ICON, icon)):
        if flags & f:
            out += sdata(v, unicode=uni)
    return out


def lnk(flags, ids=None, info=None, uni=True, extras=(), tail=TERM, hdr_kw=None, **skw):
    if ids is not None:
        flags |= F_IDLIST
    if info is not None:
        flags |= F_INFO
    if uni:
        flags |= F_UNI
    data = header(flags, **(hdr_kw or {}))
    if ids is not None:
        data += ids
    if info is not None:
        data += info
    data += strings(flags, uni=uni, **skw)
    data += b"".join(extras) + tail
    return data


SFLAGS = F_NAME | F_REL | F_WD | F_ARGS | F_ICON
FMT_STR = "D5CDD505-2E9C-101B-9397-08002B2CF9AE"


def base_cases():
    c = {}
    typical_ids = idlist(root_folder(), volume(), file_entry(b"Windows", kind=0x31),
                         file_entry(b"notepad.exe", unicode_name="notepad.exe", kind=0x36))
    c["typical_local"] = lnk(SFLAGS, ids=typical_ids, info=link_info_local(),
                             extras=[env_block(), tracker_block(), known_folder_block(), special_folder_block()])
    c["header_only"] = header(0)
    c["header_only_term"] = header(0) + TERM
    c["empty"] = b""
    c["three_bytes"] = b"L\x00\x00"
    c["header_short_50"] = header(0)[:50]
    c["header_short_70"] = header(0)[:70]
    c["header_short_20"] = header(0)[:20]
    c["header_size_2"] = header(0, hsize=2)
    c["header_size_30"] = header(0, hsize=30) + TERM
    c["header_size_100"] = header(0, hsize=100) + b"\x00" * 24 + TERM
    c["bad_clsid"] = header(0, clsid=b"\xff" * 16) + TERM
    c["all_link_flags"] = header(0xFFFFFFFF, attrs=0xFFFFFFFF) + TERM
    c["all_flags_strings"] = lnk(0x07FFFF00 & ~F_FORCENOINFO, uni=True)
    for show in (0, 1, 3, 7, 0xFFFFFFFF):
        c[f"show_{show}"] = lnk(0, hdr_kw={"show": show})
    for hk in (0x0000, 0x0241, 0x0430, 0x0191, 0x0387, 0x0841, 0x02FF, 0x0170):
        c[f"hotkey_{hk:04x}"] = lnk(0, hdr_kw={"hotkey": hk})
    for name, t in (("zero", 0), ("max", 0x7FFFFFFFFFFFFFFF), ("min", -0x8000000000000000), ("neg", -1),
                    ("y1601", 1), ("y9999", 2650467743999999999), ("y10000", 2650467744000000000),
                    ("pre_epoch", 116444736000000000 - 15), ("half_us", 116444736000000005),
                    ("half_us2", 116444736000000015), ("big", 0x0123456789ABCDEF),
                    ("y1", -504911232000000000), ("y0", -504911232000000001)):
        c[f"filetime_{name}"] = lnk(0, hdr_kw={"ct": t, "at": t, "wt": t})
    c["icon_neg"] = lnk(0, hdr_kw={"icon": -5, "r0": 1, "r1": 2, "r2": 3})
    # strings
    c["strings_unicode"] = lnk(SFLAGS)
    c["strings_ansi"] = lnk(SFLAGS, uni=False)
    c["strings_ansi_cp1252"] = header(F_NAME | F_ARGS) + sdata(b"caf\xe9 \x80\x9f", unicode=False) + sdata(b"x\x81y", unicode=False) + TERM
    c["strings_ansi_utf8"] = header(F_NAME) + sdata("naïve ✓".encode("utf-8") + b"\xc3\x81", unicode=False) + TERM
    c["strings_unicode_astral"] = lnk(F_NAME | F_ARGS, name="emoji \U0001F600 \u00e9", args="\u4e2d\u6587 \"quoted\" \\path\\")
    c["strings_unicode_surrogates"] = header(F_UNI | F_NAME | F_ARGS) + p16(3) + b"\x00\xd8A\x00\x00\xdc" + p16(2) + b"\x00\xd8\x00\xdc" + TERM
    c["strings_embedded_null"] = lnk(F_NAME | F_ARGS, name="abc\x00def", args="x\x00y")
    long_args = " " * 300 + "powershell -enc AAAA" + "B" * 5000
    c["strings_long_args"] = lnk(F_NAME | F_ARGS | F_REL, name="n" * 300, args=long_args, rel="r" * 280)
    c["strings_truncated_count"] = header(F_UNI | F_NAME | F_ARGS) + p16(100) + "short".encode("utf-16le")
    c["strings_missing_args"] = header(F_UNI | F_REL | F_ARGS) + sdata("cmd.exe")
    c["strings_missing_rel"] = header(F_UNI | F_NAME | F_REL | F_ARGS) + sdata("name")
    c["strings_only_args_missing"] = header(F_UNI | F_ARGS)
    c["strings_odd_count"] = header(F_NAME) + p16(5) + b"abc"
    for rel in ("C:\\Program Files\\x.exe", "", "a\tb", "q\"uote", "back\\\\", "tr\\\"x\\", "plain"):
        c[f"command_{len(c)}"] = lnk(F_REL | F_ARGS, rel=rel, args="--flag \"v\"")
    c["command_rel_only"] = lnk(F_REL, rel="C:\\a b\\c.exe")
    c["command_args_only"] = lnk(F_ARGS, args="-x")
    # target id list items
    c["ids_all_types"] = lnk(0, ids=idlist(
        root_folder(), root_folder(0x42), root_folder(0x77), volume(), volume_guid(),
        file_entry(b"dir", kind=0x31), file_entry(b"file.txt", kind=0x32), file_entry(b"x", kind=0x30),
        file_entry(b"y", kind=0x38), file_entry(b"z", kind=0xB5, unicode_name="z\u00e9"),
        file_entry(b"bad", mtime=dos(2000, 13, 40, 25, 61, 62)), file_entry(b"nodate", mtime=p32(0)),
        network_location(), network_location(0x42, 0, b"\\\\host"), network_location(0x43, 0x80, desc=b"d"),
        network_location(0x47, 0x40), network_location(0x4D, 0x40),
        control_panel(), control_panel(0x70), control_panel_category(), control_panel_category(99),
        cpl_unicode(), cpl_ascii(), cpl_ascii(comments=b"ccc"), users_files_folder(),
        simple(0x52), simple(0x61), simple(0x72), simple(0x73), simple(0x99), simple(0x10), simple(0xFF, 30)))
    c["ids_empty"] = lnk(0, ids=idlist())
    c["ids_size_zero"] = header(F_IDLIST) + p16(0) + TERM
    c["ids_missing"] = header(F_IDLIST)
    c["ids_one_byte"] = header(F_IDLIST) + b"\x05"
    c["ids_item_one_byte"] = header(F_IDLIST) + p16(1) + b"\x07" + TERM
    c["ids_item_two_bytes"] = header(F_IDLIST) + p16(2) + p16(9) + TERM
    c["ids_item_size_1"] = header(F_IDLIST) + p16(6) + p16(1) + b"\x1f\x50\x00\x00" + TERM
    c["ids_netloc_no_desc_null"] = header(F_IDLIST) + idlist(item(b"\x41\x00\x80" + b"loc")) + TERM
    netloc = item(b"\x41\x00\x80" + b"loc")
    c["ids_netloc_stop_iteration"] = header(F_IDLIST) + p16(len(netloc)) + netloc
    c["extra_shell_item_stop_iteration"] = lnk(0, extras=[block(0xA000000C, netloc)], tail=b"")
    c["ids_netloc_short"] =header(F_IDLIST) + idlist(item(b"\x41")) + TERM
    c["ids_root_short"] = header(F_IDLIST) + idlist(item(b"\x1f\x50\x01\x02")) + TERM
    c["ids_file_short"] = header(F_IDLIST) + idlist(item(b"\x32\x00\x01\x02\x03\x04\x05")) + TERM
    c["ids_cpl_short"] = header(F_IDLIST) + idlist(item(b"\x00\x00\x01")) + TERM
    c["ids_users_short"] = header(F_IDLIST) + idlist(item(b"\x74\x00\x10\x00CFSF\x01")) + TERM
    c["ids_size_beyond"] = header(F_IDLIST) + p16(500) + volume() + TERM
    # link info
    c["info_local"] = lnk(F_NAME, info=link_info_local())
    c["info_local_unicode"] = lnk(F_NAME, info=link_info_local(unicode=True, suffix=b"sfx", usuffix="usfx", ubase="C:\\\u00e9"))
    c["info_local_label_unicode"] = lnk(F_NAME, info=link_info_local(label_unicode="L\u00e4bel"))
    c["info_local_drive_99"] = lnk(0, info=link_info_local(drive=99, label=b"", base=b"", suffix=b""))
    c["info_network"] = lnk(F_NAME, info=link_info_network())
    c["info_network_unicode"] = lnk(F_NAME, info=link_info_network(unicode=True, unet="\\\\S\u00e9RVER", udev="Y:"))
    c["info_network_providers"] = lnk(0, info=link_info_network(flags=2, provider=0x1A000, dev=b""))
    c["info_network_provider_dav"] = lnk(0, info=link_info_network(flags=2, provider=0x2E000))
    c["info_network_noflags"] = lnk(0, info=link_info_network(flags=0, net=b""))
    c["info_neither"] = lnk(0, info=p32(28) + p32(28) + p32(0) + b"\x00" * 16)
    c["info_forced_off"] = lnk(F_FORCENOINFO, info=link_info_local())
    c["info_short_flags"] = header(F_INFO) + p32(30) + p32(28)
    c["info_short_fields"] = header(F_INFO) + p32(30) + p32(28) + p32(1) + p32(28)
    c["info_bad_offsets"] = header(F_INFO) + p32(40) + p32(0x24) + p32(3) + p32(9999) + p32(5) + p32(9) + p32(7) + p32(1) + p32(2) + b"abc\x00defg\x00"
    c["info_size_huge"] = header(F_INFO | F_NAME) + p32(0xFFFFFFF0) + link_info_local()[4:]
    # extra blocks
    c["extra_all"] = lnk(F_NAME, extras=[
        env_block(), console_block(), tracker_block(), codepage_block(), special_folder_block(), darwin_block(),
        env_block(0xA0000007, b"%SystemRoot%\\icon.ico", "%SystemRoot%\\icon.ico"), shim_block(),
        metadata_block(
            storage("F29F85E0-4FF9-1068-AB91-08002B27B3D9", [int_value(2, lpwstr("Title")), int_value(5, typed(0x40, p32(0) * 2))]),
            storage(FMT_STR, [str_value("MyProp", lpwstr("value \u00e9")), str_value("Other", typed(0x13, p32(7)))]),
            storage("B725F130-47EF-101A-A5F1-02608C9EEBAC", [int_value(10, typed(0x1F, p32(3) + "ab\x00".encode("utf-16le"), padding=1))])),
        known_folder_block(), shell_item_block(root_folder(), file_entry(b"a.txt")),
        unknown_block(), unknown_block(0x12345678, b"x" * 40)])
    c["extra_terminal_appended"] = lnk(F_NAME, extras=[codepage_block()], tail=TERM + b"APPENDED DATA AFTER TERMINAL")
    c["extra_terminal_3"] = lnk(0, tail=p32(3) + b"more stuff")
    c["extra_no_terminal"] = lnk(0, extras=[codepage_block()], tail=b"")
    c["extra_partial_size"] = lnk(0, tail=b"\x05\x00")
    c["extra_size_1"] = lnk(0, tail=p32(1) + p32(0xA0000004) + b"abcd")
    c["extra_size_6"] = lnk(0, tail=p32(6) + b"\x04\x00\x00\xa0" + p32(0))
    c["extra_size_5_short"] = lnk(0, tail=p32(5) + b"\x01")
    c["extra_size_huge"] = lnk(0, tail=p32(0x7FFFFFFF) + p32(0xA0000001) + b"abc")
    c["extra_dup_codepage"] = lnk(0, extras=[codepage_block(1), unknown_block(), codepage_block(2), unknown_block(1, b"")])
    c["extra_console_short"] = lnk(0, extras=[block(0xA0000002, b"\x00" * 20)])
    c["extra_tracker_short"] = lnk(0, extras=[block(0xA0000003, b"\x00" * 40)])
    c["extra_tracker_bad"] = lnk(0, extras=[tracker_block(b"m" * 20, 1, 2)])
    c["extra_codepage_short"] = lnk(0, extras=[block(0xA0000004, b"")])
    c["extra_known_short"] = lnk(0, extras=[block(0xA000000B, b"\x01" * 18)])
    for i, txt in enumerate(["w_1^VX!!!!!!!!!MKKSkEXCELFiles>tW{~$4Q]c@II=l2xaTO5Z", "w_1^VX!!!!!!!!!MKKSk<",
                             "w_1^VX!!!!!!!!!MKKSkFeature<", "w_1^VX!!!!!!!!!MKKSk>tW{~$4Q]c@II=l2xaTO5Z",
                             "w_1^VX!!!!!!!!!MKKSknoterminator", "short", "", "~~~~~~~~~~~~~~~~~~~~x>~~~~~~~~~~~~~~~~~~~~",
                             "\u00e9\u00e9\u00e9\u00e9\u00e9!!!!!!!!!!!!!!!>!!!!!!!!!!!!!!!!!!!!", "w_1^VX!!!!!!!!!MKKSkA>short",
                             "\U0001F600" * 20 + "<", "<" * 25, "abcdefghijklmnopqrst>" + "\x00x"]):
        c[f"extra_darwin_{i}"] = lnk(0, extras=[darwin_block(txt)])
    c["extra_darwin_short_block"] = lnk(0, extras=[block(0xA0000006, b"abc")])
    c["extra_metadata_bad_type"] = lnk(0, extras=[metadata_block(storage("F29F85E0-4FF9-1068-AB91-08002B27B3D9", [int_value(2, typed(0x7777))]))])
    c["extra_metadata_i2"] = lnk(0, extras=[metadata_block(storage("F29F85E0-4FF9-1068-AB91-08002B27B3D9", [int_value(2, typed(0x02, p16(5)))]))])
    c["extra_metadata_empty"] = lnk(0, extras=[metadata_block()])
    c["extra_metadata_truncated"] = lnk(0, extras=[block(0xA0000009, p32(0x200) + p32(0x53505331))])
    c["extra_metadata_all_types"] = lnk(0, extras=[metadata_block(storage("F29F85E0-4FF9-1068-AB91-08002B27B3D9",
        [int_value(i, typed(vt, p32(0) * 4)) for i, vt in enumerate([0, 1, 3, 4, 5, 6, 7, 8, 0xA, 0xB, 0xE, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x1E, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x1002, 0x101F, 0x1048, 0x2002, 0x200E, 0x2017])]))])
    c["extra_shell_item_netloc"] = lnk(0, extras=[shell_item_block(item(b"\x41\x00\x80loc"))])
    c["extra_shell_item_short"] = lnk(0, extras=[shell_item_block(item(b"\x1f"))])
    c["extra_shim_odd"] = lnk(0, extras=[block(0xA0000008, b"\xff\xfe\x81x")])
    c["extra_env_short"] = lnk(0, extras=[block(0xA0000001, b"short")])
    c["kitchen_sink"] = lnk(SFLAGS, ids=typical_ids, info=link_info_network(unicode=True),
                            extras=[console_block(), darwin_block(), metadata_block(storage(FMT_STR, [str_value("k", lpwstr("v"))])),
                                    shell_item_block(network_location())], tail=TERM + b"\x01\x02\x03\x04\x05")
    return c


def mutate(rng, data):
    ops = []
    for _ in range(rng.choice([1, 1, 1, 2, 3, 5])):
        n = len(data)
        r = rng.random()
        lo = 8 if rng.random() < 0.95 else 0
        if n <= lo:
            op = ["i", n, bytes([rng.randrange(256)]).hex()]
        elif r < 0.35:
            op = ["s", rng.randrange(lo, n), rng.randrange(256)]
        elif r < 0.5:
            op = ["t", rng.randrange(lo, n)]
        elif r < 0.75:
            off = rng.randrange(lo, n)
            w = rng.choice([1, 2, 4])
            v = rng.choice([0, 1, 2, 3, 4, 5, 8, 0x10, 0x14, 0x1C, 0x24, 0x7F, 0x80, 0xFF, 0x100, 0x7FFF, 0xFFFF,
                            0x10000, 0x7FFFFFFF, 0xFFFFFFFF, rng.randrange(1 << 32)])
            op = ["i", off, (v & ((1 << (8 * w)) - 1)).to_bytes(w, "little").hex(), "x"]
        elif r < 0.88:
            off = rng.randrange(lo, n)
            op = ["d", off, rng.randrange(1, 9)]
        else:
            op = ["i", rng.randrange(lo, n + 1), bytes(rng.randrange(256) for _ in range(rng.randrange(1, 9))).hex()]
        data = apply(data, op)
        ops.append(op)
    return ops, data


def apply(data, op):
    kind = op[0]
    if kind == "s":
        return data[: op[1]] + bytes([op[2]]) + data[op[1] + 1:]
    if kind == "t":
        return data[: op[1]]
    if kind == "d":
        return data[: op[1]] + data[op[1] + op[2]:]
    if kind == "i":
        raw = bytes.fromhex(op[2])
        if len(op) > 3:  # overwrite
            return data[: op[1]] + raw + data[op[1] + len(raw):]
        return data[: op[1]] + raw + data[op[1]:]
    raise ValueError(op)


def _datetime_to_str(obj):
    if isinstance(obj, datetime.datetime):
        return obj.replace(microsecond=0).isoformat()
    return obj


def run(data):
    info, command, dump, err = {}, None, None, None
    try:
        lnk = LnkParse3.lnk_file(io.BytesIO(data))
        info = lnk.get_json(get_all=True)
        command = lnk.lnk_command
        fp = io.StringIO()
        try:
            json.dump(info, fp, indent=4, default=_datetime_to_str, sort_keys=True)
        except Exception:
            dump = {"partial": fp.getvalue()}
            raise
        dump = fp.getvalue()
    except Exception as e:  # noqa: BLE001
        err = {"type": type(e).__name__, "message": str(e)}
    stored = json.dumps(info, cls=_JSONEncoder, ensure_ascii=False, separators=(",", ":"))
    return {"error": err, "info": stored, "command": command, "dump": dump}


def sha(s):
    return None if s is None else hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()


def main():
    out_path = sys.argv[1]
    full_path = sys.argv[2] if len(sys.argv) > 2 else None
    bases = base_cases()
    names = list(bases)
    out = {"base": [], "mutations": []}
    full = []
    for name in names:
        r = run(bases[name])
        out["base"].append({"name": name, "data": base64.b64encode(bases[name]).decode(), **r})
    rng = random.Random(20261108)
    for _ in range(int(sys.argv[3]) if len(sys.argv) > 3 else 6000):
        bi = rng.randrange(len(names))
        ops, data = mutate(rng, bases[names[bi]])
        r = run(data)
        out["mutations"].append({"base": bi, "ops": ops, "error": r["error"], "info_sha256": sha(r["info"]),
                                 "command": r["command"], "dump_sha256": sha(r["dump"]) if isinstance(r["dump"], str) else r["dump"]})
        if full_path:
            full.append({"base": bi, "ops": ops, "data": base64.b64encode(data).decode(), **r})
    with open(out_path, "w") as fp:
        json.dump(out, fp, indent=0, ensure_ascii=True)
    if full_path:
        with open(full_path, "w") as fp:
            json.dump(full, fp, ensure_ascii=True)


if __name__ == "__main__":
    main()
