//! pcodedmp 1.2.6's disassembler. olevba compares its keywords with the source to detect VBA
//! stomping and embeds its text in its output, so the text is byte for byte what Python prints,
//! including the text of every exception that reaches an `Error: {}.` line.
//!
//! Offsets are i64: Python's are unbounded, but they only grow from u16 and u32 reads in loops of at
//! most 65535 steps. Only `get_id` can go negative. Python's `verbose` is always false here.
//! `translateOpcode`'s VBA3 branch is dead in Python too: `pcodeDump` sets the version first.

use std::fmt::Write;

use crate::codepage::Decoder;
use crate::ole::OleFile;
use crate::py::{PyErr, PyResult, decode_utf16le, memory_error};
use crate::vba::decompress_stream;

/// The most text one dumper holds. Python would go on until memory ran out, which a crafted file
/// can make it do with overlapping lines or a cycle of arguments, so past this a print raises
/// MemoryError and takes the path that real failure would.
pub const MAX_OUTPUT: usize = 64 * 1024 * 1024;

/// A mnemonic, its argument kinds and whether a counted block follows them.
type Op = (&'static str, &'static [&'static str], bool);

const OPCODES: [Op; 264] = [
    ("Imp", &[], false),
    ("Eqv", &[], false),
    ("Xor", &[], false),
    ("Or", &[], false),
    ("And", &[], false),
    ("Eq", &[], false),
    ("Ne", &[], false),
    ("Le", &[], false),
    ("Ge", &[], false),
    ("Lt", &[], false),
    ("Gt", &[], false),
    ("Add", &[], false),
    ("Sub", &[], false),
    ("Mod", &[], false),
    ("IDiv", &[], false),
    ("Mul", &[], false),
    ("Div", &[], false),
    ("Concat", &[], false),
    ("Like", &[], false),
    ("Pwr", &[], false),
    ("Is", &[], false),
    ("Not", &[], false),
    ("UMi", &[], false),
    ("FnAbs", &[], false),
    ("FnFix", &[], false),
    ("FnInt", &[], false),
    ("FnSgn", &[], false),
    ("FnLen", &[], false),
    ("FnLenB", &[], false),
    ("Paren", &[], false),
    ("Sharp", &[], false),
    ("LdLHS", &["name"], false),
    ("Ld", &["name"], false),
    ("MemLd", &["name"], false),
    ("DictLd", &["name"], false),
    ("IndexLd", &["0x"], false),
    ("ArgsLd", &["name", "0x"], false),
    ("ArgsMemLd", &["name", "0x"], false),
    ("ArgsDictLd", &["name", "0x"], false),
    ("St", &["name"], false),
    ("MemSt", &["name"], false),
    ("DictSt", &["name"], false),
    ("IndexSt", &["0x"], false),
    ("ArgsSt", &["name", "0x"], false),
    ("ArgsMemSt", &["name", "0x"], false),
    ("ArgsDictSt", &["name", "0x"], false),
    ("Set", &["name"], false),
    ("Memset", &["name"], false),
    ("Dictset", &["name"], false),
    ("Indexset", &["0x"], false),
    ("ArgsSet", &["name", "0x"], false),
    ("ArgsMemSet", &["name", "0x"], false),
    ("ArgsDictSet", &["name", "0x"], false),
    ("MemLdWith", &["name"], false),
    ("DictLdWith", &["name"], false),
    ("ArgsMemLdWith", &["name", "0x"], false),
    ("ArgsDictLdWith", &["name", "0x"], false),
    ("MemStWith", &["name"], false),
    ("DictStWith", &["name"], false),
    ("ArgsMemStWith", &["name", "0x"], false),
    ("ArgsDictStWith", &["name", "0x"], false),
    ("MemSetWith", &["name"], false),
    ("DictSetWith", &["name"], false),
    ("ArgsMemSetWith", &["name", "0x"], false),
    ("ArgsDictSetWith", &["name", "0x"], false),
    ("ArgsCall", &["name", "0x"], false),
    ("ArgsMemCall", &["name", "0x"], false),
    ("ArgsMemCallWith", &["name", "0x"], false),
    ("ArgsArray", &["name", "0x"], false),
    ("Assert", &[], false),
    ("BoS", &["0x"], false),
    ("BoSImplicit", &[], false),
    ("BoL", &[], false),
    ("LdAddressOf", &["name"], false),
    ("MemAddressOf", &["name"], false),
    ("Case", &[], false),
    ("CaseTo", &[], false),
    ("CaseGt", &[], false),
    ("CaseLt", &[], false),
    ("CaseGe", &[], false),
    ("CaseLe", &[], false),
    ("CaseNe", &[], false),
    ("CaseEq", &[], false),
    ("CaseElse", &[], false),
    ("CaseDone", &[], false),
    ("Circle", &["0x"], false),
    ("Close", &["0x"], false),
    ("CloseAll", &[], false),
    ("Coerce", &[], false),
    ("CoerceVar", &[], false),
    ("Context", &["context_"], false),
    ("Debug", &[], false),
    ("DefType", &["0x", "0x"], false),
    ("Dim", &[], false),
    ("DimImplicit", &[], false),
    ("Do", &[], false),
    ("DoEvents", &[], false),
    ("DoUnitil", &[], false),
    ("DoWhile", &[], false),
    ("Else", &[], false),
    ("ElseBlock", &[], false),
    ("ElseIfBlock", &[], false),
    ("ElseIfTypeBlock", &["imp_"], false),
    ("End", &[], false),
    ("EndContext", &[], false),
    ("EndFunc", &[], false),
    ("EndIf", &[], false),
    ("EndIfBlock", &[], false),
    ("EndImmediate", &[], false),
    ("EndProp", &[], false),
    ("EndSelect", &[], false),
    ("EndSub", &[], false),
    ("EndType", &[], false),
    ("EndWith", &[], false),
    ("Erase", &["0x"], false),
    ("Error", &[], false),
    ("EventDecl", &["func_"], false),
    ("RaiseEvent", &["name", "0x"], false),
    ("ArgsMemRaiseEvent", &["name", "0x"], false),
    ("ArgsMemRaiseEventWith", &["name", "0x"], false),
    ("ExitDo", &[], false),
    ("ExitFor", &[], false),
    ("ExitFunc", &[], false),
    ("ExitProp", &[], false),
    ("ExitSub", &[], false),
    ("FnCurDir", &[], false),
    ("FnDir", &[], false),
    ("Empty0", &[], false),
    ("Empty1", &[], false),
    ("FnError", &[], false),
    ("FnFormat", &[], false),
    ("FnFreeFile", &[], false),
    ("FnInStr", &[], false),
    ("FnInStr3", &[], false),
    ("FnInStr4", &[], false),
    ("FnInStrB", &[], false),
    ("FnInStrB3", &[], false),
    ("FnInStrB4", &[], false),
    ("FnLBound", &["0x"], false),
    ("FnMid", &[], false),
    ("FnMidB", &[], false),
    ("FnStrComp", &[], false),
    ("FnStrComp3", &[], false),
    ("FnStringVar", &[], false),
    ("FnStringStr", &[], false),
    ("FnUBound", &["0x"], false),
    ("For", &[], false),
    ("ForEach", &[], false),
    ("ForEachAs", &["imp_"], false),
    ("ForStep", &[], false),
    ("FuncDefn", &["func_"], false),
    ("FuncDefnSave", &["func_"], false),
    ("GetRec", &[], false),
    ("GoSub", &["name"], false),
    ("GoTo", &["name"], false),
    ("If", &[], false),
    ("IfBlock", &[], false),
    ("TypeOf", &["imp_"], false),
    ("IfTypeBlock", &["imp_"], false),
    ("Implements", &["0x", "0x", "0x", "0x"], false),
    ("Input", &[], false),
    ("InputDone", &[], false),
    ("InputItem", &[], false),
    ("Label", &["name"], false),
    ("Let", &[], false),
    ("Line", &["0x"], false),
    ("LineCont", &[], true),
    ("LineInput", &[], false),
    ("LineNum", &["name"], false),
    ("LitCy", &["0x", "0x", "0x", "0x"], false),
    ("LitDate", &["0x", "0x", "0x", "0x"], false),
    ("LitDefault", &[], false),
    ("LitDI2", &["0x"], false),
    ("LitDI4", &["0x", "0x"], false),
    ("LitDI8", &["0x", "0x", "0x", "0x"], false),
    ("LitHI2", &["0x"], false),
    ("LitHI4", &["0x", "0x"], false),
    ("LitHI8", &["0x", "0x", "0x", "0x"], false),
    ("LitNothing", &[], false),
    ("LitOI2", &["0x"], false),
    ("LitOI4", &["0x", "0x"], false),
    ("LitOI8", &["0x", "0x", "0x", "0x"], false),
    ("LitR4", &["0x", "0x"], false),
    ("LitR8", &["0x", "0x", "0x", "0x"], false),
    ("LitSmallI2", &[], false),
    ("LitStr", &[], true),
    ("LitVarSpecial", &[], false),
    ("Lock", &[], false),
    ("Loop", &[], false),
    ("LoopUntil", &[], false),
    ("LoopWhile", &[], false),
    ("LSet", &[], false),
    ("Me", &[], false),
    ("MeImplicit", &[], false),
    ("MemRedim", &["name", "0x", "type_"], false),
    ("MemRedimWith", &["name", "0x", "type_"], false),
    ("MemRedimAs", &["name", "0x", "type_"], false),
    ("MemRedimAsWith", &["name", "0x", "type_"], false),
    ("Mid", &[], false),
    ("MidB", &[], false),
    ("Name", &[], false),
    ("New", &["imp_"], false),
    ("Next", &[], false),
    ("NextVar", &[], false),
    ("OnError", &["name"], false),
    ("OnGosub", &[], true),
    ("OnGoto", &[], true),
    ("Open", &["0x"], false),
    ("Option", &[], false),
    ("OptionBase", &[], false),
    ("ParamByVal", &[], false),
    ("ParamOmitted", &[], false),
    ("ParamNamed", &["name"], false),
    ("PrintChan", &[], false),
    ("PrintComma", &[], false),
    ("PrintEoS", &[], false),
    ("PrintItemComma", &[], false),
    ("PrintItemNL", &[], false),
    ("PrintItemSemi", &[], false),
    ("PrintNL", &[], false),
    ("PrintObj", &[], false),
    ("PrintSemi", &[], false),
    ("PrintSpc", &[], false),
    ("PrintTab", &[], false),
    ("PrintTabComma", &[], false),
    ("PSet", &["0x"], false),
    ("PutRec", &[], false),
    ("QuoteRem", &["0x"], true),
    ("Redim", &["name", "0x", "type_"], false),
    ("RedimAs", &["name", "0x", "type_"], false),
    ("Reparse", &[], true),
    ("Rem", &[], true),
    ("Resume", &["name"], false),
    ("Return", &[], false),
    ("RSet", &[], false),
    ("Scale", &["0x"], false),
    ("Seek", &[], false),
    ("SelectCase", &[], false),
    ("SelectIs", &["imp_"], false),
    ("SelectType", &[], false),
    ("SetStmt", &[], false),
    ("Stack", &["0x", "0x"], false),
    ("Stop", &[], false),
    ("Type", &["rec_"], false),
    ("Unlock", &[], false),
    ("VarDefn", &["var_"], false),
    ("Wend", &[], false),
    ("While", &[], false),
    ("With", &[], false),
    ("WriteChan", &[], false),
    ("ConstFuncExpr", &[], false),
    ("LbConst", &["name"], false),
    ("LbIf", &[], false),
    ("LbElse", &[], false),
    ("LbElseIf", &[], false),
    ("LbEndIf", &[], false),
    ("LbMark", &[], false),
    ("EndForVariable", &[], false),
    ("StartForVariable", &[], false),
    ("NewRedim", &[], false),
    ("StartWithExpr", &[], false),
    ("SetOrSt", &["name"], false),
    ("EndEnum", &[], false),
    ("Illegal", &[], false),
];

const INTERNAL_NAMES: [&str; 255] = [
    "<crash>",
    "0",
    "Abs",
    "Access",
    "AddressOf",
    "Alias",
    "And",
    "Any",
    "Append",
    "Array",
    "As",
    "Assert",
    "B",
    "Base",
    "BF",
    "Binary",
    "Boolean",
    "ByRef",
    "Byte",
    "ByVal",
    "Call",
    "Case",
    "CBool",
    "CByte",
    "CCur",
    "CDate",
    "CDec",
    "CDbl",
    "CDecl",
    "ChDir",
    "CInt",
    "Circle",
    "CLng",
    "Close",
    "Compare",
    "Const",
    "CSng",
    "CStr",
    "CurDir",
    "CurDir$",
    "CVar",
    "CVDate",
    "CVErr",
    "Currency",
    "Database",
    "Date",
    "Date$",
    "Debug",
    "Decimal",
    "Declare",
    "DefBool",
    "DefByte",
    "DefCur",
    "DefDate",
    "DefDec",
    "DefDbl",
    "DefInt",
    "DefLng",
    "DefObj",
    "DefSng",
    "DefStr",
    "DefVar",
    "Dim",
    "Dir",
    "Dir$",
    "Do",
    "DoEvents",
    "Double",
    "Each",
    "Else",
    "ElseIf",
    "Empty",
    "End",
    "EndIf",
    "Enum",
    "Eqv",
    "Erase",
    "Error",
    "Error$",
    "Event",
    "WithEvents",
    "Explicit",
    "F",
    "False",
    "Fix",
    "For",
    "Format",
    "Format$",
    "FreeFile",
    "Friend",
    "Function",
    "Get",
    "Global",
    "Go",
    "GoSub",
    "Goto",
    "If",
    "Imp",
    "Implements",
    "In",
    "Input",
    "Input$",
    "InputB",
    "InputB",
    "InStr",
    "InputB$",
    "Int",
    "InStrB",
    "Is",
    "Integer",
    "Left",
    "LBound",
    "LenB",
    "Len",
    "Lib",
    "Let",
    "Line",
    "Like",
    "Load",
    "Local",
    "Lock",
    "Long",
    "Loop",
    "LSet",
    "Me",
    "Mid",
    "Mid$",
    "MidB",
    "MidB$",
    "Mod",
    "Module",
    "Name",
    "New",
    "Next",
    "Not",
    "Nothing",
    "Null",
    "Object",
    "On",
    "Open",
    "Option",
    "Optional",
    "Or",
    "Output",
    "ParamArray",
    "Preserve",
    "Print",
    "Private",
    "Property",
    "PSet",
    "Public",
    "Put",
    "RaiseEvent",
    "Random",
    "Randomize",
    "Read",
    "ReDim",
    "Rem",
    "Resume",
    "Return",
    "RGB",
    "RSet",
    "Scale",
    "Seek",
    "Select",
    "Set",
    "Sgn",
    "Shared",
    "Single",
    "Spc",
    "Static",
    "Step",
    "Stop",
    "StrComp",
    "String",
    "String$",
    "Sub",
    "Tab",
    "Text",
    "Then",
    "To",
    "True",
    "Type",
    "TypeOf",
    "UBound",
    "Unload",
    "Unlock",
    "Unknown",
    "Until",
    "Variant",
    "WEnd",
    "While",
    "Width",
    "With",
    "Write",
    "Xor",
    "#Const",
    "#Else",
    "#ElseIf",
    "#End",
    "#If",
    "Attribute",
    "VB_Base",
    "VB_Control",
    "VB_Creatable",
    "VB_Customizable",
    "VB_Description",
    "VB_Exposed",
    "VB_Ext_Key",
    "VB_HelpID",
    "VB_Invoke_Func",
    "VB_Invoke_Property",
    "VB_Invoke_PropertyPut",
    "VB_Invoke_PropertyPutRef",
    "VB_MemberFlags",
    "VB_Name",
    "VB_PredecraredID",
    "VB_ProcData",
    "VB_TemplateDerived",
    "VB_VarDescription",
    "VB_VarHelpID",
    "VB_VarMemberFlags",
    "VB_VarProcData",
    "VB_UserMemID",
    "VB_VarUserMemID",
    "VB_GlobalNameSpace",
    ",",
    ".",
    "\"",
    "_",
    "!",
    "#",
    "&",
    "'",
    "(",
    ")",
    "*",
    "+",
    "-",
    " /",
    ":",
    ";",
    "<",
    "<=",
    "<>",
    "=",
    "=<",
    "=>",
    ">",
    "><",
    ">=",
    "?",
    "\\",
    "^",
    ":=",
];

fn tag_name(tag: i64) -> &'static str {
    match tag {
        1 => "PROJ_SYSKIND",
        2 => "PROJ_LCID",
        3 => "PROJ_CODEPAGE",
        4 => "PROJ_NAME",
        5 => "PROJ_DOCSTRING",
        6 => "PROJ_HELPFILE",
        7 => "PROJ_HELPCONTEXT",
        8 => "PROJ_LIBFLAGS",
        9 => "PROJ_VERSION",
        10 => "PROJ_GUID",
        11 => "PROJ_PROPERTIES",
        12 => "PROJ_CONSTANTS",
        13 => "PROJ_LIBID_REGISTERED",
        14 => "PROJ_LIBID_PROJ",
        15 => "PROJ_MODULECOUNT",
        16 => "PROJ_EOF",
        17 => "PROJ_TYPELIB_VERSION",
        18 => "PROJ_COMPAT_EXE",
        19 => "PROJ_COOKIE",
        20 => "PROJ_LCIDINVOKE",
        21 => "PROJ_COMMAND_LINE",
        22 => "PROJ_REFNAME_PROJ",
        25 => "MOD_NAME",
        26 => "MOD_STREAM",
        28 => "MOD_DOCSTRING",
        29 => "MOD_HELPFILE",
        30 => "MOD_HELPCONTEXT",
        32 => "MOD_PROPERTIES",
        33 => "MOD_FBASMOD_StdMods",
        34 => "MOD_FBASMOD_Classes",
        35 => "MOD_FBASMOD_Creatable",
        36 => "MOD_FBASMOD_NoDisplay",
        37 => "MOD_FBASMOD_NoEdit",
        38 => "MOD_FBASMOD_RefLibs",
        39 => "MOD_FBASMOD_NonBasic",
        40 => "MOD_FBASMOD_Private",
        41 => "MOD_FBASMOD_Internal",
        42 => "MOD_FBASMOD_AllModTypes",
        43 => "MOD_END",
        44 => "MOD_COOKIETYPE",
        45 => "MOD_BASECLASSNULL",
        46 => "MOD_BASECLASS",
        47 => "PROJ_LIBID_TWIDDLED",
        48 => "PROJ_LIBID_EXTENDED",
        49 => "MOD_TEXTOFFSET",
        50 => "MOD_UNICODESTREAM",
        60 => "PROJ_UNICODE_CONSTANTS",
        61 => "PROJ_UNICODE_HELPFILE",
        62 => "PROJ_UNICODE_REFNAME_PROJ",
        63 => "PROJ_UNICODE_COMMAND_LINE",
        64 => "PROJ_UNICODE_DOCSTRING",
        71 => "MOD_UNICODE_NAME",
        72 => "MOD_UNICODE_DOCSTRING",
        73 => "MOD_UNICODE_HELPFILE",
        _ => "UNKNOWN",
    }
}

const VAR_TYPES: [&str; 14] = [
    "", "?", "%", "&", "!", "#", "@", "?", "$", "?", "?", "?", "?", "?",
];
const VAR_TYPES_LONG: [&str; 13] = [
    "Var", "?", "Int", "Lng", "Sng", "Dbl", "Cur", "Date", "Str", "Obj", "Err", "Bool", "Var",
];
const DIM_TYPES: [&str; 18] = [
    "", "Null", "Integer", "Long", "Single", "Double", "Currency", "Date", "String", "Object",
    "Error", "Boolean", "Variant", "", "Decimal", "", "", "Byte",
];
const SPECIALS: [&str; 4] = ["False", "True", "Null", "Empty"];
const OPTIONS: [&str; 6] = [
    "Base 0",
    "Base 1",
    "Compare Text",
    "Compare Binary",
    "Explicit",
    "Private Module",
];
const ACCESS_MODE: [&str; 3] = ["Read", "Write", "Read Write"];
const LOCK_MODE: [&str; 3] = ["Read Write", "Write", "Read"];

fn hexdump(buffer: &[u8]) -> String {
    let mut result = String::new();
    for (index, data) in buffer.chunks(16).enumerate() {
        let hex = hex_bytes(data);
        let text: String = data
            .iter()
            .map(|&byte| {
                if 31 < byte && byte < 127 {
                    char::from(byte)
                } else {
                    '.'
                }
            })
            .collect();
        writeln!(result, "{:08X}   {hex:47}    {text}", index * 16)
            .expect("a String takes any text");
    }
    result
}

fn hex_bytes(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 3);
    for (index, byte) in data.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        write!(out, "{byte:02X}").expect("a String takes any text");
    }
    out
}

/// `unpack_from` of a little- or big-endian integer. `offset` is never negative.
fn unpack_from<const N: usize>(buffer: &[u8], offset: i64) -> PyResult<[u8; N]> {
    let size = N as i64;
    let len = buffer.len() as i64;
    if len - offset < size {
        return Err(PyErr::new(
            "error",
            format!(
                "unpack_from requires a buffer of at least {} bytes for unpacking {size} bytes at offset \
                 {offset} (actual buffer size is {len})",
                offset + size
            ),
        ));
    }
    let mut out = [0; N];
    out.copy_from_slice(&buffer[offset as usize..(offset + size) as usize]);
    Ok(out)
}

fn get_word(buffer: &[u8], offset: i64, big: bool) -> PyResult<i64> {
    let bytes = unpack_from::<2>(buffer, offset)?;
    Ok(i64::from(if big {
        u16::from_be_bytes(bytes)
    } else {
        u16::from_le_bytes(bytes)
    }))
}

fn get_dword(buffer: &[u8], offset: i64, big: bool) -> PyResult<i64> {
    let bytes = unpack_from::<4>(buffer, offset)?;
    Ok(i64::from(if big {
        u32::from_be_bytes(bytes)
    } else {
        u32::from_le_bytes(bytes)
    }))
}

fn skip_structure(
    buffer: &[u8],
    mut offset: i64,
    big: bool,
    is_length_dw: bool,
    element_size: i64,
    check_for_minus_one: bool,
) -> PyResult<i64> {
    let (length, skip);
    if is_length_dw {
        length = get_dword(buffer, offset, big)?;
        offset += 4;
        skip = check_for_minus_one && length == 0xFFFF_FFFF;
    } else {
        length = get_word(buffer, offset, big)?;
        offset += 2;
        skip = check_for_minus_one && length == 0xFFFF;
    }
    if !skip {
        offset += length * element_size;
    }
    Ok(offset)
}

fn get_var_word(buffer: &[u8], offset: &mut i64, big: bool) -> PyResult<i64> {
    let value = get_word(buffer, *offset, big)?;
    *offset += 2;
    Ok(value)
}

fn get_var_dword(buffer: &[u8], offset: &mut i64, big: bool) -> PyResult<i64> {
    let value = get_dword(buffer, *offset, big)?;
    *offset += 4;
    Ok(value)
}

/// `buffer[index]`.
fn byte_at(buffer: &[u8], index: i64) -> PyResult<i64> {
    usize::try_from(index)
        .ok()
        .and_then(|at| buffer.get(at))
        .map(|&byte| i64::from(byte))
        .ok_or_else(|| PyErr::new("IndexError", "index out of range"))
}

/// `buffer[start:stop]`, for a start and stop that aren't negative.
fn slice(buffer: &[u8], start: i64, stop: i64) -> &[u8] {
    let len = buffer.len() as i64;
    let start = start.clamp(0, len);
    let stop = stop.clamp(start, len);
    &buffer[start as usize..stop as usize]
}

fn get_type_and_length(buffer: &[u8], offset: i64, big: bool) -> PyResult<(i64, i64)> {
    if big {
        Ok((byte_at(buffer, offset)?, byte_at(buffer, offset + 1)?))
    } else {
        Ok((byte_at(buffer, offset + 1)?, byte_at(buffer, offset)?))
    }
}

/// `getTheIdentifiers`, down to its `except`. What was read before an exception stays in `identifiers`.
fn read_identifiers(data: &[u8], codec: Decoder, identifiers: &mut Vec<String>) -> PyResult<()> {
    let magic = get_word(data, 0, false)?;
    if magic != 0x61CC {
        return Ok(());
    }
    let version = get_word(data, 2, false)?;
    let excluded = matches!(version, 0x60 | 0x62 | 0x63);
    let unicode_ref = (version >= 0x5B && !excluded) || version == 0x4E;
    let unicode_name = (version >= 0x59 && !excluded) || version == 0x4E;
    // Python's second half, `0x5F > version > 0x6B`, is never true
    let non_unicode_name = version <= 0x59 && version != 0x4E;
    let big = get_word(data, 5, false)? == 0x000E;
    let mut offset = 0x1E;
    let num_refs = get_var_word(data, &mut offset, big)?;
    offset += 2;
    for _ in 0..num_refs {
        let ref_length = get_var_word(data, &mut offset, big)?;
        if ref_length == 0 {
            offset += 6;
        } else if (unicode_ref && ref_length < 5) || (!unicode_ref && ref_length < 3) {
            offset += ref_length;
        } else {
            let c = byte_at(data, offset + if unicode_ref { 4 } else { 2 })?;
            offset += ref_length;
            if c == 0x43 || c == 0x44 {
                offset = skip_structure(data, offset, big, false, 1, false)?;
            }
        }
        offset += 10;
        let word = get_var_word(data, &mut offset, big)?;
        if word != 0 {
            offset = skip_structure(data, offset, big, false, 1, false)?;
            let length = get_var_word(data, &mut offset, big)?;
            if length != 0 {
                offset += 2;
            }
            offset += length + 30;
        }
    }
    // the class/user forms table, then the compile-time identifier-value pairs
    offset = skip_structure(data, offset, big, false, 2, false)?;
    offset = skip_structure(data, offset, big, false, 4, false)?;
    offset += 2;
    // typeinfo typeID, project description, project help file name
    offset = skip_structure(data, offset, big, false, 1, true)?;
    offset = skip_structure(data, offset, big, false, 1, true)?;
    offset = skip_structure(data, offset, big, false, 1, true)?;
    offset += 0x64;
    // the module descriptors
    let num_projects = get_var_word(data, &mut offset, big)?;
    for _ in 0..num_projects {
        let mut length = get_var_word(data, &mut offset, big)?;
        if unicode_name {
            offset += length;
        }
        if non_unicode_name {
            if length != 0 {
                length = get_var_word(data, &mut offset, big)?;
            }
            offset += length;
        }
        offset = skip_structure(data, offset, big, false, 1, false)?;
        offset = skip_structure(data, offset, big, false, 1, true)?;
        get_var_word(data, &mut offset, big)?;
        if version >= 0x6B {
            offset = skip_structure(data, offset, big, false, 1, true)?;
        }
        offset = skip_structure(data, offset, big, false, 1, true)?;
        offset += 2;
        if version != 0x51 {
            offset += 4;
        }
        offset = skip_structure(data, offset, big, false, 8, false)?;
        offset += 11;
    }
    offset += 6;
    offset = skip_structure(data, offset, big, true, 1, false)?;
    offset += 6;
    let w0 = get_var_word(data, &mut offset, big)?;
    let num_ids = get_var_word(data, &mut offset, big)?;
    let w1 = get_var_word(data, &mut offset, big)?;
    offset += 4;
    // either count can be negative, and a negative count runs no loop
    let num_junk_ids = num_ids + w1 - w0;
    let num_ids = w0 - w1;
    for _ in 0..num_junk_ids {
        offset += 4;
        let (id_type, id_length) = get_type_and_length(data, offset, big)?;
        offset += 2;
        if id_type > 0x7F {
            offset += 6;
        }
        offset += id_length;
    }
    // offset now points to the variable names
    for _ in 0..num_ids {
        let mut is_kwd = false;
        let (mut id_type, mut id_length) = get_type_and_length(data, offset, big)?;
        offset += 2;
        if id_length == 0 && id_type == 0 {
            offset += 2;
            (id_type, id_length) = get_type_and_length(data, offset, big)?;
            offset += 2;
            is_kwd = true;
        }
        if id_type & 0x80 != 0 {
            offset += 6;
        }
        if id_length != 0 {
            identifiers.push(codec.decode(slice(data, offset, offset + id_length)));
            offset += id_length;
        }
        if !is_kwd {
            offset += 4;
        }
    }
    Ok(())
}

fn translate_opcode(opcode: i64, vba_ver: i64, is64bit: bool) -> i64 {
    if vba_ver == 5 {
        opcode
            + match opcode {
                0..=68 => 0,
                69..=71 => 1,
                72..=112 => 3,
                113..=151 => 7,
                152..=165 => 8,
                166..=167 => 9,
                168..=170 => 10,
                _ => 11,
            }
    } else if !is64bit {
        opcode
            + match opcode {
                0..=173 => 0,
                174..=175 => 1,
                176..=178 => 2,
                _ => 3,
            }
    } else {
        opcode
    }
}

/// `identifiers[index]`, which counts back from the end when negative.
fn list_get(identifiers: &[String], index: i64) -> Option<&String> {
    let at = if index < 0 {
        index + identifiers.len() as i64
    } else {
        index
    };
    usize::try_from(at).ok().and_then(|at| identifiers.get(at))
}

/// What the disassembly reads besides the current position: one module's tables and the project's names.
struct Module<'a> {
    data: &'a [u8],
    indirect: &'a [u8],
    object: &'a [u8],
    declaration: &'a [u8],
    identifiers: &'a [String],
    big: bool,
    vba_ver: i64,
    is64bit: bool,
}

impl Module<'_> {
    fn get_id(&self, code: i64) -> String {
        let mut id = code >> 1;
        let name = if id >= 0x100 {
            id -= 0x100;
            if self.vba_ver >= 7 {
                id -= 4;
                if self.is64bit {
                    id -= 3;
                }
                if id > 0xBE {
                    id -= 1;
                }
            }
            list_get(self.identifiers, id).map(String::as_str)
        } else {
            if self.vba_ver >= 7 && id >= 0xC3 {
                id -= 1;
            }
            INTERNAL_NAMES.get(id as usize).copied()
        };
        name.map_or_else(|| format!("id_{code:04X}"), str::to_owned)
    }

    fn get_name(&self, buffer: &[u8], offset: i64) -> PyResult<String> {
        Ok(self.get_id(get_word(buffer, offset, self.big)?))
    }

    fn disasm_name(&self, word: i64, mnemonic: &str, op_type: i64) -> String {
        let mut var_name = self.get_id(word);
        let mut str_type = "";
        if let Some(&var_type) = VAR_TYPES.get(op_type as usize) {
            str_type = var_type;
        } else if op_type == 32 {
            var_name = format!("[{var_name}]");
        }
        if mnemonic == "OnError" {
            str_type = "";
            if op_type == 1 {
                var_name = "(Resume Next)".to_owned();
            } else if op_type == 2 {
                var_name = "(GoTo 0)".to_owned();
            }
        } else if mnemonic == "Resume" {
            str_type = "";
            if op_type == 1 {
                var_name = "(Next)".to_owned();
            } else if op_type != 0 {
                var_name = String::new();
            }
        }
        format!("{var_name}{str_type} ")
    }

    fn disasm_imp(&self, arg: &str, word: i64, mnemonic: &str) -> PyResult<String> {
        if mnemonic != "Open" {
            if arg == "imp_" && self.object.len() as i64 >= word + 8 {
                return self.get_name(self.object, word + 6);
            }
            return Ok(format!("{arg}{word:04X} "));
        }
        let mode = word & 0x00FF;
        let access = (word & 0x0F00) >> 8;
        let lock = (word & 0xF000) >> 12;
        let mut name = "(For ".to_owned();
        if mode & 0x01 != 0 {
            name += "Input";
        } else if mode & 0x02 != 0 {
            name += "Output";
        } else if mode & 0x04 != 0 {
            name += "Random";
        } else if mode & 0x08 != 0 {
            name += "Append";
        } else if mode == 0x20 {
            name += "Binary";
        }
        if access != 0 && access <= 3 {
            name += " Access ";
            name += ACCESS_MODE[access as usize - 1];
        }
        if lock != 0 {
            if lock & 0x04 != 0 {
                name += " Shared";
            } else if lock <= 3 {
                name += " Lock ";
                name += LOCK_MODE[lock as usize - 1];
            }
        }
        name.push(')');
        Ok(name)
    }

    fn disasm_rec(&self, dword: i64) -> PyResult<String> {
        let name = self.get_name(self.indirect, dword + 2)?;
        let options = get_word(self.indirect, dword + 18, self.big)?;
        Ok(if options & 1 == 0 {
            format!("(Private) {name}")
        } else {
            name
        })
    }

    fn disasm_type(&self, dword: i64) -> PyResult<String> {
        let type_id = byte_at(self.indirect, dword + 6)?;
        Ok(match DIM_TYPES.get(type_id as usize) {
            Some(name) => (*name).to_owned(),
            None => format!("type_{dword:08X}"),
        })
    }

    fn disasm_object(&self, offset: i64) -> PyResult<String> {
        if self.is64bit {
            return Ok(String::new());
        }
        let type_desc = get_dword(self.indirect, offset, self.big)?;
        let flags = get_word(self.indirect, type_desc, self.big)?;
        if flags & 0x02 != 0 {
            return self.disasm_type(type_desc);
        }
        let word = get_word(self.indirect, type_desc + 2, self.big)?;
        if word == 0 {
            return Ok(String::new());
        }
        let offs = (word >> 2) * 10;
        if offs + 4 > self.object.len() as i64 {
            return Ok(String::new());
        }
        get_word(self.object, offs, self.big)?;
        let hl_name = get_word(self.object, offs + 6, self.big)?;
        Ok(self.get_id(hl_name))
    }

    fn disasm_var(&self, dword: i64) -> PyResult<String> {
        let flag1 = byte_at(self.indirect, dword)?;
        let flag2 = byte_at(self.indirect, dword + 1)?;
        let has_as = flag1 & 0x20 != 0;
        let has_new = flag2 & 0x20 != 0;
        let mut var_name = self.get_name(self.indirect, dword + 2)?;
        if has_new || has_as {
            let mut var_type = String::new();
            if has_new {
                var_type += "New";
                if has_as {
                    var_type.push(' ');
                }
            }
            if has_as {
                let offs = if self.is64bit { 16 } else { 12 };
                let word = get_word(self.indirect, dword + offs + 2, self.big)?;
                let type_name = if word == 0xFFFF {
                    get_type_name(byte_at(self.indirect, dword + offs)?)
                } else {
                    self.disasm_object(dword + offs)?
                };
                if !type_name.is_empty() {
                    var_type += "As ";
                    var_type += &type_name;
                }
            }
            if !var_type.is_empty() {
                write!(var_name, " ({var_type})").expect("a String takes any text");
            }
        }
        Ok(var_name)
    }

    fn disasm_arg(&self, arg_offset: i64) -> PyResult<String> {
        let flags = get_word(self.indirect, arg_offset, self.big)?;
        let offs = if self.is64bit { 4 } else { 0 };
        let mut arg_name = self.get_name(self.indirect, arg_offset + 2)?;
        let arg_type = get_dword(self.indirect, arg_offset + offs + 12, self.big)?;
        let arg_opts = get_word(self.indirect, arg_offset + offs + 24, self.big)?;
        if arg_opts & 0x0004 != 0 {
            arg_name.insert_str(0, "ByVal ");
        }
        if arg_opts & 0x0002 != 0 {
            arg_name.insert_str(0, "ByRef ");
        }
        if arg_opts & 0x0200 != 0 {
            arg_name.insert_str(0, "Optional ");
        }
        if flags & 0x0020 != 0 {
            arg_name += " As ";
            if arg_type & 0xFFFF_0000 != 0 {
                arg_name += &get_type_name(arg_type & 0x0000_00FF);
            }
        }
        Ok(arg_name)
    }

    fn disasm_func(&self, dword: i64, op_type: i64) -> PyResult<String> {
        let table = self.indirect;
        let mut decl = "(".to_owned();
        let flags = get_word(table, dword, self.big)?;
        let sub_name = self.get_name(table, dword + 2)?;
        let mut offs2 = if self.vba_ver > 5 { 4 } else { 0 };
        if self.is64bit {
            offs2 += 16;
        }
        let mut arg_offset = get_dword(table, dword + offs2 + 36, self.big)?;
        let ret_type = get_dword(table, dword + offs2 + 40, self.big)?;
        let decl_offset = get_word(table, dword + offs2 + 44, self.big)?;
        let c_options = byte_at(table, dword + offs2 + 54)?;
        let new_flags = byte_at(table, dword + offs2 + 57)?;
        let mut has_declare = false;
        if self.vba_ver > 5 {
            if new_flags & 0x0002 == 0 && !self.is64bit {
                decl += "Private ";
            }
            if new_flags & 0x0004 != 0 {
                decl += "Friend ";
            }
        } else if flags & 0x0008 == 0 {
            decl += "Private ";
        }
        if op_type & 0x04 != 0 {
            decl += "Public ";
        }
        if flags & 0x0080 != 0 {
            decl += "Static ";
        }
        if c_options & 0x90 == 0 && decl_offset != 0xFFFF && !self.is64bit {
            has_declare = true;
            decl += "Declare ";
        }
        if self.vba_ver > 5 && new_flags & 0x20 != 0 {
            decl += "PtrSafe ";
        }
        if flags & 0x1000 != 0 {
            decl += if op_type == 2 || op_type == 6 {
                "Function "
            } else {
                "Sub "
            };
        } else if flags & 0x2000 != 0 {
            decl += "Property Get ";
        } else if flags & 0x4000 != 0 {
            decl += "Property Let ";
        } else if flags & 0x8000 != 0 {
            decl += "Property Set ";
        }
        decl += &sub_name;
        if has_declare {
            let lib_name = self.get_name(self.declaration, decl_offset + 2)?;
            write!(decl, " Lib \"{lib_name}\" ").expect("a String takes any text");
        }
        decl.push('(');
        // joined as it goes: a cycle of arguments never ends the loop, so only the limit does
        let mut first = true;
        while arg_offset != 0xFFFF_FFFF && arg_offset != 0 && arg_offset + 26 < table.len() as i64 {
            let arg_name = self.disasm_arg(arg_offset)?;
            if !first {
                decl += ", ";
            }
            first = false;
            decl += &arg_name;
            if decl.len() > MAX_OUTPUT {
                return Err(memory_error());
            }
            arg_offset = get_dword(table, arg_offset + 20, self.big)?;
        }
        decl.push(')');
        if flags & 0x0020 != 0 {
            decl += " As ";
            if ret_type & 0xFFFF_0000 == 0xFFFF_0000 {
                decl += &get_type_name(ret_type & 0x0000_00FF);
            } else {
                decl += &self.get_name(table, ret_type + 6)?;
            }
        }
        decl.push(')');
        Ok(decl)
    }

    fn disasm_var_arg(
        &self,
        codec: Decoder,
        offset: i64,
        length: i64,
        mnemonic: &str,
    ) -> PyResult<String> {
        let substring = slice(self.data, offset, offset + length);
        let mut text = format!("0x{length:04X} ");
        match mnemonic {
            "LitStr" | "QuoteRem" | "Rem" | "Reparse" => {
                text.push('"');
                text += &codec.decode(substring);
                text.push('"');
            }
            "OnGosub" | "OnGoto" => {
                let mut offset1 = offset;
                for index in 0..length / 2 {
                    let word = get_var_word(self.data, &mut offset1, self.big)?;
                    if index > 0 {
                        text += ", ";
                    }
                    text += &self.get_id(word);
                }
                text.push(' ');
            }
            _ => text += &hex_bytes(substring),
        }
        Ok(text)
    }
}

fn get_type_name(type_id: i64) -> String {
    let mut name = DIM_TYPES
        .get((type_id & !0xE0) as usize)
        .copied()
        .unwrap_or("")
        .to_owned();
    if type_id & 0x80 != 0 {
        name += "Ptr";
    }
    name
}

/// pcodedmp's module global `codec`, which starts as latin1, which each dir stream's PROJ_CODEPAGE
/// replaces, and which persists between projects in one process, and its two output files.
#[derive(Debug)]
pub struct PCodeDumper {
    codec: Decoder,
    disasm_only: bool,
    merge_errors: bool,
    output: String,
    errors: String,
}

impl PCodeDumper {
    /// `disasm_only` is `args.disasmOnly`. `merge_errors` means sys.stderr is the output (olevba's
    /// `extract_pcode` does `sys.stderr = output`); otherwise errors have their own buffer.
    pub fn new(disasm_only: bool, merge_errors: bool) -> PCodeDumper {
        PCodeDumper {
            codec: Decoder::latin1(),
            disasm_only,
            merge_errors,
            output: String::new(),
            errors: String::new(),
        }
    }

    /// `print(text, file=output_file)`, as `processFile` uses it. It doesn't count towards the limit.
    pub fn print_line(&mut self, text: &str) {
        self.output.push_str(text);
        self.output.push('\n');
    }

    /// `print('Error: {}.'.format(e), file=sys.stderr)`, given the exception's message.
    pub fn print_error(&mut self, message: &str) {
        let buffer = if self.merge_errors {
            &mut self.output
        } else {
            &mut self.errors
        };
        buffer.push_str("Error: ");
        buffer.push_str(message);
        buffer.push_str(".\n");
    }

    /// (output, errors). With `merge_errors` the errors are in the output.
    pub fn into_output(self) -> (String, String) {
        (self.output, self.errors)
    }

    /// `processProject`, given what `find_vba_projects` returned.
    pub fn process_project(&mut self, ole: &mut OleFile, projects: &[(String, String, String)]) {
        if let Err(error) = self.process_projects(ole, projects) {
            self.print_error(&error.message);
        }
    }

    /// A `print`, which fails with MemoryError once the output is at its limit.
    fn print(&mut self, text: &str) -> PyResult<()> {
        if self.output.len() + text.len() > MAX_OUTPUT {
            return Err(memory_error());
        }
        self.output.push_str(text);
        Ok(())
    }

    fn println(&mut self, text: &str) -> PyResult<()> {
        self.print(text)?;
        self.print("\n")
    }

    fn process_projects(
        &mut self,
        ole: &mut OleFile,
        projects: &[(String, String, String)],
    ) -> PyResult<()> {
        let rule = "=".repeat(79);
        let dashes = "-".repeat(79);
        for (vba_root, _, dir_path) in projects {
            self.println(&rule)?;
            if !self.disasm_only {
                self.println(&format!("dir stream: {dir_path}"))?;
            }
            let (code_modules, is64bit) = self.process_dir(ole, dir_path)?;
            let project_path = format!("{vba_root}VBA/_VBA_PROJECT");
            let project_data = ole.read_stream(&project_path)?;
            if !self.disasm_only {
                self.println(&dashes)?;
                self.println("_VBA_PROJECT stream:")?;
                self.println(&format!("{} bytes", project_data.len()))?;
            }
            let mut identifiers = Vec::new();
            if let Err(error) = read_identifiers(&project_data, self.codec, &mut identifiers) {
                self.print_error(&error.message);
            }
            if !self.disasm_only {
                self.println("Identifiers:")?;
                self.println("")?;
                for (index, identifier) in identifiers.iter().enumerate() {
                    self.println(&format!("{index:04X}: {identifier}"))?;
                }
                self.println("")?;
                self.println("_VBA_PROJECT parsing done.")?;
                self.println(&dashes)?;
            }
            self.println("Module streams:")?;
            for module in &code_modules {
                let module_path = format!("{vba_root}VBA/{module}");
                let module_data = ole.read_stream(&module_path)?;
                self.println(&format!("{module_path} - {} bytes", module_data.len()))?;
                self.pcode_dump(&module_data, &project_data, &identifiers, is64bit)?;
            }
        }
        Ok(())
    }

    fn process_dir(&mut self, ole: &mut OleFile, dir_path: &str) -> PyResult<(Vec<String>, bool)> {
        if !self.disasm_only {
            self.println(&"-".repeat(79))?;
            self.println("dir stream after decompression:")?;
        }
        let compressed = ole.read_stream(dir_path)?;
        let dir_data = decompress_stream(&compressed)?;
        if !self.disasm_only {
            self.println(&format!("{} bytes", dir_data.len()))?;
            self.println("dir stream parsed:")?;
        }
        let mut modules = Vec::new();
        let mut is64bit = false;
        let mut offset = 0;
        // always little-endian, even on a Mac; any exception, a print's too, ends the loop
        while offset < dir_data.len() as i64 {
            if self
                .dir_record(&dir_data, &mut offset, &mut modules, &mut is64bit)
                .is_err()
            {
                break;
            }
        }
        Ok((modules, is64bit))
    }

    fn dir_record(
        &mut self,
        dir_data: &[u8],
        offset: &mut i64,
        modules: &mut Vec<String>,
        is64bit: &mut bool,
    ) -> PyResult<()> {
        let tag = get_word(dir_data, *offset, false)?;
        let mut length = get_word(dir_data, *offset + 2, false)?;
        // Microsoft doesn't stick to its own format specification here
        if tag == 9 {
            length = 6;
        } else if tag == 3 {
            length = 2;
        }
        let tag_name = tag_name(tag);
        if !self.disasm_only {
            self.print(&format!("{:08X}:  {tag_name}", *offset))?;
        }
        *offset += 6;
        if length != 0 {
            if !self.disasm_only {
                self.println(":")?;
                self.println(&hexdump(slice(dir_data, *offset, *offset + length)))?;
            }
            match tag_name {
                "PROJ_CODEPAGE" => {
                    let page = get_word(dir_data, *offset, false)?;
                    self.codec = Decoder::for_codepage(page as u16);
                }
                "MOD_UNICODESTREAM" => {
                    modules.push(decode_utf16le(slice(dir_data, *offset, *offset + length)));
                }
                "PROJ_SYSKIND" => *is64bit = get_dword(dir_data, *offset, false)? == 3,
                _ => {}
            }
            *offset += length;
        } else if !self.disasm_only {
            self.println("")?;
        }
        Ok(())
    }

    /// `pcodeDump`. Only the first read is outside its `try`, and an error there ends the project.
    fn pcode_dump(
        &mut self,
        module: &[u8],
        project_data: &[u8],
        identifiers: &[String],
        is64bit: bool,
    ) -> PyResult<()> {
        // PC (little-endian) or Mac (big-endian)
        let big = get_word(module, 2, false)? > 0xFF;
        if let Err(error) = self.pcode_body(module, project_data, identifiers, is64bit, big) {
            self.print_error(&error.message);
        }
        Ok(())
    }

    fn pcode_body(
        &mut self,
        data: &[u8],
        project_data: &[u8],
        identifiers: &[String],
        is64bit: bool,
        big: bool,
    ) -> PyResult<()> {
        let version = get_word(project_data, 2, big)?;
        let (vba_ver, declaration, indirect, object, mut offset);
        if version >= 0x6B {
            vba_ver = if version >= 0x97 { 7 } else { 6 };
            let table_start;
            if is64bit {
                let length = get_dword(data, 0x0043, big)?;
                declaration = slice(data, 0x0047, 0x0047 + length);
                table_start = get_dword(data, 0x0011, big)? + 12;
            } else {
                let length = get_dword(data, 0x003F, big)?;
                declaration = slice(data, 0x0043, 0x0043 + length);
                table_start = get_dword(data, 0x0011, big)? + 10;
            }
            let length = get_dword(data, table_start, big)?;
            indirect = slice(data, table_start + 4, table_start + 4 + length);
            let start = get_dword(data, 0x0005, big)? + 0x8A;
            let length = get_dword(data, start, big)?;
            object = slice(data, start + 4, start + 4 + length);
            offset = 0x0019;
        } else {
            vba_ver = 5;
            offset = 11;
            let length = get_dword(data, offset, big)?;
            declaration = slice(data, offset + 4, offset + 4 + length);
            offset = skip_structure(data, offset, big, true, 1, false)?;
            offset += 64;
            offset = skip_structure(data, offset, big, false, 16, false)?;
            offset = skip_structure(data, offset, big, true, 1, false)?;
            offset += 6;
            offset = skip_structure(data, offset, big, true, 1, false)?;
            let length = get_dword(data, offset + 8, big)?;
            let table_start = length + 14;
            let length = get_dword(data, length + 10, big)?;
            indirect = slice(data, table_start, table_start + length);
            let start = get_dword(data, offset, big)? + 0x008A;
            let length = get_dword(data, start, big)?;
            object = slice(data, start + 4, start + 4 + length);
            offset += 77;
        }
        offset = get_dword(data, offset, big)? + 0x003C;
        let magic = get_var_word(data, &mut offset, big)?;
        if magic != 0xCAFE {
            return Ok(());
        }
        offset += 2;
        let num_lines = get_var_word(data, &mut offset, big)?;
        let pcode_start = offset + num_lines * 12 + 10;
        let module = Module {
            data,
            indirect,
            object,
            declaration,
            identifiers,
            big,
            vba_ver,
            is64bit,
        };
        for line in 0..num_lines {
            offset += 4;
            let line_length = get_var_word(data, &mut offset, big)?;
            offset += 2;
            let line_offset = get_var_dword(data, &mut offset, big)?;
            self.dump_line(&module, pcode_start + line_offset, line_length, line)?;
        }
        Ok(())
    }

    fn dump_line(
        &mut self,
        module: &Module<'_>,
        line_start: i64,
        line_length: i64,
        line: i64,
    ) -> PyResult<()> {
        self.println(&format!("Line #{line}:"))?;
        if line_length <= 0 {
            return Ok(());
        }
        let (data, big) = (module.data, module.big);
        let mut offset = line_start;
        let end_of_line = line_start + line_length;
        while offset < end_of_line {
            let word = get_var_word(data, &mut offset, big)?;
            let mut op_type = (word & !0x03FF) >> 10;
            let opcode = word & 0x03FF;
            let translated = translate_opcode(opcode, module.vba_ver, module.is64bit);
            let Some(&(mnemonic, args, varg)) = OPCODES.get(translated as usize) else {
                return self.println(&format!(
                    "Unrecognized opcode 0x{opcode:04X} at offset 0x{offset:08X}."
                ));
            };
            self.print("\t")?;
            self.print(mnemonic)?;
            self.print(" ")?;
            match mnemonic {
                "Coerce" | "CoerceVar" | "DefType" => {
                    if let Some(name) = VAR_TYPES_LONG.get(op_type as usize) {
                        self.print(&format!("({name}) "))?;
                    } else if op_type == 17 {
                        self.print("(Byte) ")?;
                    } else {
                        self.print(&format!("({op_type}) "))?;
                    }
                }
                "Dim" | "DimImplicit" | "Type" => {
                    let scope = if op_type & 0x04 != 0 {
                        Some("Global")
                    } else if op_type & 0x08 != 0 {
                        Some("Public")
                    } else if op_type & 0x10 != 0 {
                        Some("Private")
                    } else if op_type & 0x20 != 0 {
                        Some("Static")
                    } else {
                        None
                    };
                    let constant = op_type & 0x01 != 0 && mnemonic != "Type";
                    match (scope, constant) {
                        (Some(scope), true) => self.print(&format!("({scope} Const) "))?,
                        (Some(scope), false) => self.print(&format!("({scope}) "))?,
                        (None, true) => self.print("(Const) ")?,
                        (None, false) => {}
                    }
                }
                "LitVarSpecial" => {
                    let special = SPECIALS
                        .get(op_type as usize)
                        .ok_or_else(list_index_error)?;
                    self.print(&format!("({special})"))?;
                }
                "ArgsCall" | "ArgsMemCall" | "ArgsMemCallWith" => {
                    if op_type < 16 {
                        self.print("(Call) ")?;
                    } else {
                        op_type -= 16;
                    }
                }
                "Option" => {
                    let option = OPTIONS.get(op_type as usize).ok_or_else(list_index_error)?;
                    self.print(&format!(" ({option})"))?;
                }
                "Redim" | "RedimAs" if op_type & 16 != 0 => self.print("(Preserve) ")?,
                _ => {}
            }
            for &arg in args {
                match arg {
                    "name" => {
                        let word = get_var_word(data, &mut offset, big)?;
                        self.print(&module.disasm_name(word, mnemonic, op_type))?;
                    }
                    "0x" | "imp_" => {
                        let word = get_var_word(data, &mut offset, big)?;
                        self.print(&module.disasm_imp(arg, word, mnemonic)?)?;
                    }
                    _ => offset = self.dump_table_arg(module, arg, op_type, offset)?,
                }
            }
            if varg {
                let length = get_var_word(data, &mut offset, big)?;
                self.print(&module.disasm_var_arg(self.codec, offset, length, mnemonic)?)?;
                offset += length;
                if length & 1 != 0 {
                    offset += 1;
                }
            }
            self.println("")?;
        }
        Ok(())
    }

    /// An argument of kind `func_`, `var_`, `rec_`, `type_` or `context_`. Returns the new offset.
    fn dump_table_arg(
        &mut self,
        module: &Module<'_>,
        arg: &str,
        op_type: i64,
        mut offset: i64,
    ) -> PyResult<i64> {
        let (data, big) = (module.data, module.big);
        let table_len = module.indirect.len() as i64;
        let dword = get_var_dword(data, &mut offset, big)?;
        if arg == "rec_" && table_len >= dword + 20 {
            self.print(&module.disasm_rec(dword)?)?;
        } else if arg == "type_" && table_len >= dword + 7 {
            self.print(&format!("(As {})", module.disasm_type(dword)?))?;
        } else if arg == "var_" && table_len >= dword + 16 {
            if op_type & 0x20 != 0 {
                self.print("(WithEvents) ")?;
            }
            self.print(&module.disasm_var(dword)?)?;
            if op_type & 0x10 != 0 {
                let word = get_var_word(data, &mut offset, big)?;
                self.print(&format!(" 0x{word:04X}"))?;
            }
        } else if arg == "func_" && table_len >= dword + 61 {
            self.print(&module.disasm_func(dword, op_type)?)?;
        } else {
            self.print(&format!("{arg}{dword:08X} "))?;
        }
        if module.is64bit && arg == "context_" {
            let dword = get_var_dword(data, &mut offset, big)?;
            self.print(&format!("{dword:08X} "))?;
        }
        Ok(offset)
    }
}

fn list_index_error() -> PyErr {
    PyErr::new("IndexError", "list index out of range")
}

// The expected text in these tests is what pcodedmp 1.2.6 printed on Python 3.14.
#[cfg(test)]
mod tests {
    use super::*;

    const DIR: &str = "01000400000003000000030002000000a4030400000000003200080000004d006f0064003100e703010000005a1000";
    const MODULE: &str = "000000000010000000000000000000000076000000000000000000000000000000000000000000000000000000000000000000000000000000000000feca0000030000000000140000000000000000000000000000000000000000000000040000008e00000000000000000000000000b60003006869e90020080402cd0004000402020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000";
    const MODULE_TEXT: &str = "Line #0:\n\tLitStr 0x0003 \"hi\u{e9}\"\n\tLd first% \n\tOption  (Base 0)\n\tAnd \nUnrecognized opcode 0x0204 at offset 0x00000082.\nLine #1:\nLine #2:\n\tLd ";
    const MODULE_ERROR: &str = "Error: unpack_from requires a buffer of at least 258 bytes for unpacking 2 bytes at offset 256 (actual buffer size is 256).\n";

    fn unhex(text: &str) -> Vec<u8> {
        text.as_bytes()
            .chunks(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ascii"), 16).expect("hex")
            })
            .collect()
    }

    fn module<'a>(identifiers: &'a [String], vba_ver: i64, is64bit: bool) -> Module<'a> {
        Module {
            data: &[],
            indirect: &[],
            object: &[],
            declaration: &[],
            identifiers,
            big: false,
            vba_ver,
            is64bit,
        }
    }

    #[test]
    fn struct_and_index_errors_are_pythons() {
        assert_eq!(
            get_word(b"abc", 3, false).unwrap_err().message,
            "unpack_from requires a buffer of at least 5 bytes for unpacking 2 bytes at offset 3 (actual buffer size is 3)"
        );
        assert_eq!(
            get_dword(b"", 4294967300, true).unwrap_err().message,
            "unpack_from requires a buffer of at least 4294967304 bytes for unpacking 4 bytes at offset 4294967300 (actual buffer size is 0)"
        );
        assert_eq!(
            byte_at(b"abc", 3).unwrap_err().message,
            "index out of range"
        );
        assert_eq!(get_word(b"\x01\x02", 0, true).unwrap(), 0x0102);
    }

    #[test]
    fn slices_clamp() {
        assert_eq!(slice(b"abc", 1, 100), b"bc");
        assert_eq!(slice(b"abc", 100, 200), b"");
    }

    #[test]
    fn hexdump_pads_as_python_does() {
        let bytes: Vec<u8> = (0x1E..0x34).collect();
        assert_eq!(
            hexdump(&bytes),
            "00000000   1E 1F 20 21 22 23 24 25 26 27 28 29 2A 2B 2C 2D    .. !\"#$%&'()*+,-\n\
             00000010   2E 2F 30 31 32 33                                  ./0123\n"
        );
    }

    #[test]
    fn the_tables_keep_pythons_spelling() {
        assert_eq!(OPCODES[97].0, "DoUnitil");
        assert_eq!(OPCODES[227], ("QuoteRem", &["0x"][..], true));
        assert_eq!(OPCODES[263].0, "Illegal");
        assert!(INTERNAL_NAMES.contains(&" /"));
        assert!(INTERNAL_NAMES.contains(&"VB_PredecraredID"));
    }

    #[test]
    fn a_negative_identifier_counts_from_the_end() {
        let three = ["n0".to_owned(), "n1".to_owned(), "n2".to_owned()];
        let vba7 = module(&three, 7, false);
        let got: Vec<String> = [0x200, 0x206, 0x208, 0x20E, 0xFFFF, 2]
            .iter()
            .map(|&code| vba7.get_id(code))
            .collect();
        assert_eq!(got, ["id_0200", "n2", "n0", "id_020E", "id_FFFF", "0"]);
        let one = ["n0".to_owned()];
        let vba7_64 = module(&one, 7, true);
        let got: Vec<String> = [0x200, 0x20C, 0x20E, 0x210]
            .iter()
            .map(|&code| vba7_64.get_id(code))
            .collect();
        assert_eq!(got, ["id_0200", "n0", "n0", "id_0210"]);
        // past the end of the internal names, and the one the version shifts down
        assert_eq!(module(&[], 6, false).get_id(0x1FE), "id_01FE");
        assert_eq!(module(&[], 7, false).get_id(0x1FE), ":=");
        assert_eq!(module(&[], 7, false).get_id(0x186), "Write");
    }

    #[test]
    fn opcodes_translate_by_version() {
        assert_eq!(translate_opcode(69, 5, false), 70);
        assert_eq!(translate_opcode(263, 6, false), 266);
        assert_eq!(translate_opcode(1023, 7, true), 1023);
    }

    #[test]
    fn open_modes() {
        let vba7 = module(&[], 7, false);
        assert_eq!(
            vba7.disasm_imp("0x", 0x1234, "Open").unwrap(),
            "(For Random Access Write Lock Read Write)"
        );
        assert_eq!(
            vba7.disasm_imp("0x", 0x4301, "Open").unwrap(),
            "(For Input Access Read Write Shared)"
        );
    }

    fn parse_dir(disasm_only: bool) -> PCodeDumper {
        let data = unhex(DIR);
        let mut dumper = PCodeDumper::new(disasm_only, false);
        let (mut offset, mut modules, mut is64bit) = (0, Vec::new(), false);
        while offset < data.len() as i64 {
            if dumper
                .dir_record(&data, &mut offset, &mut modules, &mut is64bit)
                .is_err()
            {
                break;
            }
        }
        assert_eq!(modules, ["Mod1"]);
        assert!(is64bit);
        assert_eq!(dumper.codec.name(), Decoder::for_codepage(932).name());
        dumper
    }

    #[test]
    fn dir_records_print_their_names_and_dumps() {
        assert_eq!(parse_dir(true).output, "");
        assert_eq!(
            parse_dir(false).output,
            "00000000:  PROJ_SYSKIND:\n00000000   03 00 00 00                                        ....\n\n\
             0000000A:  PROJ_CODEPAGE:\n00000000   A4 03                                              ..\n\n\
             00000012:  PROJ_NAME\n\
             00000018:  MOD_UNICODESTREAM:\n00000000   4D 00 6F 00 64 00 31 00                            M.o.d.1.\n\n\
             00000026:  UNKNOWN:\n00000000   5A                                                 Z\n\n"
        );
    }

    fn dump_module(merge: bool) -> (String, String) {
        let identifiers = ["first".to_owned(), "last".to_owned()];
        let mut dumper = PCodeDumper::new(true, merge);
        dumper
            .pcode_dump(&unhex(MODULE), b"\xcc\x61\x97\x00", &identifiers, false)
            .unwrap();
        dumper.into_output()
    }

    #[test]
    fn output_before_an_error_stays_and_the_error_follows_it() {
        assert_eq!(
            dump_module(true),
            (format!("{MODULE_TEXT}{MODULE_ERROR}"), String::new())
        );
        assert_eq!(
            dump_module(false),
            (MODULE_TEXT.to_owned(), MODULE_ERROR.to_owned())
        );
    }

    #[test]
    fn the_endian_read_is_outside_pcode_dumps_try() {
        let mut dumper = PCodeDumper::new(true, true);
        let error = dumper.pcode_dump(b"abc", b"", &[], false).unwrap_err();
        assert_eq!(
            error.message,
            "unpack_from requires a buffer of at least 4 bytes for unpacking 2 bytes at offset 2 (actual buffer size is 3)"
        );
        assert_eq!(dumper.output, "");
    }

    #[test]
    fn identifiers_read_before_an_error_stay() {
        // the module table is cut off after the counts: no identifier yet, and an error
        let mut data = vec![0xCC, 0x61, 0x97, 0x00];
        data.resize(0x1E, 0);
        let mut identifiers = Vec::new();
        let error = read_identifiers(&data, Decoder::latin1(), &mut identifiers).unwrap_err();
        assert!(identifiers.is_empty());
        assert_eq!(
            error.message,
            "unpack_from requires a buffer of at least 32 bytes for unpacking 2 bytes at offset 30 (actual buffer size is 30)"
        );
    }

    #[test]
    fn a_cycle_of_arguments_ends_at_the_limit() {
        // the first argument's offset at dword + 40, no Declare at + 58, then an argument linking to itself
        let mut table = vec![0u8; 120];
        table[58] = 0x90;
        table[40..44].copy_from_slice(&64u32.to_le_bytes());
        table[64 + 20..64 + 24].copy_from_slice(&64u32.to_le_bytes());
        table[64 + 2..64 + 4].copy_from_slice(&0x208u16.to_le_bytes());
        let identifiers = ["n".repeat(1 << 20)];
        let vba7 = Module {
            indirect: &table,
            ..module(&identifiers, 7, false)
        };
        let error = vba7.disasm_func(0, 0).unwrap_err();
        assert_eq!(error, memory_error());
    }

    #[test]
    fn a_print_past_the_limit_raises_and_the_error_is_still_printed() {
        let mut dumper = PCodeDumper::new(true, true);
        dumper.output = "x".repeat(MAX_OUTPUT);
        dumper
            .pcode_dump(&unhex(MODULE), b"\xcc\x61\x97\x00", &[], false)
            .unwrap();
        assert_eq!(dumper.output.len(), MAX_OUTPUT + "Error: .\n".len());
        assert!(dumper.output.ends_with("xError: .\n"));
    }
}
