# The idna package's tables (idna 3.20, idna/idnadata.py). Output: src/tables/idnadata.rs.

import idna
from idna import idnadata
from idna.intranges import _decode_range

assert idna.__version__ == "3.20", idna.__version__

header("idnadata.py")


def emit_intranges(name, rs, doc):
    emit_ranges(name, [(a, b - 1) for a, b in map(_decode_range, rs)], doc)


for cls in ("PVALID", "CONTEXTJ", "CONTEXTO"):
    emit_intranges(cls, idnadata.codepoint_classes[cls], "`idnadata.codepoint_classes[%r]`." % cls)
assert set(idnadata.codepoint_classes) == {"PVALID", "CONTEXTJ", "CONTEXTO"}, idnadata.codepoint_classes.keys()

for script in ("Greek", "Han", "Hebrew", "Hiragana", "Katakana"):
    emit_intranges("SCRIPT_" + script.upper(), idnadata.scripts[script], "`idnadata.scripts[%r]`." % script)

# _joining_type tries the types in the dict's order and returns the first that holds.
print("/// `idnadata.joining_types`, in the order `_joining_type` tries them.")
print("pub(crate) static JOINING_TYPES: &[(char, &[(u32, u32)])] = &[")
for jt, rs in idnadata.joining_types.items():
    assert len(jt) == 1
    print("    ('%s', &[%s])," % (jt, ", ".join("(0x%x, 0x%x)" % (a, b - 1) for a, b in map(_decode_range, rs))))
print("];")
