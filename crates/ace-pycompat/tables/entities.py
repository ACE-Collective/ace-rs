# html.entities.html5 and html's numeric reference tables, from Python 3.14. Output: src/tables/entities.rs.

import html
from html.entities import html5

header("entities.py")

print("/// `html._invalid_charrefs`: what a numeric reference to one of these code points becomes.")
print("pub(crate) static INVALID_CHARREFS: &[(u32, &str)] = &[")
for k in sorted(html._invalid_charrefs):
    print("    (0x%x, %s)," % (k, rust_str(html._invalid_charrefs[k])))
print("];")
print()

# html._invalid_codepoints as inclusive ranges.
cps = sorted(html._invalid_codepoints)
runs = []
for c in cps:
    if runs and runs[-1][1] == c - 1:
        runs[-1][1] = c
    else:
        runs.append([c, c])
print("/// `html._invalid_codepoints`, as inclusive ranges: a numeric reference to one becomes nothing.")
print("pub(crate) static INVALID_CODEPOINTS: &[(u32, u32)] = &[")
for a, b in runs:
    print("    (0x%x, 0x%x)," % (a, b))
print("];")
print()

print("/// `html.entities.html5`, sorted by name. Names keep their `;`.")
print("#[rustfmt::skip]")
print("pub(crate) static HTML5: &[(&str, &str)] = &[")
for k in sorted(html5):
    print("    (%s, %s)," % (rust_str(k), rust_str(html5[k])))
print("];")
