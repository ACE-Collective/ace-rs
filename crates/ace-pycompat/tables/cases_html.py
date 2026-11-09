# Cases for html.escape and html.unescape. Output: tests/data/html.json.

import html
from html.entities import html5

names = sorted(html5)
fixed = ["", "&", "&&", "&;", "&#", "&#;", "&#x", "&#x;", "&#X41", "&#65", "&#65;", "&#0", "&#13;", "&#128;", "&#x80",
         "&#xD800;", "&#x10FFFF;", "&#x110000;", "&#99999999999999999999;", "&#1;", "&#11;", "&#xFDD0;", "&#x1FFFF;",
         "&amp", "&amp;", "&ampx", "&ampx;", "&notit;", "&notin;", "&noti", "&AMP;", "&Amp;", "&lt&gt", "&lt;&gt;",
         "&\u00e9;", "&a\u00e9b;", "&" + "a" * 40 + ";", "&" + "a" * 31 + ";", "&" + "a" * 32 + ";", "&amp" + "x" * 40,
         "<a href=\"x\">'&'</a>", "&\tamp;", "&am p;", "&#x41g", "&#65a"]
cases = list(fixed)
HEAD = len(cases)
while len(cases) < 8000:
    parts = []
    for _ in range(rng.randrange(1, 6)):
        r = rng.random()
        if r < 0.3:
            n = rng.choice(names)
            if rng.random() < 0.3:
                n = n[: rng.randrange(1, len(n) + 1)]
            parts.append("&" + n + rng.choice(["", "", ";", "x", "\u00e9", " "]))
        elif r < 0.5:
            parts.append("&#" + rng.choice(["", "x", "X"]) + "".join(rng.choice("0123456789abcdefABCDEFg") for _ in range(rng.randrange(0, 9))) + rng.choice(["", ";", ";;"]))
        else:
            parts.append(random_string(10))
    cases.append("".join(parts))
dump(sample([{"s": s, "unescape": html.unescape(s), "escape": html.escape(s), "escape_noquote": html.escape(s, False)} for s in cases], HEAD))
