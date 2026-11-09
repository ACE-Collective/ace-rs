# What the case generators share. Each one is run as
#   cat tables/cases_common.py tables/cases_NAME.py | docker exec -i ace-dev-1 /venv/bin/python3 - > tests/data/NAME.json
# (tables/cases does all of them). The random cases come from a fixed seed, so the output is the
# same each time.
#
# The committed files are samples: every hand-written case, and of the generated ones those that
# cover each outcome (each exception class and message shape), then random ones up to a byte
# budget. With ACE_PYCOMPAT_FULL=1 a generator writes every case instead; tables/cases does that
# into tests/full, and ACE_PYCOMPAT_CASES=tests/full makes the Rust tests read those files.

import hashlib
import json
import os
import random
import re
import sys
import traceback

assert sys.version_info[:3] == (3, 14, 10), sys.version

rng = random.Random(20261108)
FULL = os.environ.get("ACE_PYCOMPAT_FULL") == "1"

WHITESPACE = "\t\n\x0b\x0c\r\x1c\x1d\x1e\x1f \x85\xa0\u1680\u2000\u200a\u2028\u2029\u202f\u205f\u3000\u200b\ufeff"
PUNCT = ":/?#[]@!$&'()*+,;=%-._~\"<>\\^`{|}"
LETTERS = "abcxyzAKSZ019"
SPECIAL = ("\u00e9\u00df\u0130\u0131\u017f\u212a\u03a3\u03c2\u03c3\u0345\u1e9e\u00ff\u0178\u01c5\u2126"
           "\u0301\u0308\u0327\u0323\u200c\u200d\u00b7\u0375\u05f3\u30fb\u0660\u06f0\u094d"
           "\u0430\u0435\u043e\u0440\u0441\u0410\u03b1\u03bf\u05d0\u05d1\u0627\u0628\u0661\u4e2d\u6587\u3042\u30a2\uac00\u1100\u1161\u11a8"
           "\uff21\uff41\uff10\uff0f\uff0e\uff20\uff1a\uff03\uff1f\u3002\uff61\u2100\u2101\u2048\u2049\ufe56\ufe5f\u2122\ufb01\u2460\u00bd\u2024\u2025\u2026\u2052\u2215\u2044"
           "\u00ab\u00bb\u2018\u2019\u201c\u201d\u2039\u203a\u00a0\u00ad\u034f\u180b\ufe00\U000e0100\U0001f600\U0001f310\U0001d400\U00010000\ufffd\ufffe\uffff\U0010ffff\U000e0001"
           "\u0000\u0001\u007f\u0080\u009f")
TOKENS = ["%41", "%2F", "%2f", "%25", "%C3%A9", "%E2%82", "%FF", "%G0", "%", "%%", "%u00e9", "xn--", "XN--", "xn--nxasmq6b",
          "xn--bcher-kva", "xn--80ak6aa92e", "xn--", "--", "&amp;", "&#x41;", "&#65", "&lt", "&notit;", "&#0;", "&#xD800;",
          "http://", "https://", "//", "[::1]", "[v1.x]", "127.0.0.1", "::ffff:1.2.3.4", "fe80::1%eth0", "www.", ".com", "..",
          "@", "user:pass@", ":8080", "?a=1&b=2", "#frag", "\r\n", "\\u00e9", "\\ud800", "==", "=", "+/", "-_"]


def random_char():
    r = rng.random()
    if r < 0.3:
        return rng.choice(LETTERS)
    if r < 0.5:
        return rng.choice(PUNCT)
    if r < 0.6:
        return rng.choice(WHITESPACE)
    if r < 0.85:
        return rng.choice(SPECIAL)
    while True:
        cp = rng.choice([rng.randrange(0x80, 0x800), rng.randrange(0x800, 0x10000), rng.randrange(0x10000, 0x110000)])
        if not 0xD800 <= cp <= 0xDFFF:
            return chr(cp)


def random_string(max_len=24):
    n = rng.choice([0, 1, 2, 3, rng.randrange(0, max_len + 1), rng.randrange(0, max_len + 1)])
    out = []
    while len(out) < n:
        if rng.random() < 0.15:
            out.append(rng.choice(TOKENS))
        else:
            out.append(random_char())
    return "".join(out)


def random_bytes(max_len=16):
    n = rng.randrange(0, max_len + 1)
    pieces = []
    while len(pieces) < n:
        r = rng.random()
        if r < 0.3:
            pieces.append(bytes([rng.randrange(0, 256)]))
        elif r < 0.5:
            pieces.append(random_char().encode("utf-8"))
        elif r < 0.7:
            # truncated or broken multi-byte sequences, overlong forms, encoded surrogates
            pieces.append(rng.choice([b"\xc3", b"\xe2\x82", b"\xf0\x9f\x98", b"\xc0\x80", b"\xc1\xbf", b"\xe0\x80\x80",
                                      b"\xed\xa0\x80", b"\xed\xbf\xbf", b"\xf4\x90\x80\x80", b"\xf5\x80", b"\xff", b"\x80",
                                      b"\xbf\xbf", b"\xe0\x9f", b"\xf0\x8f", b"\xf8\x88\x80\x80\x80"]))
        else:
            pieces.append(bytes([rng.randrange(0x80, 0x100)]))
    return b"".join(pieces)


def err(e):
    """An exception as the Rust tests compare it."""
    return {"module": type(e).__module__, "kind": type(e).__name__, "message": str(e)}


def run(f, *args, **kwargs):
    """{"ok": result} or {"err": exception}."""
    try:
        return {"ok": f(*args, **kwargs)}
    except Exception as e:
        return {"err": err(e)}


def _signature(case, top=True):
    """The outcomes a case shows: each exception's class and message shape, each ok, each bool."""
    out = set()
    if isinstance(case, dict):
        if "err" in case and isinstance(case["err"], dict):
            # The message's shape: its plain words, without quoted text, numbers or the input.
            text = re.sub(r"'[^']*'|\"[^\"]*\"", "", str(case["err"].get("message", "")))
            words = [w for w in text.split() if re.fullmatch(r"[A-Za-z]+[,:]?", w)]
            msg = " ".join(words[:4] + ["..."] + words[4:][-2:])
            out.add("E:%s:%s" % (case["err"].get("kind"), msg))
        elif "ok" in case and len(case) == 1:
            out.add("ok:%s" % type(case["ok"]).__name__)
        for k, v in case.items():
            if isinstance(v, bool):
                out.add("%s=%s" % (k, v))
            else:
                out |= _signature(v, False)
    elif isinstance(case, list):
        for v in case:
            out |= _signature(v, False)
    return frozenset(out)


def sample(items, head, budget=250_000, per_signature=2):
    """The first `head` items (the hand-written ones), up to `per_signature` of each outcome among
    the rest, then random ones while the budget in bytes lasts. All of them with FULL."""
    if FULL:
        return items
    pick = set(range(min(head, len(items))))
    seen = {}
    for i in range(head, len(items)):
        sig = _signature(items[i])
        if seen.get(sig, 0) < per_signature:
            seen[sig] = seen.get(sig, 0) + 1
            pick.add(i)
    size = sum(len(json.dumps(_rle(items[i]), ensure_ascii=False)) for i in pick)
    rest = [i for i in range(head, len(items)) if i not in pick]
    random.Random(len(items)).shuffle(rest)
    for i in rest:
        n = len(json.dumps(_rle(items[i]), ensure_ascii=False))
        if size + n > budget:
            continue
        size += n
        pick.add(i)
    return [items[i] for i in sorted(pick)]


def _rle(obj):
    """A long string becomes {"$rle": [[text, count], ...]}, which the Rust tests expand."""
    if isinstance(obj, str):
        if len(obj) < 2000:
            return obj
        runs = []
        for m in re.finditer(r"(.)\1{15,}|(?:(?!(.)\2{15}).)+", obj, re.S):
            t = m.group()
            if len(t) >= 16 and len(set(t)) == 1:
                runs.append([t[0], len(t)])
            else:
                runs.append([t, 1])
        return {"$rle": runs}
    if isinstance(obj, list):
        return [_rle(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _rle(v) for k, v in obj.items()}
    return obj


def dump(obj):
    obj = _rle(obj)
    # UTF-8 keeps the files small. JSON escapes every control character, so a file has no CR, and a
    # lone surrogate, which UTF-8 can't hold, is written as its escape.
    text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    text = re.sub("[\ud800-\udfff]", lambda m: "\\u%04x" % ord(m.group()), text)
    sys.stdout.buffer.write(text.encode("utf-8") + b"\n")


def digest(parts):
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", "surrogatepass"))
        h.update(b"\x00")
    return h.hexdigest()
