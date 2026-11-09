# Cases for tld.get_tld and get_fld (tld 0.13.2, its bundled list). Output: tests/data/tld.json.

import tld
from tld import get_fld, get_tld

assert tld.__version__ == "0.13.2", tld.__version__

rules = []
private = False
with open(tld.utils.project_dir("res/effective_tld_names.dat.txt"), encoding="utf-8") as f:
    for line in f:
        if "===BEGIN PRIVATE DOMAINS===" in line:
            private = True
        line = line.strip()
        if line and not line.startswith("//"):
            rules.append((line, private))
public_rules = [r for r, p in rules if not p]
private_rules = [r for r, p in rules if p]
wild = [r for r, _ in rules if r.startswith("*.")]
excs = [r for r, _ in rules if r.startswith("!")]
LABELS = ["www", "a", "example", "foo-bar", "xn--bcher-kva", "b\u00fccher", "\u4e2d\u6587", "WWW", "city", "x", "123", "", "_s",
          "\u00c9cole", "K\u212a"]


def suffix():
    r = rng.random()
    if r < 0.35:
        return rng.choice(public_rules)
    if r < 0.6:
        return rng.choice(private_rules)
    if r < 0.75:
        return rng.choice(wild).replace("*", rng.choice(LABELS[:5]))
    if r < 0.85:
        return rng.choice(excs)[1:]
    return rng.choice(["com", "co.uk", "unknowntld", "xn--p1ai", "\u0440\u0444", "jp", "kawasaki.jp", "ck", "", "local"])


def host():
    labels = [rng.choice(LABELS) for _ in range(rng.choice([0, 0, 1, 1, 2, 3]))]
    h = ".".join(labels + [suffix()])
    r = rng.random()
    if r < 0.1:
        h += rng.choice([".", ".."])
    elif r < 0.2:
        h = h.upper()
    elif r < 0.25:
        h = rng.choice(["127.0.0.1", "[::1]", "", "localhost", "1.2.3.4.in-addr.arpa"])
    return h


def url():
    r = rng.random()
    if r < 0.8:
        u = rng.choice(["http://", "https://", "ftp://", "//", "", "HTTP://", "mailto:", "x+y://"])
        if rng.random() < 0.1:
            u += "user:pw@"
        u += host()
        if rng.random() < 0.2:
            u += rng.choice([":80", ":", ":99999", ":x"])
        u += rng.choice(["", "/", "/path?q=1#f", "?a"])
        return u
    if r < 0.9:
        return rng.choice(["http://", ""]) + random_string(16)
    return random_string(24)


fixed = ["http://www.city.kawasaki.jp", "http://city.kawasaki.jp", "http://a.b.kawasaki.jp", "http://www.ck", "http://foo.www.ck",
         "http://a.ck", "http://co.uk", "http://www.google.co.uk", "http://google.com.", "http://google.com..", "http://com",
         "http://.com", "http://", "", "google.com", "//google.com", "http://[::1]/", "http://[::1", "http://127.0.0.1",
         "http://xn--9tfky.id", "http://a.xn--4dbgdty6c.xn--4dbrk0ce", "http://a.blogspot.com", "http://blogspot.com",
         "HTTP://WWW.GOOGLE.COM", "http://\u212a.com", "\u212attp://x.com", "http://a\u2100b.com", "http://a@b@c.com"]
urls = fixed + [url() for _ in range(5000)]
HEAD = 3 * len(fixed)
FLAGS = [(False, False, True, True), (True, False, True, True), (False, True, True, True), (True, True, True, True),
         (True, False, True, False), (True, False, False, True), (False, False, False, True), (False, False, False, False)]


def obj(u, fs, fp, sp, spr):
    r = get_tld(u, fail_silently=fs, as_object=True, fix_protocol=fp, search_public=sp, search_private=spr)
    if r is None:
        return None
    p = r.parsed_url
    return [r.subdomain, r.domain, r.tld, r.fld, list(p)]


out = []
for i, u in enumerate(urls):
    for flags in ([FLAGS[0], FLAGS[1]] + [rng.choice(FLAGS[2:])]):
        fs, fp, sp, spr = flags
        out.append({"url": u, "flags": list(flags), "obj": run(obj, u, *flags),
                    "str": run(lambda: get_tld(u, fail_silently=fs, fix_protocol=fp, search_public=sp, search_private=spr)),
                    "fld": run(lambda: get_fld(u, fail_silently=fs, fix_protocol=fp, search_public=sp, search_private=spr))})
dump(sample(out, HEAD))
