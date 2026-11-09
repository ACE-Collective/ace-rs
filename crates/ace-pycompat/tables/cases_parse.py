# Cases for urllib.parse. Output: tests/data/parse.json.

from urllib.parse import (parse_qs, parse_qsl, quote, unquote, unquote_plus, urljoin, urlparse, urlsplit,
                          urlunparse, urlunsplit)

SCHEMES = ["http", "https", "HTTP", "ftp", "file", "mailto", "javascript", "data", "tel", "sip", "git+ssh", "x-y.z",
           "1http", "ht tp", "h\u00e9", "", "itms-services", "svn+ssh", "rtsp", "news"]
HOSTS = ["example.com", "EXAMPLE.com", "a.b.c", "localhost", "127.0.0.1", "[::1]", "[::1]:80", "[fe80::1%25eth0]",
         "[fe80::1%Eth0]", "[v1.abc]", "[V1.]", "[vx.y]", "[1.2.3.4]", "[::1", "::1]", "a[b]c", "[::1]x", "x[::1]",
         "\u00e9x.com", "xn--bcher-kva.ch", "b\u00fccher.ch", "\u2100.com", "a\uff0fb", "a\u2048b", "\ufe56x", "\ufe5f",
         "\u2101", "\u00aa.com", "\u212a.com", "EX\u0130.com", "", "user@host", "user:pw@host:99", "a@b@c", ":80",
         "host:", "host:65535", "host:65536", "host:0", "host:00080", "host:-1", "host:\u0661", "host:8a", "[::1]:x",
         "\u3002.com", "a.\uff0ecom"]
PATHS = ["", "/", "/a/b", "/a/b/", "a/b", "/a;p", "/a/b;p=1", ";x", "/./a/../b", "/..", "//x", "/%7e", "/a b",
         "/\u00e9", "/a?b", "/#", "/a/b/c/./../d"]
QUERIES = ["", "?", "?a=1", "?a=1&b=2", "?a=&b", "?a=1;b=2", "?a+b=c%20d", "?%zz=1", "?a=1&a=2", "?=", "?&&"]
FRAGS = ["", "#", "#f", "#a#b", "#a?b"]


def random_url():
    r = rng.random()
    if r < 0.6:
        s = ""
        if rng.random() < 0.85:
            s += rng.choice(SCHEMES) + ":"
        if rng.random() < 0.8:
            s += "//" + rng.choice(HOSTS)
        s += rng.choice(PATHS) + rng.choice(QUERIES) + rng.choice(FRAGS)
        if rng.random() < 0.3:
            pos = rng.randrange(0, len(s) + 1)
            s = s[:pos] + random_string(4) + s[pos:]
        if rng.random() < 0.15:
            s = rng.choice(["\x00", " ", "\t", "\x1f ", "\r\n", "\u3000"]) + s
        return s
    if r < 0.8:
        return rng.choice(["//", "http://", "https://", ""]) + random_string(20)
    return random_string(28)


fixed = ["", "http://example.com", "http://[::1]:8080/a", "http://[::ffff:1.2.3.4]/", "http://[1.2.3.4]/", "http://[v1.x]/",
         "http://[v1.x\n]/", "http://a[b]/", "http://\u2100/", "http://a\u2100b/", "http://user@\uff03/", "//x/y",
         "x:y", "1:2", "a1+-.:b", "\x00 \x1fhttp://x", "ht\ttp://x", "http://x\n/y", "mailto:a@b.c", "http:", "http:/",
         "http://", "http:///x", "file:///etc/passwd", "path;params?q#f", "http://a/b;c/d;e"]
urls = list(fixed)
HEAD = len(urls)
while len(urls) < 4000:
    urls.append(random_url())


def split_info(u):
    r = urlsplit(u)
    return {"parts": list(r), "hostname": r.hostname, "username": r.username, "password": r.password,
            "port": run(lambda: r.port), "geturl": r.geturl()}


bases = ["", "http://a/b/c/d;p?q", "http://a/b/c/", "https://h.com", "file:///x/y", "mailto:x@y", "//h/p", "a/b",
         "http://[::1]/x/y", "ftp://u@h/p/q/", "http:"]
out_split = []
for u in urls:
    p = run(lambda: list(urlparse(u)))
    out_split.append({"url": u, "split": run(split_info, u), "split_nofrag": run(lambda: list(urlsplit(u, "", False))),
                      "split_scheme": run(lambda: list(urlsplit(u, " ht\ttp\n"))),
                      "parse": p,
                      "unparse": urlunparse(p["ok"]) if "ok" in p else None,
                      "unsplit": urlunsplit(urlsplit(u)) if "ok" in run(urlsplit, u) else None,
                      "join": [[b, x, run(urljoin, b, x)] for b, x in [(b, u) for b in rng.sample(bases, 3)] + [(u, rng.choice(urls))]]})

relatives = ["g:h", "g", "./g", "g/", "/g", "//g", "?y", "g?y", "#s", "g#s", "g?y#s", ";x", "g;x", "g;x?y#s", "", ".", "./",
             "..", "../", "../g", "../..", "../../", "../../g", "../../../g", "/./g", "/../g", "g.", ".g", "g..", "..g",
             "./../g", "./g/.", "g/./h", "g/../h", "g;x=1/./y", "g;x=1/../y", "http:g", "http:", "//", "///", "a//b/../c"]
joins = []
for b in bases:
    for r in relatives:
        joins.append({"base": b, "url": r, "out": run(urljoin, b, r), "nofrag": run(urljoin, b, r, False)})

quoted = ["", "abc", "a b", "%", "%4", "%41", "%4G", "%%41", "%e9", "%C3%A9", "%C3", "%E2%82%AC", "%e2%82", "\u00e9%41\u00e9%42",
          "%C3\u00e9%A9", "a+b", "%2B+", "%F0%9F%98%80", "%ED%A0%80", "%C0%AF", "%FF%FE"]
QUOTE_HEAD = len(quoted)
while len(quoted) < 5000:
    quoted.append(random_string(24))
out_quote = []
for q in quoted:
    out_quote.append({"s": q, "unquote": unquote(q), "unquote_plus": unquote_plus(q), "quote": quote(q),
                      "quote_safe": quote(q, safe="/:@&=+$,;~\u00e9%"), "quote_empty": quote(q, safe=""),
                      "unquote_bytes": __import__("urllib.parse").parse.unquote_to_bytes(q).hex()})

qs_list = ["", "a", "a=", "=a", "a=1", "a=1&b=2", "a=1&&b=2", "&", "a=1&a=2&b=3", "a=1;b=2", "a+b=c+d", "a%3D=b%26",
           "a=%zz", "a=1=2", "=", "&=&", ";;", "a=1;", "%C3%A9=%E9"]
QS_HEAD = len(qs_list)
while len(qs_list) < 2500:
    qs_list.append(random_string(20))
out_qs = []
for q in qs_list:
    case = {"qs": q}
    for keep in (False, True):
        for strict in (False, True):
            for sep in ("&", ";"):
                key = "%d%d%s" % (keep, strict, sep)
                case["qsl" + key] = run(lambda: [list(x) for x in parse_qsl(q, keep, strict, separator=sep)])
                case["qs" + key] = run(lambda: [[k, v] for k, v in parse_qs(q, keep, strict, separator=sep).items()])
    out_qs.append(case)

dump({"split": sample(out_split, HEAD, 300_000), "join": joins, "quote": sample(out_quote, QUOTE_HEAD, 120_000),
      "qs": sample(out_qs, QS_HEAD, 150_000)})
