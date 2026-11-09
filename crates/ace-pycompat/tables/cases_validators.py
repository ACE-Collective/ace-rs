# Cases for validators.url (simple_host False and True), validators.email and validators.domain.
# Output: tests/data/validators.json.

import validators

assert validators.__version__ == "0.36.0"

SCHEMES = ["http", "https", "HTTP", "ftp", "ftps", "file", "ssh", "telnet", "irc", "rtmp", "git", "mailto", "javascript", "x", ""]
HOSTS = ["example.com", "EXAMPLE.COM", "a.b.c.d", "localhost", "intranet", "a-b", "-ab", "ab-", "a_b", "a__b.com",
         "127.0.0.1", "256.1.1.1", "01.2.3.4", "[::1]", "[::1]:80", "::1", "[fe80::1%25eth0]", "[fe80::1%eth0]",
         "[v1.x]", "1.2.3.4:8080", "host:0", "host:65535", "host:65536", "host:080", "host:", ":80", "user@host",
         "user:pass@host", "user:pa/ss@host", "a:b:c@host", "%41:%42@host", "\u0100@host", "\"q\"@host", "a.b@host",
         "a..b@host", "a@b@host", "b\u00fccher.de", "xn--bcher-kva.de", "\u043f\u0440\u0438\u043c\u0435\u0440.\u0440\u0444",
         "\u212aelvin.com", "\u017fsite.com", "\u0130.com", "\u0131x.com", "a" * 63 + ".com", "a" * 64 + ".com",
         ("a" * 63 + ".") * 4 + "com", "x.c0m", "x.c", "x.co1", "x.1co", "x." + "a" * 62 + "b", "com", "c\u212a",
         "a\u212a", "\u00e9", "\u00e9.com", "x.\u00e9", "\u2100.com", "\u3002.com", "a\u3002com", "\uff21.com"]
PATHS = ["", "/", "/a/b", "/a b", "/%7e", "/\u00e9", "/\U0001f600", "/\U0001f680", "/\ud7ff", "/\ufdd0", "/\uffef",
         "/\ufff0", "/<x>", "/a\n", "/a|b", "/\u212a", "/\u0130"]
QUERIES = ["", "?", "?a=1", "?a=1&b=2", "?a", "?a=1&b", "?a=", "?a=&b", "?a=1;b=2", "?a=1;b", "?&", "?a=1&&b=2", "?=1"]
FRAGS = ["", "#", "#frag", "#a b", "#a#b", "#\u00e9", "#a%20b", "#[x]", "#\u212a"]


def random_url():
    r = rng.random()
    if r < 0.75:
        s = rng.choice(SCHEMES) + "://" + rng.choice(HOSTS) + rng.choice(PATHS) + rng.choice(QUERIES) + rng.choice(FRAGS)
        if rng.random() < 0.25:
            i = rng.randrange(0, len(s) + 1)
            s = s[:i] + random_string(3) + s[i:]
        return s
    return random_string(30)


USERS = ["a", "a.b", "a..b", ".a", "a.", "\"a b\"", "\"a\\\"b\"", "\"a\\.b\"", "\"\"", "\u00e9", "\u0100x", "\u212a",
         "\u1e9e", "a+b", "a b", "a" * 64, "a" * 65, "(a)", "a\\b", "\"a\n\"", "\u0130", "x\u0178"]


def random_email():
    if rng.random() < 0.8:
        u = rng.choice(USERS) if rng.random() < 0.6 else random_string(8)
        d = rng.choice(HOSTS) if rng.random() < 0.7 else random_string(10)
        return u + "@" + d
    return random_string(20)


cases = ["", " ", "http://example.com", "http://example.com\n", "http://a.b/c?d=e#f", "file:///etc/passwd",
         "file://localhost/x", "http://", "http://[::1", "a@b.com", "a@b.com\n", "a@b", "@b.com", "a@", "example.com",
         "example.com.", "example.com\n", "a.b", "-a.com", "a-.com", "1.com", "a.1", "a.b1", "a.b-"]
HEAD = len(cases)
while len(cases) < 4000:
    cases.append(random_url())
while len(cases) < 7000:
    cases.append(rng.choice(["http", "https", "ftp", "file", "ssh"]) + "://" + rng.choice(HOSTS) + rng.choice(PATHS)
                 + rng.choice(QUERIES) + rng.choice(FRAGS))
while len(cases) < 10000:
    cases.append(random_email())
while len(cases) < 13000:
    h = rng.choice(HOSTS) if rng.random() < 0.6 else random_string(12)
    cases.append(h)

out = []
for s in cases:
    out.append({"s": s, "url": bool(validators.url(s)), "url_simple": bool(validators.url(s, simple_host=True)),
                "email": bool(validators.email(s)), "domain": bool(validators.domain(s))})
dump(sample(out, HEAD))
