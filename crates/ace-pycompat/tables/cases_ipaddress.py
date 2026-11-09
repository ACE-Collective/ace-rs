# Cases for ipaddress. Output: tests/data/ipaddress.json.

import ipaddress

fixed = ["", "0.0.0.0", "1.2.3.4", "255.255.255.255", "256.1.1.1", "01.2.3.4", "1.2.3", "1.2.3.4.5", "1..2.3", "1.2.3.4/24",
         "\u0661.2.3.4", "1.2.3.\uff14", "1234.1.1.1", "::", "::1", "1::", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8:9", "1::2::3",
         ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:", "::ffff:1.2.3.4", "::1.2.3.4", "1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:7:1.2.3.4",
         "fe80::1%eth0", "fe80::1%", "fe80::1%a%b", "%eth0", "::%1", "1:2:3:4:5:6:7::", "::1:2:3:4:5:6:7", "::1:2:3:4:5:6:7:8",
         "12345::", "g::", "::ffff:1.2.3", "::ffff:01.2.3.4", "0:0:0:0:0:0:0:0", "1:0:0:2:0:0:0:3", "0:0:1:0:0:0:0:0",
         "1:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1", "2001:db8::0:1", "::ffff:0:0", "::fffe:1.2.3.4", "1" * 46, "1:" * 60,
         "a" * 120, "[::1]", "::1/128", "1.2.3.4%x", "::1.2.3.4%x", ":", "::::", ":::", "1:::", "1:2", " ::1", "::1 ",
         "\u0660::", "FFFF::FFFF", "::FFFF:255.255.255.255"]
rng_parts = ["0", "1", "00", "001", "255", "256", "ffff", "FFFF", "fffff", "g", "", "1.2.3.4", "a", "12", "0x1", "\uff11", "\u0661", " 1", "%1"]
cases = list(fixed)
HEAD = len(cases)
while len(cases) < 6000:
    r = rng.random()
    if r < 0.35:
        n = rng.choice([3, 4, 4, 4, 5])
        s = ".".join(rng.choice(["0", "1", "9", "10", "99", "100", "199", "200", "249", "250", "255", "256", "300", "999",
                                 "01", "00", "1000", "", "a", "\u0661", "1 "]) for _ in range(n))
    elif r < 0.85:
        n = rng.randrange(1, 11)
        s = ":".join(rng.choice(rng_parts) for _ in range(n))
        if rng.random() < 0.2:
            s += "%" + rng.choice(["eth0", "", "1", "%", "a%b", "\u00e9"])
    else:
        s = random_string(20)
    cases.append(s)


def v(a):
    return [isinstance(a, ipaddress.IPv4Address), str(a)]


out = []
for s in cases:
    out.append({"s": s, "ip_address": run(lambda: v(ipaddress.ip_address(s))),
                "v4": run(lambda: str(ipaddress.IPv4Address(s))), "v6": run(lambda: str(ipaddress.IPv6Address(s)))})
dump(sample(out, HEAD))
