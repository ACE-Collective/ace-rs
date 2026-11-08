"""A fake DNS server for ace3's DNS lookups in the reference dumps and the trees (PLAN.md 7.4).

It runs inside ace3's dev container on ace3's Python and dnspython, on 127.0.0.1 over UDP, and
answers from a zone fixture as a recursive resolver would: a CNAME is followed inside the zone and
the whole chain goes in the answer, a name the zone has with no record of the type asked is an empty
NOERROR, a name it doesn't have is NXDOMAIN, and a name listed under `servfail` is SERVFAIL. A name
under `*.<name>` matches a wildcard. run_module.py's `--dns` points ace3's resolver here.

Every exchange is written to the recording, as the query's name and type and the response's bytes,
so a port's tests replay exactly what ace3 was told (`ace_testkit::dns`).

    python3 -I fake_dns.py --zone zone.json --port 5353 --record dns.json --pid-file pid

The zone fixture:

    {"names": {"example.com": {"A": ["192.0.2.10"], "MX": ["10 mail.example.com."]},
               "www.example.com": {"CNAME": ["edge.example.net."]},
               "*.wild.example.org": {"A": ["192.0.2.40"]}},
     "servfail": ["broken.example.com"]}
"""

import argparse
import json
import os
import socket

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

TTL = 300


def load_zone(path):
    with open(path) as fp:
        zone = json.load(fp)
    names = {dns.name.from_text(name): records for name, records in zone["names"].items()}
    servfail = {dns.name.from_text(name) for name in zone.get("servfail", [])}
    return names, servfail


def records_of(names, name):
    """The records the zone has for `name`, directly or through a wildcard, or None."""
    if name in names:
        return names[name]
    for depth in range(1, len(name.labels) - 1):
        wildcard = dns.name.Name((b"*",) + name.labels[depth:])
        if wildcard in names:
            return names[wildcard]
    return None


def answer(names, servfail, query):
    response = dns.message.make_response(query)
    response.flags |= dns.flags.RA
    question = query.question[0]
    name, rdtype = question.name, question.rdtype
    if name in servfail:
        response.set_rcode(dns.rcode.SERVFAIL)
        return response
    for _ in range(8):
        records = records_of(names, name)
        if records is None:
            # an NXDOMAIN at the end of a chain is still the chain's answer
            response.set_rcode(dns.rcode.NXDOMAIN)
            return response
        cname = records.get("CNAME")
        if cname and rdtype != dns.rdatatype.CNAME:
            rrset = dns.rrset.from_text_list(name, TTL, dns.rdataclass.IN, dns.rdatatype.CNAME, cname)
            response.answer.append(rrset)
            name = rrset[0].target
            continue
        texts = records.get(dns.rdatatype.to_text(rdtype))
        if texts:
            response.answer.append(dns.rrset.from_text_list(name, TTL, dns.rdataclass.IN, rdtype, texts))
        return response
    response.set_rcode(dns.rcode.SERVFAIL)
    return response


def main():
    parser = argparse.ArgumentParser(prog="fake_dns.py")
    parser.add_argument("--zone", required=True)
    parser.add_argument("--port", type=int, default=5353)
    parser.add_argument("--record", required=True, help="the recording to write, as JSON")
    parser.add_argument("--pid-file", required=True)
    args = parser.parse_args()

    names, servfail = load_zone(args.zone)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", args.port))
    exchanges = []
    with open(args.pid_file, "w") as fp:
        fp.write(str(os.getpid()))
    while True:
        wire, peer = sock.recvfrom(65535)
        try:
            query = dns.message.from_wire(wire)
        except Exception:
            continue
        response = answer(names, servfail, query)
        out = response.to_wire()
        sock.sendto(out, peer)
        question = query.question[0]
        exchanges.append(
            {
                "name": question.name.to_text(omit_final_dot=True).lower(),
                "type": dns.rdatatype.to_text(question.rdtype),
                "response": out.hex(),
            }
        )
        with open(args.record + ".tmp", "w") as fp:
            json.dump(
                {
                    "about": "Every DNS query ace3 made of tools/ace3/dumps/fake_dns.py, in order, "
                    "with the bytes of the response it got.",
                    "exchanges": exchanges,
                },
                fp,
                indent=2,
            )
            fp.write("\n")
        os.replace(args.record + ".tmp", args.record)


if __name__ == "__main__":
    main()
