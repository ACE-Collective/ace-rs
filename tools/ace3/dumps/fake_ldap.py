"""A fake LDAP server for ace3's user_analyzer in the reference dumps (PLAN.md 7.4).

It runs inside ace3's dev container on ace3's Python, on 127.0.0.1 over plain TCP, as ace3's
module binds (in plaintext, on its configured port), and answers from a directory fixture:

- a simple bind, with the fixture's bind DN and password, and invalidCredentials (49) otherwise;
- a base search of the root DSE ("") or of the schema entry, which answer with every attribute the
  fixture gives them, so ldap3's get_info=ALL reads the fixture's schema;
- a subtree or one-level search under an entry, matching an equality, presence, substring, and,
  or or not filter, value by value without regard to case, as AD's directory strings compare;
- the simple paged results control (RFC 2696, 1.2.840.113556.1.4.319): a page holds the size the
  client asks for, or --page-limit entries when that's fewer, and a cookie when entries are left;
- an unbind.

Attribute values in the fixture are strings, or {"hex": "..."} for bytes. Every search is written
to the recording, as its base, scope, filter (in ldap3's string form), attributes and paging, so a
port's tests can check they ask what ace3 asked. ace_testkit::ldap serves the same fixture the same
way for ace-rs's tests.

    python3 -I fake_ldap.py --directory directory.json --port 3890 --record ldap.json --pid-file pid
"""

import argparse
import json
import os
import socket
import socketserver
import threading

PAGED = "1.2.840.113556.1.4.319"


# ---- BER ----

def ber_length(n):
    if n < 0x80:
        return bytes([n])
    out = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(out)]) + out


def tlv(tag, content):
    return bytes([tag]) + ber_length(len(content)) + content


def ber_int(tag, value):
    out = value.to_bytes(max(1, (value.bit_length() + 8) // 8), "big", signed=True)
    return tlv(tag, out)


def read_tlv(data, pos):
    """The tag, the content and the position after it."""
    tag = data[pos]
    pos += 1
    length = data[pos]
    pos += 1
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    return tag, data[pos:pos + length], pos + length


def children(content):
    out, pos = [], 0
    while pos < len(content):
        tag, value, pos = read_tlv(content, pos)
        out.append((tag, value))
    return out


def as_int(content):
    return int.from_bytes(content, "big", signed=True) if content else 0


# ---- filters ----

def escape(value):
    """ldap3's escape of a filter value, for the recording."""
    out = []
    for b in value:
        c = chr(b)
        if c in "*()\\\x00" or b > 0x7F:
            out.append("\\%02x" % b)
        else:
            out.append(c)
    return "".join(out)


def filter_text(tag, content):
    if tag == 0xA0:
        return "(&" + "".join(filter_text(t, c) for t, c in children(content)) + ")"
    if tag == 0xA1:
        return "(|" + "".join(filter_text(t, c) for t, c in children(content)) + ")"
    if tag == 0xA2:
        (t, c), = children(content)
        return "(!" + filter_text(t, c) + ")"
    if tag == 0xA3:
        (_, attr), (_, value) = children(content)
        return f"({attr.decode()}={escape(value)})"
    if tag == 0x87:
        return f"({content.decode()}=*)"
    if tag == 0xA4:
        (_, attr), (_, subs) = children(content)
        parts = {0x80: [], 0x81: [], 0x82: []}
        for t, c in children(subs):
            parts[t].append(escape(c))
        text = (parts[0x80][0] if parts[0x80] else "") + "*" + "".join(p + "*" for p in parts[0x81])
        text += parts[0x82][0] if parts[0x82] else ""
        return f"({attr.decode()}={text})"
    return f"(unsupported filter {tag:#x})"


def values_of(entry, name):
    for key, values in entry["attributes"].items():
        if key.lower() == name.lower():
            return [raw(v) for v in values]
    return []


def matches(entry, tag, content):
    if tag == 0xA0:
        return all(matches(entry, t, c) for t, c in children(content))
    if tag == 0xA1:
        return any(matches(entry, t, c) for t, c in children(content))
    if tag == 0xA2:
        (t, c), = children(content)
        return not matches(entry, t, c)
    if tag == 0xA3:
        (_, attr), (_, value) = children(content)
        return any(v.lower() == value.lower() for v in values_of(entry, attr.decode()))
    if tag == 0x87:
        return bool(values_of(entry, content.decode())) or content.decode().lower() == "objectclass"
    if tag == 0xA4:
        (_, attr), (_, subs) = children(content)
        for value in values_of(entry, attr.decode()):
            value, pos, ok = value.lower(), 0, True
            for t, c in children(subs):
                c = c.lower()
                if t == 0x80:
                    ok = value.startswith(c)
                    pos = len(c)
                elif t == 0x81:
                    found = value.find(c, pos)
                    ok = found >= 0
                    pos = found + len(c)
                else:
                    ok = value.endswith(c) and len(value) - len(c) >= pos
                if not ok:
                    break
            if ok:
                return True
        return False
    return False


# ---- the directory ----

def raw(value):
    if isinstance(value, dict):
        return bytes.fromhex(value["hex"])
    return value.encode("utf-8")


def under(dn, base):
    return dn.lower() == base.lower() or dn.lower().endswith("," + base.lower())


def entry_message(entry, wanted):
    attributes = b""
    everything = not wanted or "*" in wanted
    for name, values in entry["attributes"].items():
        if not everything and name.lower() not in wanted:
            continue
        vals = b"".join(tlv(0x04, raw(v)) for v in values)
        attributes += tlv(0x30, tlv(0x04, name.encode()) + tlv(0x31, vals))
    return tlv(0x64, tlv(0x04, entry["dn"].encode()) + tlv(0x30, attributes))


def result(tag, code, message=""):
    return tlv(tag, ber_int(0x0A, code) + tlv(0x04, b"") + tlv(0x04, message.encode()))


class Server:
    def __init__(self, directory, record, page_limit):
        self.directory = directory
        self.record = record
        self.page_limit = page_limit
        self.searches = []
        self.lock = threading.Lock()

    def save(self):
        with self.lock, open(self.record, "w") as fp:
            json.dump({"about": "The searches ace3 made of tools/ace3/dumps/fake_ldap.py, in order.",
                       "searches": self.searches}, fp, indent=2)

    def search(self, content, controls):
        fields = children(content)
        base = fields[0][1].decode()
        scope = as_int(fields[1][1])
        filter_tag, filter_content = fields[6]
        wanted = [v.decode().lower() for _, v in children(fields[7][1])]
        paging = None
        for control in controls:
            parts = children(control)
            if parts[0][1].decode() == PAGED:
                value = parts[-1][1]
                (_, size), (_, cookie) = children(children(value)[0][1])
                paging = (as_int(size), cookie)
        with self.lock:
            self.searches.append({
                "base": base, "scope": ["base", "one", "subtree"][scope],
                "filter": filter_text(filter_tag, filter_content),
                "attributes": [v.decode() for _, v in children(fields[7][1])],
                "paged": None if paging is None else {"size": paging[0], "cookie": paging[1].decode()},
            })
        self.save()
        if scope == 0:
            special = {"": self.directory["root_dse"], self.directory["schema_dn"].lower(): self.directory["schema"]}
            attrs = special.get(base.lower())
            if attrs is not None:
                return [entry_message({"dn": base, "attributes": attrs}, [])], None
            found = [e for e in self.directory["entries"] if e["dn"].lower() == base.lower()]
        else:
            found = [e for e in self.directory["entries"] if under(e["dn"], base)
                     and (scope == 2 or e["dn"].lower() != base.lower())]
        found = [e for e in found if matches(e, filter_tag, filter_content)]
        cookie_out = None
        if paging is not None:
            size, cookie = paging
            start = int(cookie.decode()) if cookie else 0
            size = min(size, self.page_limit) if self.page_limit else size
            end = start + size if size else len(found)
            cookie_out = str(end).encode() if end < len(found) else b""
            found = found[start:end]
        return [entry_message(e, wanted) for e in found], cookie_out


def handler_for(server):
    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            sock = self.request
            buffer = b""
            while True:
                try:
                    chunk = sock.recv(65536)
                except OSError:
                    return
                if not chunk:
                    return
                buffer += chunk
                while True:
                    try:
                        tag, content, end = read_tlv(buffer, 0)
                    except IndexError:
                        break
                    if end > len(buffer):
                        break
                    buffer = buffer[end:]
                    parts = children(content)
                    message_id = as_int(parts[0][1])
                    op_tag, op = parts[1]
                    controls = [c for t, c in children(parts[2][1])] if len(parts) > 2 and parts[2][0] == 0xA0 else []
                    out = []
                    if op_tag == 0x60:  # bind
                        fields = children(op)
                        dn, password = fields[1][1].decode(), fields[2][1].decode()
                        ok = dn == server.directory["bind_dn"] and password == server.directory["bind_password"]
                        out.append(result(0x61, 0 if ok else 49, "" if ok else "invalid credentials"))
                    elif op_tag == 0x42:  # unbind
                        return
                    elif op_tag == 0x63:  # search
                        entries, cookie = server.search(op, controls)
                        out.extend(entries)
                        done = result(0x65, 0)
                        if cookie is not None:
                            value = tlv(0x30, ber_int(0x02, 0) + tlv(0x04, cookie))
                            control = tlv(0x30, tlv(0x04, PAGED.encode()) + tlv(0x04, value))
                            done_msg = tlv(0x30, ber_int(0x02, message_id) + done + tlv(0xA0, control))
                            for e in out:
                                sock.sendall(tlv(0x30, ber_int(0x02, message_id) + e))
                            sock.sendall(done_msg)
                            continue
                        out.append(done)
                    else:
                        out.append(result(op_tag + 1, 2, "unsupported operation"))
                    for message in out:
                        sock.sendall(tlv(0x30, ber_int(0x02, message_id) + message))

    return Handler


def main():
    parser = argparse.ArgumentParser(prog="fake_ldap.py")
    parser.add_argument("--directory", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--record", required=True)
    parser.add_argument("--pid-file", required=True)
    parser.add_argument("--page-limit", type=int, default=0, help="the most entries a page holds")
    args = parser.parse_args()
    with open(args.directory) as fp:
        directory = json.load(fp)
    server = Server(directory, args.record, args.page_limit)
    server.save()
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    tcp = socketserver.ThreadingTCPServer(("127.0.0.1", args.port), handler_for(server))
    with open(args.pid_file, "w") as fp:
        fp.write(str(os.getpid()))
    tcp.serve_forever()


if __name__ == "__main__":
    main()
