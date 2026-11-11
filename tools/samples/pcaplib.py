"""Frames and captures written by hand, for tools/samples/make-pcaps and make-pcap-hostile: Ethernet,
IPv4 and IPv6, UDP and TCP (with its handshake and segments), DNS, DHCP, NBNS, HTTP, TFTP, SMTP and
the TLS handshake messages tshark reads names, fingerprints and certificates from. Every name,
address and MAC is synthetic. ace3's synthesize_frames.py, which writes its network.pcap, is where
the UDP, DNS, DHCP and NBNS frames come from.
"""

import socket
import struct

BASE_TIME = 1767225600  # 2026-01-01T00:00:00Z


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def mac(text: str) -> bytes:
    return bytes.fromhex(text.replace(":", ""))


def is_v6(address: str) -> bool:
    return ":" in address


def ip_packet(src: str, dst: str, protocol: int, payload: bytes, ident: int = 1) -> tuple[bytes, bytes]:
    """The IP header and payload, and the Ethernet type for it."""
    if is_v6(src):
        header = struct.pack("!IHBB16s16s", 0x60000000, len(payload), protocol, 64,
                             socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst))
        return header + payload, b"\x86\xdd"
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF, 0, 64, protocol, 0,
                         socket.inet_aton(src), socket.inet_aton(dst))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload, b"\x08\x00"


def pseudo_header(src: str, dst: str, protocol: int, length: int) -> bytes:
    if is_v6(src):
        return (socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst)
                + struct.pack("!IxxxB", length, protocol))
    return socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!xBH", protocol, length)


def ethernet(src_mac: bytes, dst_mac: bytes, ethertype: bytes, payload: bytes) -> bytes:
    return dst_mac + src_mac + ethertype + payload


def udp_frame(src_mac: bytes, dst_mac: bytes, src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    value = checksum(pseudo_header(src, dst, 17, len(udp)) + udp) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", value) + udp[8:]
    packet, ethertype = ip_packet(src, dst, 17, udp)
    return ethernet(src_mac, dst_mac, ethertype, packet)


SYN, ACK, PSH, FIN = 0x02, 0x10, 0x08, 0x01


def tcp_frame(src_mac: bytes, dst_mac: bytes, src: str, dst: str, sport: int, dport: int, seq: int, ack: int,
              flags: int, payload: bytes = b"") -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, 65535, 0, 0)
    value = checksum(pseudo_header(src, dst, 6, len(tcp) + len(payload)) + tcp + payload)
    tcp = tcp[:16] + struct.pack("!H", value) + tcp[18:]
    packet, ethertype = ip_packet(src, dst, 6, tcp + payload)
    return ethernet(src_mac, dst_mac, ethertype, packet)


class TcpFlow:
    """One TCP connection: its handshake, then each side's data in segments of at most `mss`, then
    both FINs. Frames go to `frames`."""

    def __init__(self, frames: list, client: tuple, server: tuple, mss: int = 1400):
        (self.client_mac, self.client_ip, self.client_port) = client
        (self.server_mac, self.server_ip, self.server_port) = server
        self.frames = frames
        self.mss = mss
        self.client_seq = 1000
        self.server_seq = 5000
        self.send(True, b"", SYN)
        self.server_seq -= 1
        self.client_seq -= 1
        self.frames.append(tcp_frame(self.server_mac, self.client_mac, self.server_ip, self.client_ip,
                                     self.server_port, self.client_port, self.server_seq, self.client_seq + 1,
                                     SYN | ACK))
        self.server_seq += 1
        self.client_seq += 1
        self.send(True, b"", ACK)

    def send(self, from_client: bool, data: bytes, flags: int = PSH | ACK):
        if not data:
            self._segment(from_client, b"", flags)
            if flags & (SYN | FIN):
                self._advance(from_client, 1)
            return
        for start in range(0, len(data), self.mss):
            self._segment(from_client, data[start:start + self.mss], flags)

    def _segment(self, from_client: bool, data: bytes, flags: int):
        if from_client:
            frame = tcp_frame(self.client_mac, self.server_mac, self.client_ip, self.server_ip, self.client_port,
                              self.server_port, self.client_seq, self.server_seq, flags, data)
        else:
            frame = tcp_frame(self.server_mac, self.client_mac, self.server_ip, self.client_ip, self.server_port,
                              self.client_port, self.server_seq, self.client_seq, flags, data)
        self.frames.append(frame)
        self._advance(from_client, len(data))

    def _advance(self, from_client: bool, n: int):
        if from_client:
            self.client_seq += n
        else:
            self.server_seq += n

    def close(self):
        self.send(True, b"", FIN | ACK)
        self.send(False, b"", FIN | ACK)
        self.send(True, b"", ACK)


# ---- DNS, DHCP, NBNS (ace3's synthesize_frames.py, with more record types) ----

def dns_name(name: str) -> bytes:
    if name in ("", "."):
        return b"\x00"
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"


def dns_query(txid: int, name: str, qtype: int = 1) -> bytes:
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack("!HH", qtype, 1)


def rr(name: str, rtype: int, data: bytes, ttl: int = 300) -> bytes:
    return dns_name(name) + struct.pack("!HHIH", rtype, 1, ttl, len(data)) + data


def a_rr(name: str, address: str) -> bytes:
    return rr(name, 1, socket.inet_aton(address))


def aaaa_rr(name: str, address: str) -> bytes:
    return rr(name, 28, socket.inet_pton(socket.AF_INET6, address))


def cname_rr(name: str, target: str) -> bytes:
    return rr(name, 5, dns_name(target))


def ns_rr(name: str, server: str) -> bytes:
    return rr(name, 2, dns_name(server))


def soa_rr(zone: str) -> bytes:
    return rr(zone, 6, dns_name(f"ns1.{zone}") + dns_name(f"hostmaster.{zone}") + struct.pack("!IIIII", 1, 2, 3, 4, 5))


OPT_RR = b"\x00" + struct.pack("!HHIH", 41, 1232, 0, 0)


def dns_response(txid: int, name: str, answers: list[bytes], authority: list[bytes] = (), qtype: int = 1,
                 rcode: int = 0, opt: bool = True) -> bytes:
    question = dns_name(name) + struct.pack("!HH", qtype, 1)
    additional = [OPT_RR] if opt else []
    return (struct.pack("!HHHHHH", txid, 0x8180 | rcode, 1, len(answers), len(authority), len(additional))
            + question + b"".join(answers) + b"".join(authority) + b"".join(additional))


def dhcp_request(client_mac: bytes, client_ip: str, hostname: str) -> bytes:
    header = struct.pack("!BBBBIHH4s4s4s4s16s64s128s", 1, 1, 6, 0, 0x12345678, 0, 0x8000,
                         b"\x00" * 4, b"\x00" * 4, b"\x00" * 4, b"\x00" * 4,
                         client_mac + b"\x00" * 10, b"\x00" * 64, b"\x00" * 128)
    options = b"\x63\x82\x53\x63" + b"\x35\x01\x03" + b"\x32\x04" + socket.inet_aton(client_ip)
    options += b"\x0c" + bytes([len(hostname)]) + hostname.encode() + b"\xff"
    return header + options


def nbns_name(name: str, suffix: int = 0) -> bytes:
    padded = name.upper().ljust(15)[:15] + chr(suffix)
    encoded = "".join(chr(0x41 + (ord(c) >> 4)) + chr(0x41 + (ord(c) & 0x0F)) for c in padded)
    return bytes([32]) + encoded.encode() + b"\x00"


def nbns_registration(name: str, client_ip: str, suffix: int = 0) -> bytes:
    question = nbns_name(name, suffix) + struct.pack("!HH", 0x20, 1)
    record = b"\xc0\x0c" + struct.pack("!HHIH", 0x20, 1, 300000, 6) + b"\x00\x00" + socket.inet_aton(client_ip)
    return struct.pack("!HHHHHH", 0x4242, 0x2910, 1, 0, 0, 1) + question + record


# ---- HTTP, TFTP, SMTP ----

def http_request(host: str, path: str, user_agent: str | None, method: str = "GET", body: bytes = b"") -> bytes:
    lines = [f"{method} {path} HTTP/1.1", f"Host: {host}"]
    if user_agent is not None:
        lines.append(f"User-Agent: {user_agent}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def http_response(body: bytes, content_type: str = "text/plain", status: str = "200 OK",
                  headers: tuple = ()) -> bytes:
    lines = [f"HTTP/1.1 {status}", f"Content-Type: {content_type}", f"Content-Length: {len(body)}", *headers]
    return ("\r\n".join(lines) + "\r\n\r\n").encode() + body


def http_exchange(frames: list, client: tuple, server: tuple, host: str, path: str, user_agent: str | None,
                  body: bytes, content_type: str = "text/plain", headers: tuple = (), status: str = "200 OK"):
    flow = TcpFlow(frames, client, server)
    flow.send(True, http_request(host, path, user_agent))
    flow.send(False, http_response(body, content_type, status, headers))
    flow.close()


# ---- TLS handshake messages ----

def tls_record(handshakes: bytes, version: int = 0x0301) -> bytes:
    return struct.pack("!BHH", 0x16, version, len(handshakes)) + handshakes


def handshake(kind: int, body: bytes) -> bytes:
    return struct.pack("!B", kind) + len(body).to_bytes(3, "big") + body


def extension(kind: int, data: bytes) -> bytes:
    return struct.pack("!HH", kind, len(data)) + data


def client_hello(random: bytes, sni: str | None, ciphers: tuple = (0x1301, 0x1302, 0xc02b, 0xc02f),
                 alpn: str = "http/1.1", tls13: bool = True) -> bytes:
    extensions = b""
    if sni is not None:
        name = sni.encode()
        entry = b"\x00" + struct.pack("!H", len(name)) + name
        extensions += extension(0x0000, struct.pack("!H", len(entry)) + entry)
    groups = struct.pack("!HHH", 0x001d, 0x0017, 0x0018)
    extensions += extension(0x000a, struct.pack("!H", len(groups)) + groups)
    extensions += extension(0x000b, b"\x01\x00")
    algorithms = struct.pack("!HHHH", 0x0403, 0x0804, 0x0401, 0x0201)
    extensions += extension(0x000d, struct.pack("!H", len(algorithms)) + algorithms)
    protocol = alpn.encode()
    protocols = bytes([len(protocol)]) + protocol
    extensions += extension(0x0010, struct.pack("!H", len(protocols)) + protocols)
    if tls13:
        extensions += extension(0x002b, b"\x04\x03\x04\x03\x03")
    suites = b"".join(struct.pack("!H", c) for c in ciphers)
    body = (struct.pack("!H", 0x0303) + random + b"\x00" + struct.pack("!H", len(suites)) + suites + b"\x01\x00"
            + struct.pack("!H", len(extensions)) + extensions)
    return handshake(1, body)


def server_hello(random: bytes, cipher: int = 0xc02f) -> bytes:
    return handshake(2, struct.pack("!H", 0x0303) + random + b"\x00" + struct.pack("!HB", cipher, 0)
                     + struct.pack("!H", 0))


def certificate(ders: list[bytes]) -> bytes:
    certs = b"".join(len(der).to_bytes(3, "big") + der for der in ders)
    return handshake(11, len(certs).to_bytes(3, "big") + certs)


def tls_exchange(frames: list, client: tuple, server: tuple, random: bytes, sni: str | None, ders: list[bytes] = (),
                 ciphers: tuple = (0x1301, 0x1302, 0xc02b, 0xc02f)):
    flow = TcpFlow(frames, client, server)
    flow.send(True, tls_record(client_hello(random, sni, ciphers)))
    server_messages = server_hello(bytes(31) + b"\x01")
    if ders:
        server_messages += certificate(list(ders))
    flow.send(False, tls_record(server_messages, 0x0303))
    flow.close()


# ---- writing ----

def write_pcap(path, frames: list, linktype: int = 1, step_us: int = 1000):
    """A little-endian microsecond pcap, frame i at BASE_TIME + i * step_us microseconds."""
    with open(path, "wb") as fp:
        fp.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype))
        for index, frame in enumerate(frames):
            micros = index * step_us
            fp.write(struct.pack("<IIII", BASE_TIME + micros // 1_000_000, micros % 1_000_000, len(frame), len(frame)))
            fp.write(frame)
