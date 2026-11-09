"""Writes the cases ace-x509's tests compare with ace3: certificates and other inputs, built with
cryptography 50.0.2 and by hand, plus mutations of them.

Run in ace3's dev container (ace-dev-1): /venv/bin/python3 -I gen_corpus.py OUT.json [SCALE [SEED]]
SCALE (default 1) multiplies the random and mutated cases; a larger run is for a one-off check.
Each case is {"name": ..., "b64": ...}. Mutations use fixed seeds, but ECDSA signatures and the RSA
key are random, so a rerun writes different bytes; the tests compare against whatever oracle.py
recorded for these bytes.
"""

import base64
import datetime
import ipaddress
import json
import random
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    ExtensionOID,
    NameOID,
    ObjectIdentifier,
)

CASES = []


def add(name, data):
    CASES.append({"name": name, "b64": base64.b64encode(data).decode()})


# ---- a small DER encoder, for what cryptography will not build -------------------------------


def tlv(tag, content):
    n = len(content)
    if n < 0x80:
        length = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + length + content


def seq(*items):
    return tlv(0x30, b"".join(items))


def set_(*items, sort=True):
    items = list(items)
    if sort:
        items.sort()
    return tlv(0x31, b"".join(items))


def oid(dotted):
    arcs = [int(a) for a in dotted.split(".")]
    out = bytearray()
    for i, a in enumerate([arcs[0] * 40 + arcs[1]] + arcs[2:]):
        chunk = [a & 0x7F]
        a >>= 7
        while a:
            chunk.append(0x80 | (a & 0x7F))
            a >>= 7
        out += bytes(reversed(chunk))
    return tlv(0x06, bytes(out))


def integer(v):
    if isinstance(v, bytes):
        return tlv(0x02, v)
    n = (v.bit_length() + 8) // 8
    return tlv(0x02, v.to_bytes(n, "big", signed=True))


def octets(b):
    return tlv(0x04, b)


def bits(b, unused=0):
    return tlv(0x03, bytes([unused]) + b)


def explicit(n, content):
    return tlv(0xA0 | n, content)


def utctime(s):
    return tlv(0x17, s.encode())


def gentime(s):
    return tlv(0x18, s.encode())


def boolean(v):
    return tlv(0x01, b"\xff" if v else b"\x00")


NULL = b"\x05\x00"
SHA256_RSA = seq(oid("1.2.840.113549.1.1.11"), NULL)
ECDSA_SHA256 = seq(oid("1.2.840.10045.4.3.2"))

KEY_EC = ec.derive_private_key(12345678901234567890, ec.SECP256R1())
KEY_EC384 = ec.derive_private_key(98765432109876543210, ec.SECP384R1())
KEY_ED = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
_rsa = None


def key_rsa():
    global _rsa
    if _rsa is None:
        # A fixed key would be nicer; generating one is fast enough and only its public part
        # ends up in the certificates, which the tests store as bytes anyway.
        _rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return _rsa


SPKI_EC = KEY_EC.public_key().public_bytes(
    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
)


def name_der(rdns):
    """rdns: list of RDNs, each a list of (oid, tag, value bytes)."""
    return seq(*[set_(*[seq(oid(o), tlv(t, v)) for (o, t, v) in rdn]) for rdn in rdns])


CN_A = name_der([[("2.5.4.3", 0x0C, b"example.com")]])


def make_cert(
    serial=integer(5),
    issuer=CN_A,
    subject=CN_A,
    not_before=utctime("200101000000Z"),
    not_after=utctime("300101000000Z"),
    exts=None,
    version=b"default",
    sig_alg=ECDSA_SHA256,
    outer_alg=None,
    spki=SPKI_EC,
    extra_tbs=b"",
    raw_exts=None,
):
    items = []
    if version == b"default":
        items.append(explicit(0, integer(2)))
    elif version is not None:
        items.append(explicit(0, version))
    items += [serial, sig_alg, issuer, seq(not_before, not_after), subject, spki]
    items.append(extra_tbs)
    if raw_exts is not None:
        items.append(explicit(3, raw_exts))
    elif exts:
        ext_items = []
        for e in exts:
            o, crit, val = e
            parts = [oid(o)]
            if crit is not None:
                parts.append(boolean(crit))
            parts.append(octets(val))
            ext_items.append(seq(*parts))
        items.append(explicit(3, seq(*ext_items)))
    tbs = seq(*items)
    return seq(tbs, outer_alg or sig_alg, bits(b"\x01" * 64))


def pem(der, label="CERTIFICATE"):
    b = base64.encodebytes(der).decode().replace("\n", "")
    lines = [b[i : i + 64] for i in range(0, len(b), 64)]
    return (f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n").encode()


# ---- certificates built with cryptography ---------------------------------------------------


def builder(subject, issuer=None, serial=1, nb=None, na=None, key=None):
    key = key or KEY_EC
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer or subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(nb or datetime.datetime(2020, 1, 1))
        .not_valid_after(na or datetime.datetime(2030, 1, 1))
    )


def sign(b, key=None):
    key = key or KEY_EC
    alg = None if isinstance(key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return b.sign(key, alg).public_bytes(serialization.Encoding.DER)


def NA(o, v, t=None):
    return x509.NameAttribute(o, v, t) if t else x509.NameAttribute(o, v)


def simple_name(cn):
    return x509.Name([NA(NameOID.COMMON_NAME, cn)])


def built_certs():
    out = []
    n = x509.Name(
        [
            NA(NameOID.COUNTRY_NAME, "US"),
            NA(NameOID.STATE_OR_PROVINCE_NAME, "Ohio"),
            NA(NameOID.LOCALITY_NAME, "Cincinnati"),
            NA(NameOID.ORGANIZATION_NAME, "Example, Inc."),
            NA(NameOID.ORGANIZATIONAL_UNIT_NAME, "IT+Ops"),
            NA(NameOID.COMMON_NAME, "www.example.com"),
        ]
    )
    out.append(("ec_basic", sign(builder(n))))
    out.append(("ed25519", sign(builder(simple_name("ed.example")), KEY_ED)))
    out.append(("ec384", sign(builder(simple_name("p384"), key=KEY_EC384), KEY_EC384)))
    out.append(("rsa", sign(builder(simple_name("rsa.example"), key=key_rsa()), key_rsa())))
    # CA-signed
    ca_name = x509.Name([NA(NameOID.ORGANIZATION_NAME, "Test CA"), NA(NameOID.COMMON_NAME, "Test Root")])
    out.append(
        (
            "ca_signed",
            sign(
                builder(simple_name("leaf.example"), issuer=ca_name, serial=0x1234567890ABCDEF1234567890ABCDEF)
                .add_extension(x509.BasicConstraints(False, None), True)
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(KEY_EC384.public_key()), False
                ),
                KEY_EC384,
            ),
        )
    )
    # odd names
    odd = [
        ("escapes", [NA(NameOID.COMMON_NAME, ' #lead\\"+,;<>=\x00 trail ')]),
        ("hash_first", [NA(NameOID.COMMON_NAME, "#x")]),
        ("space_only", [NA(NameOID.ORGANIZATION_NAME, " ")]),
        ("space_two", [NA(NameOID.ORGANIZATION_NAME, "  ")]),
        ("unicode", [NA(NameOID.COMMON_NAME, "üñî.例え.テスト"), NA(NameOID.ORGANIZATION_NAME, "Zß\U0001f600")]),
        ("bmp", [NA(NameOID.COMMON_NAME, "bmp é中", _ASN1Type.BMPString)]),
        ("bmp_astral", [NA(NameOID.ORGANIZATION_NAME, "astral \U0001f600", _ASN1Type.BMPString)]),
        ("universal", [NA(NameOID.COMMON_NAME, "univ \U0001f600", _ASN1Type.UniversalString)]),
        ("t61", [NA(NameOID.COMMON_NAME, "teletex", _ASN1Type.T61String)]),
        ("t61_utf8", [NA(NameOID.COMMON_NAME, "tél", _ASN1Type.T61String)]),
        ("printable", [NA(NameOID.COMMON_NAME, "Printable", _ASN1Type.PrintableString)]),
        ("ia5", [NA(NameOID.COMMON_NAME, "ia5", _ASN1Type.IA5String)]),
        ("visible", [NA(NameOID.COMMON_NAME, "visible", _ASN1Type.VisibleString)]),
        ("numeric", [NA(NameOID.SERIAL_NUMBER, "12345", _ASN1Type.NumericString)]),
        ("utctime_type", [NA(NameOID.COMMON_NAME, "200101000000Z", _ASN1Type.UTCTime)]),
        ("octet_type", [NA(NameOID.COMMON_NAME, "octet", _ASN1Type.OctetString)]),
        ("bitstring", [NA(NameOID.X500_UNIQUE_IDENTIFIER, b"\x00\x01\x02", _ASN1Type.BitString)]),
        ("bitstring_empty", [NA(NameOID.X500_UNIQUE_IDENTIFIER, b"", _ASN1Type.BitString)]),
        ("many_cn", [NA(NameOID.COMMON_NAME, "first"), NA(NameOID.COMMON_NAME, "second"), NA(NameOID.COMMON_NAME, "*.third.example")]),
        ("wildcard", [NA(NameOID.COMMON_NAME, "*.example.org")]),
        ("no_cn", [NA(NameOID.ORGANIZATION_NAME, "No CN")]),
        ("empty_name", []),
        (
            "all_oids",
            [
                NA(NameOID.COUNTRY_NAME, "DE"),
                NA(NameOID.JURISDICTION_COUNTRY_NAME, "FR"),
                NA(NameOID.STREET_ADDRESS, "1 Main St"),
                NA(NameOID.DOMAIN_COMPONENT, "com"),
                NA(NameOID.DOMAIN_COMPONENT, "example"),
                NA(NameOID.USER_ID, "uid1"),
                NA(NameOID.EMAIL_ADDRESS, "a@b.c"),
                NA(NameOID.SERIAL_NUMBER, "SN1"),
                NA(NameOID.SURNAME, "Doe"),
                NA(NameOID.GIVEN_NAME, "Jane"),
                NA(NameOID.TITLE, "Dr"),
                NA(NameOID.PSEUDONYM, "jd"),
                NA(NameOID.BUSINESS_CATEGORY, "biz"),
                NA(NameOID.POSTAL_CODE, "12345"),
                NA(ObjectIdentifier("1.2.3.4.5"), "custom"),
            ],
        ),
    ]
    for label, attrs in odd:
        out.append((f"name_{label}", sign(builder(x509.Name(attrs)))))
    multi = x509.Name(
        [
            x509.RelativeDistinguishedName([NA(NameOID.COMMON_NAME, "multi"), NA(NameOID.ORGANIZATION_NAME, "O+")]),
            x509.RelativeDistinguishedName([NA(NameOID.COUNTRY_NAME, "US")]),
        ]
    )
    out.append(("name_multi_rdn", sign(builder(multi))))
    # serials and dates
    for nbytes in (1, 2, 7, 8, 9, 16, 19, 20):
        out.append((f"serial_{nbytes}", sign(builder(simple_name("s"), serial=(1 << (8 * nbytes - 2)) + 7))))
    for y in (1950, 1951, 2049, 2050, 2100, 9999):
        nb = datetime.datetime(y, 6, 15, 12, 30, 45)
        out.append((f"date_{y}", sign(builder(simple_name("d"), nb=nb, na=datetime.datetime(9999, 12, 31, 23, 59, 59)))))
    # every extension cryptography builds
    exts = [
        x509.SubjectAlternativeName(
            [
                x509.DNSName("a.example"),
                x509.DNSName("*.wild.example"),
                x509.IPAddress(ipaddress.ip_address("192.0.2.1")),
                x509.IPAddress(ipaddress.ip_address("2001:db8::1")),
                x509.IPAddress(ipaddress.ip_address("::ffff:1.2.3.4")),
                x509.IPAddress(ipaddress.ip_network("10.0.0.0/8")),
                x509.IPAddress(ipaddress.ip_network("2001:db8::/32")),
                x509.RFC822Name("user@example.com"),
                x509.UniformResourceIdentifier("https://example.com/p?q='x'"),
                x509.DirectoryName(multi),
                x509.RegisteredID(ObjectIdentifier("1.2.3.4")),
                x509.OtherName(ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"), b"\x0c\x05upn@x"),
            ]
        ),
        x509.IssuerAlternativeName([x509.DNSName("issuer.example"), x509.UniformResourceIdentifier("http://i")]),
        x509.SubjectKeyIdentifier(b"\x00\x01'\"\\\xff"),
        x509.AuthorityKeyIdentifier(b"\x09\x08", [x509.DirectoryName(simple_name("ca"))], 123456789012345678901234567890),
        x509.BasicConstraints(True, 3),
        x509.KeyUsage(True, True, True, True, True, True, True, True, False),
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH, ObjectIdentifier("1.2.3.4.5.6")]),
        x509.CRLDistributionPoints(
            [
                x509.DistributionPoint([x509.UniformResourceIdentifier("http://crl.example/a.crl")], None, None, None),
                x509.DistributionPoint(
                    None,
                    x509.RelativeDistinguishedName([NA(NameOID.COMMON_NAME, "rel")]),
                    frozenset([x509.ReasonFlags.key_compromise]),
                    [x509.DNSName("crl-issuer")],
                ),
            ]
        ),
        x509.FreshestCRL([x509.DistributionPoint([x509.UniformResourceIdentifier("http://delta")], None, None, None)]),
        x509.AuthorityInformationAccess(
            [
                x509.AccessDescription(AuthorityInformationAccessOID.OCSP, x509.UniformResourceIdentifier("http://ocsp")),
                x509.AccessDescription(AuthorityInformationAccessOID.CA_ISSUERS, x509.UniformResourceIdentifier("http://ca")),
            ]
        ),
        x509.SubjectInformationAccess(
            [x509.AccessDescription(ObjectIdentifier("1.3.6.1.5.5.7.48.5"), x509.UniformResourceIdentifier("http://repo"))]
        ),
        x509.CertificatePolicies(
            [
                x509.PolicyInformation(ObjectIdentifier("2.23.140.1.2.1"), None),
                x509.PolicyInformation(
                    ObjectIdentifier("1.3.6.1.4.1.99.1"),
                    [
                        "http://cps.example",
                        x509.UserNotice(x509.NoticeReference("Org 'q'", [1, 2, 30000000000]), "explicit text é"),
                        x509.UserNotice(None, None),
                    ],
                ),
            ]
        ),
        x509.PolicyConstraints(1, None),
        x509.InhibitAnyPolicy(0),
        x509.NameConstraints(
            [x509.DNSName("permitted.example"), x509.IPAddress(ipaddress.ip_network("192.168.0.0/16"))],
            [x509.IPAddress(ipaddress.ip_network("fe80::/10")), x509.DirectoryName(simple_name("ex"))],
        ),
        x509.TLSFeature([x509.TLSFeatureType.status_request, x509.TLSFeatureType.status_request_v2]),
        x509.OCSPNoCheck(),
        x509.PrecertPoison(),
        x509.MSCertificateTemplate(ObjectIdentifier("1.3.6.1.4.1.311.21.8.1"), 100, None),
        x509.Admissions(
            x509.DNSName("authority"),
            [
                x509.Admission(
                    x509.UniformResourceIdentifier("http://adm"),
                    x509.NamingAuthority(ObjectIdentifier("1.2.3"), "http://na", "na text"),
                    [
                        x509.ProfessionInfo(
                            x509.NamingAuthority(None, None, None),
                            ["Doctor", "Pharmacist"],
                            [ObjectIdentifier("1.2.276.0.76.4.10")],
                            "REG1",
                            b"\x04\x00",
                        ),
                        x509.ProfessionInfo(None, [], None, None, None),
                    ],
                )
            ],
        ),
        x509.PrivateKeyUsagePeriod(datetime.datetime(2021, 1, 1), datetime.datetime(2022, 2, 2, 3, 4, 5)),
        x509.UnrecognizedExtension(ObjectIdentifier("1.2.3.4.5.6.7"), b"\x04\x02hi"),
    ]
    b = builder(simple_name("all.extensions"))
    for i, e in enumerate(exts):
        b = b.add_extension(e, i % 3 == 0)
    out.append(("all_extensions", sign(b)))
    for i, e in enumerate(exts):
        for crit in (False, True):
            out.append((f"ext_{type(e).__name__}_{crit}", sign(builder(simple_name("one")).add_extension(e, crit))))
    ku_variants = [
        (False,) * 9,
        (False, False, False, False, True, False, False, False, False),
        (False, False, False, False, True, False, False, True, True),
        (False, False, False, False, True, False, False, False, True),
        (True,) * 9,
    ]
    for i, v in enumerate(ku_variants):
        out.append((f"ku_{i}", sign(builder(simple_name("ku")).add_extension(x509.KeyUsage(*v), False))))
    for reasons in ([], [x509.ReasonFlags.ca_compromise, x509.ReasonFlags.aa_compromise], list(x509.ReasonFlags)[1:9]):
        dp = x509.DistributionPoint([x509.DNSName("x")], None, frozenset(reasons) if reasons else None, None)
        out.append((f"dp_reasons_{len(reasons)}", sign(builder(simple_name("dp")).add_extension(x509.CRLDistributionPoints([dp]), False))))
    out.append(("pkup_before_only", sign(builder(simple_name("p")).add_extension(x509.PrivateKeyUsagePeriod(datetime.datetime(2021, 1, 1), None), False))))
    out.append(("bc_false", sign(builder(simple_name("b")).add_extension(x509.BasicConstraints(False, None), False))))
    out.append(("bc_ca_nolen", sign(builder(simple_name("b")).add_extension(x509.BasicConstraints(True, None), True))))
    out.append(("pc_both", sign(builder(simple_name("p")).add_extension(x509.PolicyConstraints(2, 3), True))))
    out.append(("pc_inhibit", sign(builder(simple_name("p")).add_extension(x509.PolicyConstraints(None, 0), True))))
    out.append(("ms_tpl_both", sign(builder(simple_name("m")).add_extension(x509.MSCertificateTemplate(ObjectIdentifier("1.2.3"), 1, 2), False))))
    out.append(("aki_kid_only", sign(builder(simple_name("a")).add_extension(x509.AuthorityKeyIdentifier(b"k", None, None), False))))
    out.append(("aki_empty", sign(builder(simple_name("a")).add_extension(x509.AuthorityKeyIdentifier(None, None, None), False))))
    return out


# ---- hand-made certificates -----------------------------------------------------------------


def crafted():
    out = []
    # versions
    out.append(("v1_absent", make_cert(version=None)))
    out.append(("v1_explicit_zero", make_cert(version=integer(0))))
    out.append(("v2", make_cert(version=integer(1))))
    out.append(("v4", make_cert(version=integer(3))))
    out.append(("v_big", make_cert(version=integer(300))))
    # serials
    for v in (b"\x00", b"\x01", b"\xff", b"\x80", b"\x00\x80", b"\x00\x01", b"\xff\x7f", bytes([0x7F]) + b"\xff" * 19, b"\x80" + b"\x00" * 19, bytes([0x55]) * 21, b"\x00" * 2, b""):
        out.append((f"serial_raw_{v.hex() or 'empty'}", make_cert(serial=integer(v))))
    for v in (-1, -128, -129, -(1 << 100), 0):
        out.append((f"serial_int_{v}", make_cert(serial=integer(v))))
    # times
    times = [
        ("utc_1950", utctime("500101000000Z")),
        ("utc_2049", utctime("491231235959Z")),
        ("gen_1949", gentime("19491231235959Z")),
        ("gen_2050", gentime("20500101000000Z")),
        ("gen_0001", gentime("00010101000000Z")),
        ("gen_0000", gentime("00000101000000Z")),
        ("gen_frac", gentime("20200101000000.5Z")),
        ("gen_noz", gentime("20200101000000")),
        ("utc_noseconds", utctime("2001010000Z")),
        ("utc_offset", utctime("200101000000+0100")),
        ("utc_feb29", utctime("240229000000Z")),
        ("utc_feb30", utctime("230230000000Z")),
        ("utc_hour24", utctime("200101240000Z")),
        ("gen_9999", gentime("99991231235959Z")),
        ("gen_1000", gentime("10000615123045Z")),
        ("gen_0999", gentime("09990615123045Z")),
    ]
    for label, t in times:
        out.append((f"time_{label}", make_cert(not_before=t)))
        out.append((f"time_after_{label}", make_cert(not_after=t)))
    # names
    names = [
        ("empty_rdn", seq(set_())),
        ("dup_attr", name_der([[("2.5.4.3", 0x0C, b"a"), ("2.5.4.3", 0x0C, b"a")]])),
        ("dup_attr_types", name_der([[("2.5.4.3", 0x0C, b"a"), ("2.5.4.3", 0x13, b"a")]])),
        ("unsorted_set", seq(set_(seq(oid("2.5.4.3"), tlv(0x0C, b"z")), seq(oid("2.5.4.10"), tlv(0x0C, b"a")), sort=False))),
        ("sorted_set_rev", seq(set_(seq(oid("2.5.4.10"), tlv(0x0C, b"a")), seq(oid("2.5.4.3"), tlv(0x0C, b"z")), sort=False))),
        ("bad_utf8", name_der([[("2.5.4.3", 0x0C, b"\xff\xfe")]])),
        ("latin1_t61", name_der([[("2.5.4.3", 0x14, b"caf\xe9")]])),
        ("utf8_t61", name_der([[("2.5.4.3", 0x14, "café".encode())]])),
        ("printable_bad", name_der([[("2.5.4.3", 0x13, b"a@b")]])),
        ("printable_star", name_der([[("2.5.4.3", 0x13, b"*.x")]])),
        ("ia5_highbit", name_der([[("2.5.4.3", 0x16, b"\xc3\xa9")]])),
        ("ia5_bad_utf8", name_der([[("2.5.4.3", 0x16, b"\xe9")]])),
        ("bmp_odd", name_der([[("2.5.4.3", 0x1E, b"\x00a\x00")]])),
        ("bmp_lone_surrogate", name_der([[("2.5.4.3", 0x1E, b"\xd8\x00")]])),
        ("universal_surrogate", name_der([[("2.5.4.3", 0x1C, b"\x00\x00\xd8\x00")]])),
        ("universal_ok", name_der([[("2.5.4.3", 0x1C, b"\x00\x01\xf6\x00")]])),
        ("int_value", name_der([[("2.5.4.3", 0x02, b"\x01")]])),
        ("null_value", seq(set_(seq(oid("2.5.4.3"), NULL)))),
        ("bitstring_wrong_oid", name_der([[("2.5.4.3", 0x03, b"\x00\x01")]])),
        ("bitstring_uid", name_der([[("2.5.4.45", 0x03, b"\x00\xab")]])),
        ("constructed_utf8", seq(set_(seq(oid("2.5.4.3"), tlv(0x2C, tlv(0x0C, b"x")))))),
        ("context_tag_value", name_der([[("2.5.4.3", 0x80, b"x")]])),
        ("long_tag_value", seq(set_(seq(oid("2.5.4.3"), b"\x1f\x81\x00\x01x")))),
        ("empty_value", name_der([[("2.5.4.3", 0x0C, b"")]])),
        ("cn_then_empty_cn", name_der([[("2.5.4.3", 0x0C, b"x")], [("2.5.4.3", 0x0C, b"")]])),
        ("cn_65", name_der([[("2.5.4.3", 0x0C, b"x" * 65)]])),
        ("country_3", name_der([[("2.5.4.6", 0x13, b"USA")]])),
        ("nul_and_controls", name_der([[("2.5.4.3", 0x0C, b"a\x00b\x01\x7f\n")]])),
        ("utctime_value", name_der([[("2.5.4.3", 0x17, b"not a time")]])),
        ("generalized_value", name_der([[("2.5.4.3", 0x18, b"x")]])),
        ("octet_value_bin", name_der([[("2.5.4.3", 0x04, b"\x80")]])),
        ("numeric_letters", name_der([[("2.5.4.3", 0x12, b"abc")]])),
        ("visible_utf8", name_der([[("2.5.4.3", 0x1A, "é".encode())]])),
        ("long_oid", name_der([[("1.2." + ".".join(["999999999"] * 15), 0x0C, b"x")]])),
        ("big_arc_oid", name_der([[("2.999999999999999999999999999999999999999", 0x0C, b"x")]])),
        ("multi_rdn_escapes", name_der([[("2.5.4.3", 0x0C, b"a+b"), ("2.5.4.10", 0x0C, b"#c")], [("2.5.4.6", 0x13, b"US")]])),
    ]
    for label, nm in names:
        out.append((f"subject_{label}", make_cert(subject=nm)))
        out.append((f"issuer_{label}", make_cert(issuer=nm)))
    # algorithms
    algs = [
        ("rsa_sha256_noparams", seq(oid("1.2.840.113549.1.1.11"))),
        ("rsa_sha256_null", SHA256_RSA),
        ("ecdsa_null", seq(oid("1.2.840.10045.4.3.2"), NULL)),
        ("ed25519", seq(oid("1.3.101.112"))),
        ("ed25519_null", seq(oid("1.3.101.112"), NULL)),
        ("unknown", seq(oid("1.2.3.4"), integer(5))),
        ("unknown_noparams", seq(oid("1.2.3.4"))),
        ("pss_empty", seq(oid("1.2.840.113549.1.1.10"), seq())),
        ("pss_sha256", seq(oid("1.2.840.113549.1.1.10"), seq(explicit(0, seq(oid("2.16.840.1.101.3.4.2.1"), NULL)), explicit(1, seq(oid("1.2.840.113549.1.1.8"), seq(oid("2.16.840.1.101.3.4.2.1"), NULL))), explicit(2, integer(32))))),
        ("pss_default_salt", seq(oid("1.2.840.113549.1.1.10"), seq(explicit(2, integer(20))))),
        ("pss_trailer_1", seq(oid("1.2.840.113549.1.1.10"), seq(explicit(3, integer(1))))),
        ("dsa_sha256", seq(oid("2.16.840.1.101.3.4.3.2"))),
        ("two_params", seq(oid("1.2.840.10045.4.3.2"), NULL, NULL)),
    ]
    for label, a in algs:
        out.append((f"alg_{label}", make_cert(sig_alg=a)))
    def nested_pss(depth):
        a = seq(oid("2.16.840.1.101.3.4.2.1"), NULL)
        for _ in range(depth):
            a = seq(oid("1.2.840.113549.1.1.10"), seq(explicit(0, a)))
        return a

    for depth in (1, 5, 30, 45, 60, 200):
        out.append((f"alg_pss_nested_{depth}", make_cert(sig_alg=nested_pss(depth))))
    out.append(("alg_mismatch", make_cert(sig_alg=ECDSA_SHA256, outer_alg=SHA256_RSA)))
    # SPKI
    out.append(("spki_garbage_key", make_cert(spki=seq(seq(oid("1.2.840.10045.2.1"), oid("1.2.840.10045.3.1.7")), bits(b"\x04junk")))))
    out.append(("spki_unknown", make_cert(spki=seq(seq(oid("1.2.3.4.5")), bits(b"key")))))
    out.append(("spki_ec_noparams", make_cert(spki=seq(seq(oid("1.2.840.10045.2.1")), bits(b"\x04")))))
    out.append(("spki_rsa_noparams", make_cert(spki=seq(seq(oid("1.2.840.113549.1.1.1")), bits(b"\x00")))))
    out.append(("spki_bits_padding", make_cert(spki=seq(seq(oid("1.3.101.112")), bits(b"\x01", 1)))))
    out.append(("spki_bits_padding_ok", make_cert(spki=seq(seq(oid("1.3.101.112")), bits(b"\x02", 1)))))
    # unique ids
    out.append(("issuer_uid", make_cert(extra_tbs=tlv(0x81, b"\x00\x01"))))
    out.append(("subject_uid", make_cert(extra_tbs=tlv(0x82, b"\x00\x01"))))
    out.append(("both_uid", make_cert(extra_tbs=tlv(0x81, b"\x00\x01") + tlv(0x82, b"\x00\x02"))))
    # extension encodings
    out.append(("exts_empty_seq", make_cert(raw_exts=seq())))
    out.append(("exts_dup", make_cert(exts=[("2.5.29.19", None, seq()), ("2.5.29.19", None, seq())])))
    out.append(("exts_crit_false_encoded", make_cert(exts=[("2.5.29.19", False, seq())])))
    out.append(("exts_crit_true", make_cert(exts=[("2.5.29.19", True, seq())])))
    out.append(("exts_unknown_bad_der", make_cert(exts=[("1.2.3.4", None, b"\xff\xff")])))
    out.append(("exts_unknown_empty", make_cert(exts=[("1.2.3.4", None, b"")])))
    out.append(("exts_v1_with_exts", make_cert(version=None, exts=[("2.5.29.19", None, seq())])))
    out.append(("exts_sct_oid_unparsed", make_cert(exts=[("1.3.6.1.4.1.11129.2.4.5", None, octets(b"\x00\x00"))])))
    gn_dns = tlv(0x82, b"a.example")
    ext_values = {
        "2.5.29.17": [
            ("empty", seq()),
            ("dns_utf8", seq(tlv(0x82, "ü.example".encode()))),
            ("dns_bad_utf8", seq(tlv(0x82, b"\xff"))),
            ("dns_empty", seq(tlv(0x82, b""))),
            ("x400", seq(tlv(0xA3, b""))),
            ("edi", seq(tlv(0xA5, b""))),
            ("ip_5", seq(tlv(0x87, b"\x01\x02\x03\x04\x05"))),
            ("ip_0", seq(tlv(0x87, b""))),
            ("ip_8_badmask", seq(tlv(0x87, b"\x0a\x00\x00\x00\xff\x00\xff\x00"))),
            ("ip_8_hostbits", seq(tlv(0x87, b"\x0a\x00\x00\x01\xff\x00\x00\x00"))),
            ("ip_8_ok", seq(tlv(0x87, b"\x0a\x00\x00\x00\xff\xff\xff\xff"))),
            ("ip_8_zero", seq(tlv(0x87, b"\x00\x00\x00\x00\x00\x00\x00\x00"))),
            ("ip_32_ok", seq(tlv(0x87, bytes.fromhex("20010db8" + "00" * 12 + "ffffffff" + "00" * 12)))),
            ("ip_32_hostbits", seq(tlv(0x87, bytes.fromhex("20010db8" + "00" * 11 + "01" + "ffffffff" + "00" * 12)))),
            ("ip_16_mapped", seq(tlv(0x87, bytes.fromhex("00000000000000000000ffff7f000001")))),
            ("ip_16_zero", seq(tlv(0x87, bytes(16)))),
            ("ip_16_v4compat", seq(tlv(0x87, bytes.fromhex("0000000000000000000000000a000001")))),
            ("dirname_bad", seq(tlv(0xA4, seq(set_())))),
            ("dirname_implicit", seq(tlv(0xA4, b""))),
            ("othername_noexplicit", seq(tlv(0xA0, oid("1.2.3") + NULL))),
            ("registered", seq(tlv(0x88, oid("1.2.3.4")[2:]))),
            ("uri_bad_utf8", seq(tlv(0x86, b"\xc3"))),
            ("trailing", seq(gn_dns) + b"\x00"),
            ("not_seq", gn_dns),
            ("many", seq(*[tlv(0x82, f"h{i}.example".encode()) for i in range(30)])),
        ],
        "2.5.29.18": [("empty", seq()), ("x400", seq(tlv(0xA3, b"")))],
        "2.5.29.14": [("empty", octets(b"")), ("notoctet", integer(1))],
        "2.5.29.15": [
            ("empty_bits", bits(b"")),
            ("one_bit", bits(b"\x80", 7)),
            ("decipher_only", bits(b"\x00\x80", 7)),
            ("encipher_no_ka", bits(b"\x01")),
            ("ka_decipher", bits(b"\x08\x80", 7)),
            ("long", bits(b"\xff\xff\xff")),
            ("bad_padding", bits(b"\x81", 1)),
        ],
        "2.5.29.19": [
            ("ca_false_len", seq(integer(1))),
            ("ca_true_len0", seq(boolean(True), integer(0))),
            ("len_neg", seq(boolean(True), integer(-1))),
            ("len_huge", seq(boolean(True), integer(1 << 70))),
            ("ca_false_encoded", seq(boolean(False))),
        ],
        "2.5.29.37": [("empty", seq()), ("one", seq(oid("1.3.6.1.5.5.7.3.3")))],
        "1.3.6.1.5.5.7.1.24": [("empty", seq()), ("unknown", seq(integer(6))), ("ok", seq(integer(5), integer(5)))],
        "2.5.29.36": [("empty", seq()), ("big", seq(tlv(0x80, b"\x7f" + b"\xff" * 7)))],
        "2.5.29.54": [("neg", integer(-1)), ("big", integer(1 << 80))],
        "1.3.6.1.5.5.7.48.1.5": [("notnull", integer(0))],
        "1.3.6.1.4.1.11129.2.4.3": [("notnull", octets(b""))],
        "2.5.29.35": [
            ("issuer_only", seq(tlv(0xA1, gn_dns))),
            ("serial_only", seq(tlv(0x82, b"\x01"))),
            ("both", seq(tlv(0xA1, gn_dns), tlv(0x82, b"\xff"))),
            ("empty", seq()),
        ],
        "2.5.29.31": [
            ("empty_dp", seq(seq())),
            ("empty_fullname", seq(seq(explicit(0, tlv(0xA0, b""))))),
            ("reasons_only", seq(seq(tlv(0x81, b"\x07\x80")))),
            ("crl_issuer_empty", seq(seq(tlv(0xA2, b"")))),
            ("rel_empty", seq(seq(explicit(0, tlv(0xA1, b""))))),
            ("reasons_bit0", seq(seq(explicit(0, tlv(0xA0, gn_dns)), tlv(0x81, b"\x07\x80")))),
            ("reasons_many", seq(seq(explicit(0, tlv(0xA0, gn_dns)), tlv(0x81, b"\x07\x7f\x80")))),
            ("reasons_empty_bits", seq(seq(explicit(0, tlv(0xA0, gn_dns)), tlv(0x81, b"\x00")))),
            ("both_names", seq(seq(explicit(0, tlv(0xA0, gn_dns))))),
        ],
        "2.5.29.32": [
            ("cps_wrong_oid", seq(seq(oid("1.2.3"), seq(seq(oid("1.3.6.1.5.5.7.2.2"), tlv(0x16, b"http://x")))))),
            ("notice_wrong_oid", seq(seq(oid("1.2.3"), seq(seq(oid("1.3.6.1.5.5.7.2.1"), seq()))))),
            ("bmp_text", seq(seq(oid("1.2.3"), seq(seq(oid("1.3.6.1.5.5.7.2.2"), seq(tlv(0x1E, "bmp é".encode("utf-16-be")))))))),
            ("visible_utf8", seq(seq(oid("1.2.3"), seq(seq(oid("1.3.6.1.5.5.7.2.2"), seq(tlv(0x1A, "vis é".encode()))))))),
            ("ia5_text", seq(seq(oid("1.2.3"), seq(seq(oid("1.3.6.1.5.5.7.2.2"), seq(tlv(0x16, b"ia5 'q'"))))))),
            ("notice_ref", seq(seq(oid("1.2.3"), seq(seq(oid("1.3.6.1.5.5.7.2.2"), seq(seq(tlv(0x0C, b'Org "x"'), seq(integer(0), integer(99))))))))),
            ("cps_bad_ia5", seq(seq(oid("1.2.3"), seq(seq(oid("1.3.6.1.5.5.7.2.1"), tlv(0x16, b"\xe9")))))),
            ("empty_quals", seq(seq(oid("1.2.3"), seq()))),
            ("empty", seq()),
        ],
        "2.5.29.30": [
            ("empty", seq()),
            ("permitted_empty", seq(tlv(0xA0, b""))),
            ("ip_address", seq(tlv(0xA0, seq(tlv(0x87, b"\x01\x02\x03\x04"))))),
            ("dns_star", seq(tlv(0xA0, seq(tlv(0x82, b"*.x"))))),
            ("min_max", seq(tlv(0xA1, seq(gn_dns, tlv(0x80, b"\x01"), tlv(0x81, b"\x05"))))),
            ("min_zero_encoded", seq(tlv(0xA1, seq(gn_dns, tlv(0x80, b"\x00"))))),
        ],
        "1.3.6.1.4.1.311.21.7": [("noversions", seq(oid("1.2.3"))), ("bad", seq())],
        "2.5.29.16": [
            ("empty", seq()),
            ("reversed", seq(tlv(0x80, b"20220101000000Z"), tlv(0x81, b"20210101000000Z"))),
            ("year0", seq(tlv(0x80, b"00000101000000Z"))),
            ("after_only", seq(tlv(0x81, b"20210101000000Z"))),
        ],
        "1.3.36.8.3.3": [
            ("empty", seq(seq())),
            ("authority_x400", seq(tlv(0xA3, b""), seq())),
            ("plain", seq(seq(seq(seq(seq(tlv(0x0C, b"item"))))))),
        ],
    }
    for o, variants in ext_values.items():
        for label, v in variants:
            out.append((f"extval_{o}_{label}", make_cert(exts=[(o, None, v)])))
    # SCTs

    def sct(version=0, hash_alg=4, sig_alg=3, ts=1700000000123, ext=b"", sig=b"\x30\x00", extra=b""):
        body = bytes([version]) + bytes(range(32)) + ts.to_bytes(8, "big") + len(ext).to_bytes(2, "big") + ext
        body += bytes([hash_alg, sig_alg]) + len(sig).to_bytes(2, "big") + sig + extra
        return len(body).to_bytes(2, "big") + body

    def sct_list(*scts, extra=b""):
        inner = b"".join(scts)
        return octets(len(inner).to_bytes(2, "big") + inner + extra)

    sct_cases = [
        ("one", sct_list(sct())),
        ("two", sct_list(sct(hash_alg=1, sig_alg=1, ts=0, ext=b"\x01\x02"), sct(hash_alg=6, sig_alg=2, ts=253402300799999))),
        ("ts_too_big", sct_list(sct(ts=253402300800000))),
        ("ts_max", sct_list(sct(ts=(1 << 64) - 1))),
        ("bad_version", sct_list(sct(version=1))),
        ("bad_hash", sct_list(sct(hash_alg=0))),
        ("bad_sig", sct_list(sct(sig_alg=0))),
        ("extra_inner", sct_list(sct(extra=b"\x00"))),
        ("extra_outer", sct_list(sct(), extra=b"\x00")),
        ("empty_list", sct_list()),
        ("short", octets(b"\x00")),
        ("not_octets", seq()),
    ]
    for label, v in sct_cases:
        out.append((f"sct_{label}", make_cert(exts=[("1.3.6.1.4.1.11129.2.4.2", None, v)])))
    # framing
    base = make_cert()
    out.append(("trailing_zero", base + b"\x00"))
    out.append(("trailing_garbage", base + b"garbage"))
    hdr = 2 + (base[1] & 0x7F if base[1] & 0x80 else 0)
    out.append(("ber_long_length", b"\x30\x83" + len(base[hdr:]).to_bytes(3, "big") + base[hdr:]))
    out.append(("indefinite", b"\x30\x80" + base[hdr:] + b"\x00\x00"))
    out.append(("big_cert", make_cert(exts=[("2.5.29.17", None, seq(*[tlv(0x82, f"host{i}.example.com".encode()) for i in range(600)]))])))
    return out


# ---- inputs that are not certificates -------------------------------------------------------


def non_certs():
    out = []
    out.append(("empty", b""))
    out.append(("text", b"hello world\n"))
    out.append(("ec_key_pem", KEY_EC.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())))
    out.append(("ec_key_der", KEY_EC.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())))
    out.append(("pub_pem", KEY_EC.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)))
    out.append(("pub_der", SPKI_EC))
    csr = x509.CertificateSigningRequestBuilder().subject_name(simple_name("csr")).sign(KEY_EC, hashes.SHA256())
    out.append(("csr_pem", csr.public_bytes(serialization.Encoding.PEM)))
    out.append(("csr_der", csr.public_bytes(serialization.Encoding.DER)))
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(simple_name("crl"))
        .last_update(datetime.datetime(2020, 1, 1))
        .next_update(datetime.datetime(2021, 1, 1))
        .sign(KEY_EC, hashes.SHA256())
    )
    out.append(("crl_pem", crl.public_bytes(serialization.Encoding.PEM)))
    out.append(("crl_der", crl.public_bytes(serialization.Encoding.DER)))
    rng = random.Random(7)
    for i in range(40):
        out.append((f"random_bytes_{i}", bytes(rng.randrange(256) for _ in range(rng.randrange(1, 64)))))
    return out


def random_der(rng, depth=0):
    """A random BER-ish element, for comparing with pyasn1's decoder."""
    kind = rng.random()
    if depth > 4 or kind < 0.45:
        tag = rng.choice([1, 2, 3, 4, 5, 6, 7, 9, 10, 12, 13, 18, 19, 20, 22, 23, 24, 26, 28, 30, 0, 8, 14, 31, 0x80, 0x81, 0x41, 0xC2, 0x22, 0x24, 0x23, 0x2C])
        content_kind = rng.random()
        if tag == 1:
            content = rng.choice([b"\x00", b"\xff", b"\x01", b"", b"\x00\x00"])
        elif tag == 5:
            content = rng.choice([b"", b"\x00"])
        elif tag == 6 or tag == 13:
            content = rng.choice([b"\x2a\x03", b"\x80\x01", b"", b"\x81", b"\x2a\x86\x48", b"\x88\x80\x01", b"\xff" * 21 + b"\x01", b"\xff" * 20 + b"\x01"])
        elif tag == 9:
            content = rng.choice([b"", b"\x40", b"\x41", b"\x01" + b"12", b"\x02" + b"1.5", b"\x03" + b"1e5", b"\x03nan", b"\x02inf", b"\x01 1_0 ", b"\x80\x01\x05", b"\x83\x00\x05", b"\xb0\x01\x01", b"\x80", b"\x00x", b"\x01" + b"1" * 4301, b"\x01" + b"1" * 4300])
        elif tag in (12, 18, 19, 22, 26, 20, 28, 30, 23, 24, 7):
            content = rng.choice([b"abc", b"\xc3\xa9", b"\xff", b"\x00\x00\x00a", b"\x00a", b"\xd8\x00\xdc\x00", b"\xd8\x00", b"", b"\x00\x11\x00\x00"])
        elif tag == 3:
            content = rng.choice([b"", b"\x00", b"\x07\x80", b"\x08\x00", b"\x00abc", b"\x03"])
        elif tag == 0x2C:
            content = b"".join(tlv(rng.choice([0x0C, 0x0C, 0x13, 0x2C]), rng.choice([b"a", b"\xc3", b"\xa9", b""])) for _ in range(rng.randrange(0, 3)))
        else:
            content = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 6))) if content_kind < 0.5 else b""
        return tlv(tag, content)
    if kind < 0.8:
        tag = rng.choice([0x30, 0x31, 0x30, 0x10])
        return tlv(tag, b"".join(random_der(rng, depth + 1) for _ in range(rng.randrange(0, 4))))
    tag = rng.choice([0xA0, 0xA1, 0x61, 0xE3, 0xBF])
    if tag == 0xBF:
        return b"\xbf\x81\x00" + tlv(0x00, random_der(rng, depth + 1))[1:]
    n = rng.randrange(0, 3)
    return tlv(tag, b"".join(random_der(rng, depth + 1) for _ in range(n)))


def ber_cases():
    out = []
    rng = random.Random(11 + SEED)
    for i in range(600 * SCALE):
        d = random_der(rng)
        if rng.random() < 0.2:
            d += bytes(rng.randrange(256) for _ in range(3))
        out.append((f"der_random_{i}", d))
    fixed = [
        b"\x30\x00", b"\x30\x02\x30\x00", b"\xa0\x02\x30\x00", b"\x30\x04\xa0\x02\x30\x00", b"\x1f\x02\x01\x05",
        b"\x1f\x82\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x80\x00\x00",
        b"\x1f" + b"\x80" * 19 + b"\x02\x01\x00", b"\x1f" + b"\x80" * 20 + b"\x02\x01\x00",
        b"\x30\x81\x03\x02\x01\x00", b"\x30\x88" + (3).to_bytes(8, "big") + b"\x02\x01\x00",
        b"\x30\x89" + (3).to_bytes(9, "big") + b"\x02\x01\x00", b"\x30\x84\xff\xff\xff\xff",
        b"\x21\x01\xff", b"\x2c\x05\x0c\x01\xc3\x0c\x00", b"\x2c\x06\x0c\x02\xc3\xa9\x0c\x00", b"\x2c\x03\x13\x01a",
        b"\x2c\x04\x2c\x02\x0c\x00", b"\x2c\x04\xa0\x02\x0c\x00", b"\x3e\x06\x1e\x01\x00\x1e\x01\x00",
        b"\x30\x03\x02\x01", b"\x02\x01\x01\x02", b"\xa0\x05\x02\x01\x00\x02\x00",
    ]
    for i, f in enumerate(fixed):
        out.append((f"der_fixed_{i}", f))

    def nest(n, inner=b"\x02\x01\x00", tag=0x30):
        d = inner
        for _ in range(n):
            d = tlv(tag, d)
        return d

    for n in (98, 99, 100, 101, 102):
        out.append((f"der_nest_seq_{n}", nest(n)))
        out.append((f"der_nest_explicit_{n}", nest(n, tag=0xA0)))
        out.append((f"der_nest_utf8_{n}", nest(n, inner=b"\x0c\x00", tag=0x2C)))
    return out


# ---- PEM forms --------------------------------------------------------------------------------


def pem_cases(der_good, der_other):
    out = []
    p = pem(der_good)
    out.append(("pem", p))
    out.append(("pem_crlf", p.replace(b"\n", b"\r\n")))
    out.append(("pem_leading_text", b"Subject: x\nIssuer: y\n\n" + p))
    out.append(("pem_leading_binary", b"\x00\xff\x30\x00 junk" + p))
    out.append(("pem_x509_label", pem(der_good, "X509 CERTIFICATE")))
    out.append(("pem_trusted_label", pem(der_good, "TRUSTED CERTIFICATE")))
    out.append(("pem_lowercase_label", pem(der_good, "certificate")))
    out.append(("pem_chain", p + pem(der_other)))
    out.append(("pem_key_then_cert", KEY_EC.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()) + p))
    out.append(("pem_bad_block_then_cert", b"-----BEGIN FOO-----\n!!!!\n-----END FOO-----\n" + p))
    out.append(("pem_cert_then_bad_block", p + b"-----BEGIN FOO-----\n!!!!\n-----END FOO-----\n"))
    out.append(("pem_no_newlines", p.replace(b"\n", b"")))
    out.append(("pem_spaces", p.replace(b"\n", b"\n  ")))
    out.append(("pem_headers", p.replace(b"-----\n", b"-----\nProc-Type: 4,ENCRYPTED\nX: y\n\n", 1)))
    out.append(("pem_mismatched_end", p.replace(b"END CERTIFICATE", b"END FOO")))
    out.append(("pem_missing_end", p.split(b"-----END")[0]))
    b64 = base64.b64encode(der_good)
    out.append(("pem_no_padding", b"-----BEGIN CERTIFICATE-----\n" + b64.rstrip(b"=") + b"\n-----END CERTIFICATE-----\n"))
    out.append(("pem_extra_padding", b"-----BEGIN CERTIFICATE-----\n" + b64 + b"==\n-----END CERTIFICATE-----\n"))
    out.append(("pem_urlsafe", b"-----BEGIN CERTIFICATE-----\n" + base64.urlsafe_b64encode(der_good) + b"\n-----END CERTIFICATE-----\n"))
    out.append(("pem_tab_inside", b"-----BEGIN CERTIFICATE-----\n" + b64[:10] + b"\t" + b64[10:] + b"\n-----END CERTIFICATE-----\n"))
    out.append(("pem_nbsp_inside", b"-----BEGIN CERTIFICATE-----\n" + b64[:10] + " ".encode() + b64[10:] + b"\n-----END CERTIFICATE-----\n"))
    out.append(("pem_trailing_garbage", p + b"trailing garbage\x00\xff"))
    out.append(("pem_six_dashes", b"-" + p))
    out.append(("pem_der_inside_bad", pem(der_good + b"\x00")))
    out.append(("pem_non_cert", pem(SPKI_EC, "PUBLIC KEY")))
    out.append(("pem_after_8192", b"x" * 9000 + p))
    out.append(("pem_after_8192_der_head", der_other + b"x" * 9000 + p))
    out.append(("pem_straddle_8192", b"y" * (8192 - 20) + p))
    out.append(("der_then_pem", der_other + p))
    out.append(("pem_utf8_bad_header", b"-----BEGIN CERTIFICATE-----\n\xff: x\n\n" + b64 + b"\n-----END CERTIFICATE-----\n"))
    out.append(("pem_v4", pem(make_cert(version=integer(3)))))
    return out


def mutations(seeds, count, rng, pem_mode=False):
    out = []
    for i in range(count):
        name, data = seeds[rng.randrange(len(seeds))]
        d = bytearray(data)
        for _ in range(rng.choice([1, 1, 1, 2, 3])):
            op = rng.random()
            if not d:
                break
            pos = rng.randrange(len(d))
            if op < 0.35:
                if pem_mode:
                    d[pos] = ord(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n -\r\t"))
                else:
                    d[pos] = rng.randrange(256)
            elif op < 0.5:
                d[pos] ^= 1 << rng.randrange(8)
            elif op < 0.65:
                del d[pos : pos + rng.randrange(1, 4)]
            elif op < 0.8:
                d[pos:pos] = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 3)))
            elif op < 0.9:
                d = d[: rng.randrange(len(d))]
            else:
                # adjust a length octet
                d[pos] = (d[pos] + rng.choice([-1, 1])) % 256
        out.append((f"mut{'_pem' if pem_mode else ''}_{i}_{name}", bytes(d)))
    return out


SCALE = int(sys.argv[2]) if len(sys.argv) > 2 else 1
SEED = int(sys.argv[3]) if len(sys.argv) > 3 else 0


def main():
    built = built_certs()
    for name, der in built:
        add(name, der)
    hand = crafted()
    for name, der in hand:
        add(name, der)
    for name, d in non_certs():
        add(name, d)
    for name, d in ber_cases():
        add(name, d)
    good = dict(built)["ec_basic"]
    other = dict(built)["ca_signed"]
    for name, d in pem_cases(good, other):
        add(name, d)
    for name, der in built[:12]:
        add(f"pemof_{name}", pem(der))
    rng = random.Random(1234 + SEED)
    seeds = [b for b in built if len(b[1]) < 1500]
    seeds += [h for h in hand if len(h[1]) < 1500 and h[0].startswith(("extval", "sct", "subject"))][: 60 * SCALE]
    for name, d in mutations(seeds, 2500 * SCALE, rng):
        add(name, d)
    pem_seeds = [(n, pem(d)) for n, d in built[:8]]
    for name, d in mutations(pem_seeds, 700 * SCALE, rng, pem_mode=True):
        add(name, d)
    json.dump(CASES, open(sys.argv[1], "w"))
    print(len(CASES), "cases")


main()
