//! The ASN.1 structures cryptography 50.0.2 parses a certificate with, copied from its
//! `cryptography-x509` crate (`src/rust/cryptography-x509/src` in the sdist): `certificate.rs`,
//! `common.rs`, `name.rs`, `extensions.rs` and `oid.rs`, with their tests left out and
//! `crl::ReasonFlags` moved into `extensions.rs`. That crate is not published, so it is vendored
//! here. It parses with the same `asn1` crate at the same version (0.24.1), so a certificate is
//! accepted or refused by the same rules: strict DER, DEFAULT values that must not be encoded,
//! SET OF ordering, the parameters each algorithm OID allows, and so on.
//!
//! cryptography's code is dual licensed under the Apache License 2.0 and the BSD license.

#![allow(dead_code, clippy::all)]

pub mod certificate;
pub mod common;
pub mod extensions;
pub mod name;
pub mod oid;
