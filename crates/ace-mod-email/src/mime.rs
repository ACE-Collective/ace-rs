//! A message's MIME structure as Python's `email.message.Message` presents it to ace3: a tree of
//! messages and parts, walked depth first, where a `message/rfc822` part holds the message
//! inside it.
//!
//! mail-parser finds the structure and undoes the transfer encodings. Each node's headers are
//! read again from its raw bytes by `py::parse_headers`, so values and lookups behave as
//! compat32's do.

use std::borrow::Cow;

use mail_parser::{MessagePart, MessageRef, PartKind};

use crate::py::{self, Headers};

/// One message or MIME part.
pub struct Node<'m> {
    pub headers: Headers,
    /// `get_content_type()`.
    pub content_type: String,
    /// The part as mail-parser read it, for its body.
    pub part: MessagePart<'m>,
    pub children: Vec<Node<'m>>,
    /// Whether this node is a whole message (the root, or the payload of a `message/*` part)
    /// rather than a part.
    pub is_message: bool,
}

impl<'m> Node<'m> {
    /// The message and everything inside it.
    pub fn message(message: MessageRef<'m>) -> Node<'m> {
        let mut node = Node::part(message.root_part(), "text/plain");
        node.is_message = true;
        node
    }

    fn part(part: MessagePart<'m>, default_type: &str) -> Node<'m> {
        let headers = py::parse_headers(part.raw());
        let content_type = headers.content_type(default_type);
        let children = match part.kind() {
            PartKind::Multipart => {
                // inside multipart/digest a part without a Content-Type is a message
                let child_default = if content_type == "multipart/digest" {
                    "message/rfc822"
                } else {
                    "text/plain"
                };
                part.children()
                    .map(|child| Node::part(child, child_default))
                    .collect()
            }
            PartKind::Message(inner) => vec![Node::message(inner)],
            _ => Vec::new(),
        };
        Node {
            headers,
            content_type,
            part,
            children,
            is_message: false,
        }
    }

    /// `msg.walk()`: this node, then every node under it, depth first.
    pub fn walk(&self) -> Vec<&Node<'m>> {
        let mut nodes = vec![self];
        for child in &self.children {
            nodes.extend(child.walk());
        }
        nodes
    }

    /// The body as written, before transfer decoding.
    pub fn raw_body(&self) -> &'m [u8] {
        let raw = self.part.raw();
        raw.get(self.headers.body_offset..).unwrap_or_default()
    }

    /// `get_payload(decode=True)` for a part that isn't multipart: the body with its transfer
    /// encoding undone.
    pub fn decoded_body(&self) -> Cow<'m, [u8]> {
        self.part.decoded()
    }

    /// The `Content-Transfer-Encoding`, as ace3 reads it: `str(...).strip().lower()`.
    pub fn transfer_encoding(&self) -> String {
        self.headers
            .get("content-transfer-encoding")
            .map(|v| py::py_strip(&v.to_str()).to_lowercase())
            .unwrap_or_default()
    }

    /// `get_payload()` of a part that isn't multipart: the body as text. Bytes outside ASCII are
    /// decoded with the part's charset (ASCII by default), replacing what doesn't decode.
    pub fn payload_text(&self) -> String {
        let body = self.raw_body();
        if body.is_ascii() {
            return String::from_utf8_lossy(body).into_owned();
        }
        let charset = self
            .headers
            .content_charset()
            .unwrap_or_else(|| "ascii".to_owned());
        py::decode_charset_replace(body, &charset)
            .unwrap_or_else(|| py::decode_charset_replace(body, "ascii").unwrap_or_default())
    }
}
