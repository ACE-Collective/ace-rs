//! `email.utils.parseaddr` and `getaddresses`, with their default `strict=True`, and the
//! `email._parseaddr` parser they run on (Python 3.14's `email/utils.py` and `email/_parseaddr.py`).

/// The address parser of `email._parseaddr.AddrlistClass`.
struct AddrList {
    field: Vec<char>,
    pos: usize,
    commentlist: Vec<String>,
}

const SPECIALS: &str = "()<>@,:;.\"[]";
const LWS: &str = " \t";
const CR: &str = "\r\n";

fn is_atomend(c: char) -> bool {
    SPECIALS.contains(c) || LWS.contains(c) || CR.contains(c)
}

fn is_phraseend(c: char) -> bool {
    c != '.' && is_atomend(c)
}

impl AddrList {
    fn new(field: &str) -> Self {
        AddrList {
            field: field.chars().collect(),
            pos: 0,
            commentlist: Vec::new(),
        }
    }

    fn at(&self) -> Option<char> {
        self.field.get(self.pos).copied()
    }

    fn gotonext(&mut self) -> String {
        let mut ws = String::new();
        while let Some(c) = self.at() {
            if " \t\n\r".contains(c) {
                if c != '\n' && c != '\r' {
                    ws.push(c);
                }
                self.pos += 1;
            } else if c == '(' {
                let comment = self.getcomment();
                self.commentlist.push(comment);
            } else {
                break;
            }
        }
        ws
    }

    fn getaddrlist(&mut self) -> Vec<(String, String)> {
        let mut result = Vec::new();
        while self.pos < self.field.len() {
            let ad = self.getaddress();
            if ad.is_empty() {
                result.push((String::new(), String::new()));
            } else {
                result.extend(ad);
            }
        }
        result
    }

    fn getaddress(&mut self) -> Vec<(String, String)> {
        self.commentlist.clear();
        self.gotonext();

        let oldpos = self.pos;
        let oldcl = self.commentlist.clone();
        let plist = self.getphraselist();

        self.gotonext();
        let mut returnlist = Vec::new();

        match self.at() {
            None => {
                if let Some(first) = plist.first() {
                    returnlist = vec![(self.commentlist.join(" "), first.clone())];
                }
            }
            Some(c) if c == '.' || c == '@' => {
                self.pos = oldpos;
                self.commentlist = oldcl;
                let addrspec = self.getaddrspec();
                returnlist = vec![(self.commentlist.join(" "), addrspec)];
            }
            Some(':') => {
                self.pos += 1;
                while self.pos < self.field.len() {
                    self.gotonext();
                    if self.at() == Some(';') {
                        self.pos += 1;
                        break;
                    }
                    returnlist.extend(self.getaddress());
                }
            }
            Some('<') => {
                let routeaddr = self.getrouteaddr();
                let name = if self.commentlist.is_empty() {
                    plist.join(" ")
                } else {
                    format!("{} ({})", plist.join(" "), self.commentlist.join(" "))
                };
                returnlist = vec![(name, routeaddr)];
            }
            Some(c) => {
                if let Some(first) = plist.first() {
                    returnlist = vec![(self.commentlist.join(" "), first.clone())];
                } else if SPECIALS.contains(c) {
                    self.pos += 1;
                }
            }
        }

        self.gotonext();
        if self.at() == Some(',') {
            self.pos += 1;
        }
        returnlist
    }

    fn getrouteaddr(&mut self) -> String {
        if self.at() != Some('<') {
            return String::new();
        }
        let mut expectroute = false;
        self.pos += 1;
        self.gotonext();
        let mut adlist = String::new();
        while let Some(c) = self.at() {
            if expectroute {
                self.getdomain();
                expectroute = false;
            } else if c == '>' {
                self.pos += 1;
                break;
            } else if c == '@' {
                self.pos += 1;
                expectroute = true;
            } else if c == ':' {
                self.pos += 1;
            } else {
                adlist = self.getaddrspec();
                self.pos += 1;
                break;
            }
            self.gotonext();
        }
        adlist
    }

    fn getaddrspec(&mut self) -> String {
        let mut aslist: Vec<String> = Vec::new();
        self.gotonext();
        while let Some(c) = self.at() {
            let mut preserve_ws = true;
            if c == '.' {
                if aslist.last().is_some_and(|w| w.trim().is_empty()) {
                    aslist.pop();
                }
                aslist.push(".".to_owned());
                self.pos += 1;
                preserve_ws = false;
            } else if c == '"' {
                let quoted = self.getquote();
                aslist.push(format!(
                    "\"{}\"",
                    quoted.replace('\\', "\\\\").replace('"', "\\\"")
                ));
            } else if is_atomend(c) {
                if aslist.last().is_some_and(|w| w.trim().is_empty()) {
                    aslist.pop();
                }
                break;
            } else {
                let atom = self.getatom(false);
                aslist.push(atom);
            }
            let ws = self.gotonext();
            if preserve_ws && !ws.is_empty() {
                aslist.push(ws);
            }
        }

        if self.at() != Some('@') {
            return aslist.concat();
        }
        aslist.push("@".to_owned());
        self.pos += 1;
        self.gotonext();
        let domain = self.getdomain();
        if domain.is_empty() {
            return String::new();
        }
        aslist.concat() + &domain
    }

    fn getdomain(&mut self) -> String {
        let mut sdlist: Vec<String> = Vec::new();
        while let Some(c) = self.at() {
            if LWS.contains(c) {
                self.pos += 1;
            } else if c == '(' {
                let comment = self.getcomment();
                self.commentlist.push(comment);
            } else if c == '[' {
                let literal = self.getdomainliteral();
                sdlist.push(literal);
            } else if c == '.' {
                self.pos += 1;
                sdlist.push(".".to_owned());
            } else if c == '@' {
                return String::new();
            } else if is_atomend(c) {
                break;
            } else {
                let atom = self.getatom(false);
                sdlist.push(atom);
            }
        }
        sdlist.concat()
    }

    fn getdelimited(&mut self, beginchar: char, endchars: &str, allowcomments: bool) -> String {
        if self.at() != Some(beginchar) {
            return String::new();
        }
        let mut slist = String::new();
        let mut quote = false;
        self.pos += 1;
        while let Some(c) = self.at() {
            if quote {
                slist.push(c);
                quote = false;
            } else if endchars.contains(c) {
                self.pos += 1;
                break;
            } else if allowcomments && c == '(' {
                let comment = self.getcomment();
                slist.push_str(&comment);
                continue;
            } else if c == '\\' {
                quote = true;
            } else {
                slist.push(c);
            }
            self.pos += 1;
        }
        slist
    }

    fn getquote(&mut self) -> String {
        self.getdelimited('"', "\"\r", false)
    }

    fn getcomment(&mut self) -> String {
        self.getdelimited('(', ")\r", true)
    }

    fn getdomainliteral(&mut self) -> String {
        format!("[{}]", self.getdelimited('[', "]\r", false))
    }

    fn getatom(&mut self, phrase: bool) -> String {
        let mut atom = String::new();
        while let Some(c) = self.at() {
            let end = if phrase {
                is_phraseend(c)
            } else {
                is_atomend(c)
            };
            if end {
                break;
            }
            atom.push(c);
            self.pos += 1;
        }
        atom
    }

    fn getphraselist(&mut self) -> Vec<String> {
        let mut plist = Vec::new();
        while let Some(c) = self.at() {
            if " \t\r\n".contains(c) {
                self.pos += 1;
            } else if c == '"' {
                plist.push(self.getquote());
            } else if c == '(' {
                let comment = self.getcomment();
                self.commentlist.push(comment);
            } else if is_phraseend(c) {
                break;
            } else {
                plist.push(self.getatom(true));
            }
        }
        plist
    }
}

fn address_list(field: &str) -> Vec<(String, String)> {
    if field.is_empty() {
        return Vec::new();
    }
    AddrList::new(field).getaddrlist()
}

/// `email.utils._iter_escaped_chars`: (position, char) pairs, a backslash escape as one item.
fn iter_escaped_chars(addr: &str) -> Vec<(usize, String)> {
    let chars: Vec<char> = addr.chars().collect();
    let mut out = Vec::new();
    let mut escape = false;
    let mut last = 0;
    for (pos, &ch) in chars.iter().enumerate() {
        last = pos;
        if escape {
            out.push((pos, format!("\\{ch}")));
            escape = false;
        } else if ch == '\\' {
            escape = true;
        } else {
            out.push((pos, ch.to_string()));
        }
    }
    if escape {
        out.push((last, "\\".to_owned()));
    }
    out
}

/// `email.utils._strip_quoted_realnames`.
fn strip_quoted_realnames(addr: &str) -> String {
    if !addr.contains('"') {
        return addr.to_owned();
    }
    let chars: Vec<char> = addr.chars().collect();
    let mut start = 0;
    let mut open_pos: Option<usize> = None;
    let mut result = String::new();
    for (pos, ch) in iter_escaped_chars(addr) {
        if ch == "\"" {
            match open_pos {
                None => open_pos = Some(pos),
                Some(open) => {
                    if start != open {
                        result.extend(&chars[start..open]);
                    }
                    start = pos + 1;
                    open_pos = None;
                }
            }
        }
    }
    if start < chars.len() {
        result.extend(&chars[start..]);
    }
    result
}

/// `email.utils._check_parenthesis`.
fn check_parenthesis(addr: &str) -> bool {
    let addr = strip_quoted_realnames(addr);
    let mut opens = 0i64;
    for (_, ch) in iter_escaped_chars(&addr) {
        if ch == "(" {
            opens += 1;
        } else if ch == ")" {
            opens -= 1;
            if opens < 0 {
                return false;
            }
        }
    }
    opens == 0
}

fn pre_parse_validation(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|v| {
            if check_parenthesis(v) {
                v.clone()
            } else {
                "('', '')".to_owned()
            }
        })
        .collect()
}

fn post_parse_validation(parsed: Vec<(String, String)>) -> Vec<(String, String)> {
    parsed
        .into_iter()
        .map(|v| {
            if v.1.contains('[') {
                (String::new(), String::new())
            } else {
                v
            }
        })
        .collect()
}

/// `email.utils.getaddresses(values)` with its default `strict=True`.
pub fn getaddresses(values: &[String]) -> Vec<(String, String)> {
    let values = pre_parse_validation(values);
    let joined = values.join(", ");
    let result = post_parse_validation(address_list(&joined));
    let expected: usize = values
        .iter()
        .map(|v| 1 + strip_quoted_realnames(v).matches(',').count())
        .sum();
    if result.len() != expected {
        return vec![(String::new(), String::new())];
    }
    result
}

/// `email.utils.parseaddr(addr)` with its default `strict=True`.
pub fn parseaddr(addr: &str) -> (String, String) {
    let addr = &pre_parse_validation(&[addr.to_owned()])[0];
    let addrs = post_parse_validation(address_list(addr));
    if addrs.len() != 1 {
        return (String::new(), String::new());
    }
    addrs.into_iter().next().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(text: &str) -> String {
        text.to_owned()
    }

    #[test]
    fn addresses_parse_like_email_utils() {
        assert_eq!(
            parseaddr("John Davison <unixfreak0037@gmail.com>"),
            (s("John Davison"), s("unixfreak0037@gmail.com"))
        );
        assert_eq!(parseaddr("a@b.com"), (s(""), s("a@b.com")));
        // two addresses in one: strict parsing refuses
        assert_eq!(parseaddr("a@b.com, c@d.com"), (s(""), s("")));
        assert_eq!(
            getaddresses(&[s("\"Doe, John\" <a@x.com>, b@x.com")]),
            vec![(s("Doe, John"), s("a@x.com")), (s(""), s("b@x.com"))]
        );
        assert_eq!(
            getaddresses(&[s("alice@example.com <bob@example.com>")]),
            vec![(s(""), s(""))]
        );
        assert_eq!(parseaddr("<a@[1.2.3.4]>"), (s(""), s("")));
        assert_eq!(parseaddr("a@malicious.org@important.com"), (s(""), s("")));
    }
}
