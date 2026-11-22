# Searching alerts

The search box on the alert list finds alerts three ways. Which ones run depends on what you type.

## Free text

```
docusign invoice
powershell encoded download
vendor mailer false positive
```

Plain words are searched by meaning, over each alert's text: its title, its detections, an email's
headers and body, a command line, the text OCR and `pdftotext` read, a macro's source. An alert doesn't
have to hold your exact words to match, and one that shares a rare word with your query ranks higher.
A query that resembles nothing returns nothing.

A bare indicator is free text too. Pasting `10.20.30.40` or a hash searches by meaning and by shared
words only. It never looks the indicator up exactly. To find every alert that holds it, name it.

## Field terms

A term is `name:value`. Each of these is looked up exactly, and its matches come first, newest first:

| Term | Finds |
|---|---|
| `ipv4:10.20.30.40` | alerts with that observable. Any observable type works as the name: `fqdn:`, `url:`, `email_address:`, `sha256:`, `file:` (by the file's sha256) and the rest |
| `observable:url:https://evil.example/a` | the same, written out, for a value with colons in it |
| `tag:phish` | alerts with that tag on an observable or a result |
| `uuid:1f2e3d4c-…` | the alert with that id, or with an id that starts with those eight or more characters |

The alert list's filters are terms too, by the names their share links use. They narrow the search:

| Term | Keeps |
|---|---|
| `queue:default` | alerts in that queue |
| `disposition:DELIVERY,IGNORE` | alerts with either disposition |
| `alert_date:-7d` | alerts of the last seven days |
| `owner:jdoe` | alerts that analyst owns |
| `description:invoice` | alerts whose title contains the text |
| `detection_point:<signature uuid>` | alerts with a detection from that signature |
| `analysis:<module>` | alerts a module wrote a result for |
| `observable_pattern:fqdn:*.evil.com` | alerts with an observable of that type whose value matches the pattern, `any` for any type |

Also `event_date:`, `disposition_date:`, `disposition_by:` and `unconfirmed_detections:`.

- Put `-` or `!` before a term to invert it: `-tag:whitelisted` keeps alerts without the tag.
- Separate values with commas to match any of them: `queue:default,edr`.
- Quote a value that holds a space or a comma: `tag:"vendor mailer"`.
- Repeating a name means either: `queue:default queue:edr`.
- A tag with `*` matches by pattern: `tag:phish*`.
- An observable pattern has `*` at its start or its end: `observable_pattern:fqdn:*.evil.com`,
  `observable_pattern:url:https://evil.example/*`. A `*` in the middle is fine when one end is text
  (`observable_pattern:fqdn:evil.com*.net`), but not at both ends (`*evil*`), which would read every
  observable. Only `*` is a wildcard, and the match keeps case. A pattern that matches more than 500
  observables, or takes longer than a second to look up, is reported and nothing is searched: make its
  text longer or name a type. A `*` in `observable:` or a type's own term is a literal character, so
  `email_subject:"***SPAM***"` finds that subject.

A name that is neither a filter nor an observable type isn't a term, so `https://evil.example` and
`C:\windows\system32` stay text as you typed them.

Terms and text combine: `docusign invoice queue:default -tag:whitelisted`. With terms and no text, the
answer is a plain listing, newest first.

## What comes back

Each alert has a tier under it, which says why it matched:

| Tier | Why |
|---|---|
| exact | a field term matched an observable, a tag or the id as written |
| strong | its text is clearly like the query, or like it and shares a word with it |
| good | its text is like the query |
| weak | it shares a word with the query, and its text isn't like it |

Under the tier are up to five of the pieces that matched, each with where it came from.

A term that can't be used, such as `alert_date:-7dd` or `uuid:` with something that isn't an id, is
reported and nothing is searched. Searching without it would return more than you asked for.

## Test-run alerts

Alerts in the test queue are left out unless your search names a queue. The count says how many were
left out, with a link that includes them.

## Similar alerts

An alert's page has a **Similar alerts** link: the alerts whose text is most like that alert's, with
their dispositions. It answers "have we seen this before?".
