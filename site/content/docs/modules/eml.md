---
title: "eml"
description: ""
summary: ""
date: 2026-10-03T00:00:00+00:00
lastmod: 2026-10-03T00:00:00+00:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "eml-module"
weight: 450
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The `eml` module parses email messages in the
[EML format](https://datatracker.ietf.org/doc/html/rfc2045) (RFC 2045), and
exposes their headers, addresses, body and MIME parts to YARA.

-------

## Module structure

| Field        | Type                          | Description                                                                                                                                                                       |
|--------------|-------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| is_eml       | bool                          | True if the file was parsed as an EML file.                                                                                                                                       |
| headers      | [Header](#header) array       | All the top-level headers, in the order they appear, with repeated headers kept as separate entries. Folded headers are unfolded.                                                 |
| body         | string                        | The body of the message, exactly as it appears after the headers.                                                                                                                 |
| decoded_body | string                        | The body after decoding its `Content-Transfer-Encoding`. Only set for `base64` and `quoted-printable` bodies.                                                                    |
| parts        | [EmlPart](#emlpart) array     | The MIME parts of a multipart message. See [EmlPart](#emlpart).                                                                                                                  |
| from         | [Address](#address) array     | Mailboxes in the `From` header.                                                                                                                                                   |
| to           | [Address](#address) array     | Mailboxes in the `To` header.                                                                                                                                                     |
| cc           | [Address](#address) array     | Mailboxes in the `Cc` header.                                                                                                                                                     |
| reply_to     | [Address](#address) array     | Mailboxes in the `Reply-To` header.                                                                                                                                               |
| return_path  | [Address](#address)           | The mailbox in the `Return-Path` header.                                                                                                                                          |
| subject      | string                        | The `Subject` header, with [RFC 2047](https://datatracker.ietf.org/doc/html/rfc2047) encoded words decoded to UTF-8.                                                              |
| message_id   | string                        | The raw `Message-ID` header.                                                                                                                                                      |
| date         | string                        | The raw `Date` header.                                                                                                                                                            |

The convenience fields (`from`, `to`, `cc`, `reply_to`, `return_path`,
`subject`, `message_id` and `date`) come from the top-level headers and use the
first matching header, except for the address fields, which collect the
mailboxes of every occurrence of the header. If the message doesn't have the
corresponding header, the address arrays are empty and the other fields are
undefined. The raw, undecoded header values are always available in `headers`.

{{< callout title="Notice">}}
`defined` can't be applied to a structure. To check whether `return_path` is
present, test one of its fields, like `defined eml.return_path.address`.
{{< /callout >}}

### Header

Each entry of the `headers` array, and of the `headers` array in each
[EmlPart](#emlpart).

| Field | Type   | Description                                                      |
|-------|--------|------------------------------------------------------------------|
| key   | string | The header name, **lowercased**. For example `content-type`.     |
| value | string | The header value, with folded lines joined by a single space.    |

Because keys are lowercased, compare them against lowercase strings, or use
[header()](#headername) and [header_count()](#header_countname), which are
case-insensitive.

#### Example

```yara
import "eml"

rule received_from_localhost {
  condition:
    for any h in eml.headers : (
      h.key == "received" and h.value contains "localhost"
    )
}
```

### Address

A single mailbox, like `Jane Doe <jane@example.com>`. Address headers are
parsed into individual mailboxes, handling quoted display names (even if they
contain commas or angle brackets), bare addresses, `addr (Name)` comments and
groups. Encoded words in display names are decoded to UTF-8.

| Field   | Type   | Description                                                                |
|---------|--------|----------------------------------------------------------------------------|
| name    | string | The display name, without quotes. Undefined if the mailbox has no name.    |
| address | string | The address itself, like `jane@example.com`.                               |

#### Example

```yara
import "eml"

rule display_name_spoof {
  condition:
    eml.from[0].name contains "PayPal" and
    not eml.from[0].address endswith "@paypal.com"
}
```

### EmlPart

Each entry of the `parts` array is a leaf part of a multipart message. A
message that isn't multipart has no parts. Nested
multipart containers are traversed but not listed themselves, and the text
before the first boundary (the preamble) is not a part. To guard against MIME
bombs, parsing stops after 100 MIME entities (containers included).

| Field        | Type                    | Description                                                                                                                  |
|--------------|-------------------------|------------------------------------------------------------------------------------------------------------------------------|
| headers      | [Header](#header) array | The headers of the part.                                                                                                     |
| body         | string                  | The body of the part, exactly as it appears after its headers.                                                               |
| decoded_body | string                  | The body after decoding its `Content-Transfer-Encoding`. Only set for `base64` and `quoted-printable` bodies.                |
| filename     | string                  | The `filename` parameter of `Content-Disposition`, or if missing, the `name` parameter of `Content-Type`. Not decoded.      |
| disposition  | string                  | The disposition type of `Content-Disposition`, lowercased. Usually `attachment` or `inline`.                                 |
| content_type | string                  | The media type of `Content-Type` without parameters, lowercased. For example `text/html`.                                    |
| charset      | string                  | The `charset` parameter of `Content-Type`, as written.                                                                       |
| content_id   | string                  | The `Content-ID` header without the surrounding angle brackets.                                                              |
| size         | integer                 | Size in bytes of `decoded_body`, or of `body` if the part isn't encoded.                                                     |

#### Example

```yara
import "eml"

rule html_attachment {
  condition:
    for any p in eml.parts : (
      p.disposition == "attachment" and
      p.content_type == "text/html" and
      p.filename endswith ".html"
    )
}
```

-------

## Functions

### has_header(name)

Returns true if the top-level headers contain a header named `name`.

- `name` is case-insensitive.

#### Example

```yara
import "eml"

rule has_date {
  condition:
    eml.has_header("Date")
}
```

### header(name)

Returns the value of the first top-level header named `name`, or undefined if
there is none. To inspect every occurrence of a repeated header, iterate over
`headers` instead.

- `name` is case-insensitive.

#### Example

```yara
import "eml"

rule phpmailer {
  condition:
    eml.header("X-Mailer") contains "PHPMailer"
}
```

### header_count(name)

Returns the number of top-level headers named `name`, which is 0 if there are
none. This is useful for headers that shouldn't repeat, or whose repetition is
meaningful.

- `name` is case-insensitive.

#### Example

```yara
import "eml"

rule duplicate_from {
  condition:
    eml.header_count("from") > 1
}
```
