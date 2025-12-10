---
title: "crx"
description: ""
summary: ""
date: 2025-08-04T16:00:00:00+00:00
lastmod: 2025-08-04T16:00:00:00+00:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "crx-module"
weight: 200
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

The `crx` module parses Chrome Extension (CRX) files and enables the creation of 
YARA rules based on metadata extracted from these files. CRX files are used by 
Chromium-based browsers—such as Google Chrome and Microsoft Edge—to package and
distribute browser extensions. Essentially, they are ZIP archives with a 
different file extension and additional metadata, including one or more digital
signatures that validate the file’s integrity.

-------

## Functions

{{< callout context="caution" title="Important">}}

Hashes returned by the functions below are always in lowercase.

{{< /callout >}}

### permhash()

Returns permhash of the crx. See [Google blog post](https://cloud.google.com/blog/topics/threat-intelligence/permhash-no-curls-necessary/) for more details.

Example: `crx.permhash() == "0bd16e5d8c30b71e844aa6f30b381adf20dc14cc555f5594fc3ac49985c9a52e"`

#### Examples

```
import "crx"

rule AllCrx {
    condition:
        crx.is_crx
}

rule CrxV2 {
    condition:
        crx.crx_version == 2
}


rule ProtocolPreregistration {
    condition:
        crx.name == "Protocol Preregistration"
}
```

-------

## Module structure

| Field                     | Type            |
|---------------------------|-----------------|
| is_crx                    | bool            |
| crx_version               | integer         |
| header_size               | integer         |
| id                        | string          |
| version                   | string          |
| name                      | string          |
| description               | string          |
| raw_name                  | string          |
| raw_description           | string          |
| homepage_url              | string          |
| permissions               | string array    |
| host_permissions          | string array    |
| optional_permissions      | string array    |
| optional_host_permissions | string array    |
| signatures                | Signature array |

### Signature

Structure that describes each of the signatures found in a CRX file.

| Field     | Type   |
|-----------|--------|
| key       | string |
| verified  | bool   |

#### Example

```
import "crx"

rule crx_verified {
    condition:
        for any signature in crx.signatures {
           signature.verified
        }
}
```

