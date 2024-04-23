---
title: "Go"
description: ""
summary: ""
date: 2023-09-07T16:04:48+02:00
lastmod: 2023-09-07T16:04:48+02:00
draft: false
menu:
  docs:
    parent: ""
    identifier: "go-api"
weight: 520
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

Go is one of the languages we love and use at VirusTotal, integrating YARA-X
into Go
programs is a must for us. Therefore, the Go library is a first-class citizen
in the YARA-X ecosystem, and we battle test it every day. The Go library uses
the [C API]({{< ref "c.md" >}}) under the hood.

Please refer to the
package [documentation](https://pkg.go.dev/github.com/VirusTotal/yara-x/go).