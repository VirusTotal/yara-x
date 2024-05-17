[![tests](https://github.com/VirusTotal/yara-x/actions/workflows/tests.yaml/badge.svg)](https://github.com/VirusTotal/yara-x/actions/workflows/tests.yaml)
[![coverage](https://codecov.io/gh/VirusTotal/yara-x/branch/main/graph/badge.svg?token=dPsruCiDqN)](https://app.codecov.io/gh/VirusTotal/yara-x)
[![Crates.io](https://img.shields.io/crates/v/yara-x.svg)](https://crates.io/crates/yara-x)
![Crates.io MSRV](https://img.shields.io/crates/msrv/yara-x)

## YARA-X

YARA-X is a re-incarnation of [YARA](https://github.com/VirusTotal/yara), a
pattern matching tool designed with malware researchers in mind. This new
incarnation intends to be faster, safer and more user-friendly than its
predecessor. The ultimate goal of YARA-X is to serve as the future replacement
for YARA.

With YARA-X you can create descriptions of malware families (or whatever you
want to describe) based on textual or binary patterns. Each description (a.k.a.
rule) consists of a set of patterns and a boolean expression which determine its
logic. Let’s see an example:

```yara
rule silent_banker : banker {
    meta:
        description = "This is just an example"
        threat_level = 3
        in_the_wild = true

    strings:
        $a = {6A 40 68 00 30 00 00 6A 14 8D 91}
        $b = {8D 4D B0 2B C1 83 C0 27 99 6A 4E 59 F7 F9}
        $c = "UVODFRYSIHLNWPEJXQZAKCBGMT"

    condition:
        $a or $b or $c
}
```

The above rule is telling YARA-X that any file containing one of the three
patterns must be reported as `silent_banker`. This is just a simple example,
more complex and powerful rules can be created by using wild-cards,
case-insensitive strings, regular expressions, special operators and many other
features that you'll find explained in
the [documentation](https://virustotal.github.io/yara-x/docs/writing_rules/anatomy-of-a-rule/).

## FAQ

#### How does YARA-X compare to YARA?

Read [this](https://virustotal.github.io/yara-x/docs/intro/yara-x-vs-yara/).

#### Which are the differences at the rule level?

Read [this](https://virustotal.github.io/yara-x/docs/writing_rules/differences-with-yara/).

#### Is YARA still maintained?

Yes, it is. YARA is still being maintained, and future releases will include
bug fixes and minor features. However, don’t expect new large features or
modules. All efforts to enhance YARA, including the addition of new modules,
will now focus on YARA-X.

#### What's the current state of YARA-X?

YARA-X is still in beta, but is mature and stable enough for use, specially
from the command-line interface or one-shot Python scripts. While the APIs may
still undergo minor changes, the foundational aspects are already established.

At VirusTotal, we have been running YARA-X alongside YARA for a while,
scanning
millions of files with tens of thousands of rules, and addressing
discrepancies
between the two. This means that YARA-X is already battle-tested. These tests
have even uncovered YARA bugs!

Please test YARA-X and don’t hesitate
to [open an issue](https://github.com/VirusTotal/yara-x/issues/new) if you
find a bug or some feature that you want to see implemented.