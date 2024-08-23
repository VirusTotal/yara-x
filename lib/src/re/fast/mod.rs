/*! This module implements [FastVM], a faster but less general alternative
to [PikeVM], accompanied by a compiler designed to generate code for it.

[FastVM] closely resembles [PikeVM], albeit with certain limitations. It
exclusively supports regular expressions adhering to the following rules:

- No repetitions are allowed, except when the repeated pattern is any byte. So,
  `.*` and `.{1,3}` are permitted, but `a*` and `a{1,3}` are not.

- Character classes are disallowed unless they can be represented as masked
  bytes. For example, `[a-z]` is not supported, but `[Aa]` is, as it can be
  expressed as `0x41` masked with `0x20` (where `0x41` corresponds to `A`,
  and applying the mask `0x20` yields `0x61`, representing `a`).

- Alternatives are accepted, provided that the options consist only of literals
  or character classes equivalent to masked bytes. For example, `(foo|bar)`
  is supported because both options are literals, and `[Ff]oo|[Bb]ar` is also
  supported since the byte classes can be expressed as masked bytes.

- Nested alternations are not permitted.

Most regular expressions derived from YARA hex patterns (which are simply a
subset of regular expressions), are compatible with [FastVM], except when they
contain alternations that contain variable length jumps
(e.g: `{ (01 02 03 [1-4] 05 | 06 07 08) }`).

Many standard regular expressions also work with [FastVM].

YARA prioritizes compiling regular expressions for [FastVM] and only resorts
to [PikeVM] if the compilation fails due to incompatible constructs in the
regular expression.

[FastVM]: fastvm::FastVM
[PikeVM]: crate::re::thompson::pikevm::PikeVM
*/

pub(crate) use compiler::Compiler;
pub(crate) use fastvm::FastVM;

mod compiler;
mod fastvm;
mod instr;
