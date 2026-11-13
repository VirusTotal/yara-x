# Patch Guidelines

- **Scope**: Keep patches minimal and narrowly focused on fixing the vulnerability. Do not bundle unrelated refactoring, dependency upgrades, or cosmetic cleanups.
- **Error handling**: Never introduce `.unwrap()`, `.expect()`, or unchecked slice indexing on untrusted scanned inputs or rule inputs. Propagate errors idiomatically via `Result`, `nom` combinators, or checked/saturating arithmetic (`checked_add`, `checked_mul`, `get(...)`).
- **Formatting & lints**:
  - YARA-X enforces `max_width = 79` in `rustfmt.toml`. Run `cargo fmt --all` and verify with `cargo fmt --all --check`.
  - Verify zero Clippy warnings with `cargo clippy --offline --tests --no-deps -- --deny clippy::all`.
- **Comments**: Add a brief comment only when an invariant, bounds check, or `unsafe` safety justification is non-obvious. All public items must have doc comments (`#![deny(missing_docs)]` is enabled).
- **Regression test**: Include a minimal unit test in the affected crate/module exercising the reproducer input so `cargo test --offline` verifies the fix.
