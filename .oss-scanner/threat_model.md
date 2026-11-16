# Threat model

## What this project does and where untrusted input enters

YARA-X is a pure-Rust pattern-matching compiler and scanner designed for malware analysis, threat hunting, endpoint security agents, and high-throughput multi-tenant scanning pipelines (such as VirusTotal).

### Untrusted inputs

1. **Scanned files and byte streams** passed to `Scanner::scan`, `Scanner::scan_file`, `Scanner::scan_mem`, block scanning (`scanner::blocks`), CLI commands (`yr scan`, `yr dump`), C bindings (`yrx_scanner_*`), and Python bindings (`Rules.scan`, `Scanner.scan`).
   - Callers routinely scan adversarial, malformed, or deliberately crafted malware binaries and archives.
   - Built-in modules parse untrusted formats including PE/COFF & Authenticode/X.509 (`pe`), .NET metadata (`dotnet`), ELF (`elf`), Mach-O & code signatures (`macho`), Android Dalvik executables (`dex`), Chrome extensions (`crx`), Windows shortcuts (`lnk`), ZIP archives (`zip`), MSI/OLECF/VBA Office documents (`msi`, `olecf`, `vba`), JSON sandbox/metadata payloads (`cuckoo`, `vt`), and file type signatures (`magic`).
2. **YARA source rules** passed to `yara_x::compile`, `Compiler::add_source`, `yara-x-parser`, `yara-x-fmt`, `yara-x-ls`, CLI commands (`yr compile`, `yr check`, `yr fmt`), C bindings (`yrx_compile`, `yrx_compiler_*`), and Python bindings (`yara_x.compile`, `Compiler.add_source`).
   - Multi-tenant services, rule-testing pipelines, and developer tools compile and execute third-party YARA rules.
   - Source rules are lexed/parsed into CST/AST, compiled into Aho-Corasick / SIMD Teddy atom matchers, regular expression bytecode (`FastVM` and Thompson `PikeVM`), and WebAssembly rule conditions executed by Wasmtime (Cranelift JIT by default, or the `pulley` bytecode interpreter).

### Trusted inputs

- **Serialized compiled rules** loaded via `Rules::deserialize`, `Rules::deserialize_from`, C API `yrx_rules_deserialize`, and Python `Rules.deserialize`. These APIs explicitly require trusted bytes produced by `Rules::serialize` because precompiled Wasmtime artifacts cannot be safely loaded from untrusted sources.
- **Host-provided API arguments and environment**, such as host pointers passed across the C FFI boundary (`capi/`), global variable definitions (`Compiler::define_global`), include directories explicitly configured via `Compiler::add_include_dir`, and CLI filesystem arguments.

## Components that matter most / least

### Highest priority
- **Core library (`lib/`)**:
  - **Scanner & WASM runtime integration (`lib/src/scanner/`, `lib/src/wasm/`, `lib/src/compiler/`)**: `ScanContext` lifecycle, pinned memory, raw pointers bridging Rust and Wasmtime host functions, matching-rule bitmaps, memory-mapped file handling, and WASM linear memory bounds.
  - **Pattern & regular expression engines (`lib/src/re/`, `lib/src/teddy/`)**: `unsafe` SIMD vector routines in `teddy`, `FastVM`, `PikeVM`, and bitmap/instruction decoding.
  - **Binary format & certificate parsers (`lib/src/modules/`)**: `pe`, `dotnet`, `elf`, `macho`, `dex`, `crx`, `lnk`, `zip`, `msi`, `olecf`, `vba`, and cryptographic/ASN.1/X.509 parsing (`crypto`), especially integer overflows, slice bounds, unbounded allocations, or infinite loops on crafted files.
- **Rule parser (`parser/`)**: Tokenizer, CST, and AST construction (`unsafe` tree/token/slice operations, recursion depth, and malformed syntax recovery).

### Medium priority
- **FFI & language bindings (`capi/`, `py/`, `go/`, `js-wasm/`)**: Memory safety, ownership/lifetime soundness, error propagation, and buffer handling when callers follow documented API contracts.
- **CLI, formatter, and Language Server (`cli/`, `fmt/`, `ls/`)**: Handling untrusted rules and scanned files without memory unsafety or crashes.

### Out of scope
- Documentation site (`site/`), web playground frontend (`playground/`), `docs/`, `examples/`, and binary test corpora (`**/testdata/**`, `**/*.zip`, `**/*.out`).

## How to exercise it

All dependencies are vendored/cached during the container build; pass `--offline` to Cargo when running without network access in `/src`:

- **Run workspace unit & integration tests**:
  ```bash
  cargo test --offline --features=magic-module,rules-profiling
  ```
- **Test core library including experimental modules (`msi`, `olecf`, `vba`)**:
  ```bash
  cargo test --offline -p yara-x --features=magic-module,msi-module,olecf-module,vba-module,rules-profiling
  ```
- **Test with Wasmtime's Pulley interpreter backend**:
  ```bash
  cargo test --offline -p yara-x --features=pulley,magic-module
  ```
- **Run CLI binary (`/src/target/debug/yr`) and CLI test suite**:
  ```bash
  CARGO_BIN_EXE_yr=/src/target/debug/yr cargo test --offline -p yara-x-cli --bin yr
  ```
- **Check formatting and lints on proposed patches**:
  ```bash
  cargo fmt --all --check
  cargo clippy --offline --tests --no-deps -- --deny clippy::all
  ```

## How you rate severity

- **Critical**: Memory corruption (buffer overflow, use-after-free, double free, type confusion), WASM sandbox escape, or arbitrary code execution triggered by untrusted scanned data or untrusted YARA source rules.
- **High**: Out-of-bounds read, uninitialized memory disclosure, soundness bugs in `unsafe` blocks reachable from safe Rust APIs, or bypasses of WASM linear-memory isolation.
- **Medium**:
  - Unhandled panics (`unwrap()`, out-of-bounds slice indexing, arithmetic overflow/division-by-zero panics, stack overflows) reachable when compiling untrusted YARA source rules or scanning untrusted files.
  - Algorithmic complexity / OOM / infinite loops in file-format parsers, rule compilation, or scan execution **that bypass `Scanner::set_timeout`** (or occur before scan timeout enforcement).
  - Parser/verification bugs in security-critical modules (e.g., `pe` Authenticode signature validation, `macho` code signing, `elf`/`dex` structural parsing) allowing crafted binaries to spoof verified attributes or evade inspection.
- **Low**: Panics or resource exhaustion restricted to developer-facing auxiliary crates (`yara-x-fmt`, `yara-x-ls`) with no memory-safety impact.

## Anything to leave alone

- **Deserialization of compiled rules**: Do **not** report memory unsafety, panics, or RCE via `Rules::deserialize`, `Rules::deserialize_from`, `yrx_rules_deserialize`, or `yara_x.Rules.deserialize` (which invoke `unsafe { wasmtime::Module::deserialize(...) }`). Serialized compiled rules are trusted by design and explicitly documented as unsafe to load from untrusted sources.
- **`unsafe fn yara_x::finalize()`**: This function is intentionally `unsafe` and documents strict caller preconditions for tearing down global Wasmtime state prior to `dlclose`.
- **C API caller precondition violations**: Do not report issues in `capi/` that require the C caller to pass invalid/dangling/null pointers (where non-null is expected), mismatched buffer lengths, double-freeing `YRX_*` handles, or sharing a non-thread-safe `YRX_SCANNER` across threads concurrently.
- **Slow YARA rules without `Scanner::set_timeout`**: YARA allows expressive loops and regexes that can be expensive on large inputs when run without a timeout. Only report scan-time hangs/CPU exhaustion if `Scanner::set_timeout(Duration::from_secs(2))` fails to abort the scan promptly, or if a tiny input triggers multi-gigabyte unbounded allocation.
- **Forcing `opt-level = 0` on `yara-x-parser`**: `Cargo.toml` intentionally sets `[profile.dev.package.yara-x-parser] opt-level = 1` so `rustc` applies tail-call optimization to the `logos`-generated lexer (issue #441). Do not report stack overflows that only reproduce when overriding that profile setting.
- **Intentional CLI / `console` capabilities**: Local file reads requested via CLI arguments or configured `Compiler::add_include_dir` paths, and diagnostic output from the `console` module, are expected functionality.
