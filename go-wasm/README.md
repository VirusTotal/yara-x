# Go + YARA-X WASM (Wazero)

This directory contains:

- `package yara_x`: Go bindings that mirror `vendor/yara-x/go`, backed by a WASM guest.

## Build the guest WASM

`wazero` currently runs the default embedded guest as a core WebAssembly
binary, so the standard build stays on `wasm32-wasip1` and enables YARA-X's
`wasip1-runtime` feature explicitly.

```bash
cd guest
rustup target add wasm32-wasip1
RUSTFLAGS='-C target-feature=+simd128' cargo build --target wasm32-wasip1
```

The Go bindings look for the guest at:

`../target/wasm32-wasip1/debug/yarax_guest.wasm`

## Build an optimized release guest WASM

The guest crate includes a release build command that compiles in release mode,
enables the `simd128` target feature, builds YARA-X with
`exact-atoms`, `native-code-serialization`, `crypto`, and the enabled module
set (`console`, `crx`, `dex`, `dotnet`, `elf`, `hash`, `lnk`, `macho`,
`math`, `pe`, `string`, `time`, and `vt`), plus `generate-proto-code`,
optimizes with `wasm-opt` (via cargo-managed dependencies), uses `thin` LTO
with a single codegen unit for the Rust build, and writes the final artifact to
`guest/release/yarax_guest.wasm`.

Run:

```bash
cd guest
cargo build-web-release
```

To build a profiling-enabled guest instead, run:

```bash
cd guest
cargo build-web-release --profiling
```

This writes the profiling-enabled artifact to:

`guest/release-profiling/yarax_guest.wasm`

## Build an experimental MEMORY64 guest WASM

There is also an explicit experimental `memory64` build mode for tracking
WASM64 readiness. This build uses nightly Rust, switches the target to
`wasm64-unknown-unknown`, enables `-Z build-std=std,panic_abort`, and enables
the `memory64` feature in `wasm-opt`.

Run:

```bash
cd guest
rustup toolchain install nightly
rustup component add rust-src --toolchain nightly
cargo build-web-release --memory64
```

This writes the experimental artifact to:

`guest/release-memory64/yarax_guest.wasm`

There is also a profiling-enabled variant:

```bash
cd guest
cargo build-web-release --memory64 --profiling
```

This writes to:

`guest/release-memory64-profiling/yarax_guest.wasm`

This path is still experimental. At the moment, upstream Rust/WIT tooling does
not fully support this guest configuration, and the build may fail while
`wit-bindgen` still limits `cabi-realloc` support to `wasm32`. The memory64
build is therefore intended for experimentation and upstream tracking rather
than as the default guest artifact.

## Regenerate embedded guest module

The library embeds a zstd-compressed copy of the release guest module for
runtime loading. Regenerate it with:

```bash
go generate ./...
```

This runs `cargo build-web-release` in `guest/` and compresses
`guest/release/yarax_guest.wasm` to:

`internal/module/yarax_guest.wasm.zst`

You can override it with:

```bash
export YARAX_GUEST_WASM=/absolute/path/to/yarax_guest.wasm
```

Or explicitly at runtime from Go:

```go
err := yara_x.Initialise(
    yara_x.GuestWASMPath("/absolute/path/to/yarax_guest.wasm"),
)
```

or:

```go
file, err := os.Open("/absolute/path/to/yarax_guest.wasm")
if err != nil {
    // handle error
}
defer file.Close()

err = yara_x.Initialise(
    yara_x.GuestWASMReader(file),
)
```

If you don't pass an explicit source to `Initialise`, the bindings fall back
to `YARAX_GUEST_WASM` and then the embedded guest module.

For advanced guest-memory experiments, you can also provide a custom wazero
memory allocator. The `github.com/VirusTotal/yara-x/go-wasm/experimental`
package currently includes an
anonymous `mmap`-backed allocator intended as a basis for future lazy-paging
work:

```go
err := yara_x.Initialise(
    experimental.UseMmapMemoryAllocator(),
)
```

When this allocator is configured, [`Scanner.ScanFile`] can map regular local
files directly into a reserved guest-memory window and scan them without first
copying file contents into guest linear memory.

The same allocator also enables an experimental [`Scanner.ScanReaderAt`]
fast path on Linux. When scanning from an [`io.ReaderAt`] with an explicit
size, the scanner can register a guest-memory window with `userfaultfd` and
populate pages lazily from the reader. This path is only attempted for the
explicit `ReaderAt` scan API; ordinary `Scan`, `ScanReader`, and `ScanFile`
behavior is unchanged.

The module fixture suite is shared across the standard scanner tests and the
Linux-only userfaultfd integration tests, so `make docker-test-userfaultfd`
replays the same module assertions through the lazy-paged `ScanReaderAt` path.

If you don't want the Go binary to embed the guest at all, build the package
or importing program with the `no_embed_wasm` build tag and provide
`YARAX_GUEST_WASM` at runtime, or call `Initialise` with one of the explicit
source options:

```bash
go build -tags no_embed_wasm ./...
export YARAX_GUEST_WASM=/absolute/path/to/yarax_guest.wasm
```

You can also use `YARAX_GUEST_WASM` to test against a profiling-enabled guest
without changing the embedded default:

```bash
cd /Users/linus/src/yara-wasm/vendor/yara-x/go-wasm
make test-profiling
```

This builds `guest/release-profiling/yarax_guest.wasm`, points
`YARAX_GUEST_WASM` at it, and runs the profiling-specific Go tests.

For convenience, the top-level `Makefile` also exposes:

```bash
make guest-release
make guest-release-profiling
make guest-release-memory64
make guest-release-memory64-profiling
```

## Run tests in Docker (Linux + shared cache)

The Docker test path uses Linux so wazero can select the best runtime mode
(compiler/JIT when available), and mounts a shared cache directory for faster
repeat runs.

```bash
cd /Users/linus/src/yara-wasm/vendor/yara-x/go-wasm
make docker-test
```

Optional overrides:

```bash
make docker-test TEST_IMAGE=yarax-go-wasm-test:dev CACHE_DIR=$HOME/.cache/yarax-go-wasm
```
