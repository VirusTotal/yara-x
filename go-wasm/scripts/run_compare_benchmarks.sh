#!/usr/bin/env bash
set -euo pipefail

: "${COMPARE_BENCH_COUNT:=3}"
: "${COMPARE_BENCH_SCAN_ITERS:=100000}"
: "${COMPARE_BENCH_NEW_SCANNER_ITERS:=500}"
: "${COMPARE_BENCH_RULES_SCAN_ITERS:=1000}"
: "${COMPARE_BENCH_READ_FROM_ITERS:=500}"

export PATH=/usr/local/go/bin:/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

if ! cargo cinstall --help >/dev/null 2>&1; then
	cargo install cargo-c --version 0.10.18+cargo-0.92.0 --locked
fi

cargo cinstall -p yara-x-capi \
	--release \
	--prefix /usr/local \
	--libdir /usr/local/lib \
	--includedir /usr/local/include

export PKG_CONFIG_PATH=/usr/local/lib/pkgconfig:/usr/local/lib/x86_64-linux-gnu/pkgconfig:/usr/local/lib64/pkgconfig:/usr/local/share/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}
export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib/x86_64-linux-gnu:/usr/local/lib64${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}

cd /workspace/yara-x/benchcmp
go mod tidy

go test -run "^$" -bench "^(Benchmark(CGO|WASM)ScanReuseScanner)$" -benchmem -benchtime="${COMPARE_BENCH_SCAN_ITERS}x" -count="${COMPARE_BENCH_COUNT}"
go test -run "^$" -bench "^(Benchmark(CGO|WASM)NewScanner)$" -benchmem -benchtime="${COMPARE_BENCH_NEW_SCANNER_ITERS}x" -count="${COMPARE_BENCH_COUNT}"
go test -run "^$" -bench "^(Benchmark(CGO|WASM)RulesScan)$" -benchmem -benchtime="${COMPARE_BENCH_RULES_SCAN_ITERS}x" -count="${COMPARE_BENCH_COUNT}"
go test -run "^$" -bench "^(Benchmark(CGO|WASM)ReadFrom)$" -benchmem -benchtime="${COMPARE_BENCH_READ_FROM_ITERS}x" -count="${COMPARE_BENCH_COUNT}"
