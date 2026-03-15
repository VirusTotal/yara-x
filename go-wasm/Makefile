DOCKER ?= docker
TEST_IMAGE ?= yarax-go-wasm-test:latest
CACHE_DIR ?= $(HOME)/.cache/yarax-go-wasm
YARAX_ROOT := $(abspath ..)

.PHONY: guest-release guest-release-profiling guest-release-memory64 guest-release-memory64-profiling test-profiling docker-test-image docker-test docker-test-userfaultfd docker-bench-compare

guest-release:
	cd guest && cargo build-web-release

guest-release-profiling:
	cd guest && cargo build-web-release --profiling

guest-release-memory64:
	cd guest && cargo build-web-release --memory64

guest-release-memory64-profiling:
	cd guest && cargo build-web-release --memory64 --profiling

test-profiling: guest-release-profiling
	YARAX_GUEST_WASM=$(abspath guest/release-profiling/yarax_guest.wasm) \
	YARAX_REQUIRE_PROFILING=1 \
	go test ./... -run 'TestScannerProfilingEnabledWithOverride|TestScannerProfilingAPIs' -count=1

docker-test-image:
	$(DOCKER) buildx build --load -f Dockerfile.test -t $(TEST_IMAGE) .

docker-test: docker-test-image
	mkdir -p $(CACHE_DIR)/go-build $(CACHE_DIR)/go-mod $(CACHE_DIR)/cargo-home $(CACHE_DIR)/cargo-target
	$(DOCKER) run --rm \
		-v $(YARAX_ROOT):/workspace/yara-x \
		-v $(CACHE_DIR):/cache \
		-w /workspace/yara-x/go-wasm \
		-e GOCACHE=/cache/go-build \
		-e GOMODCACHE=/cache/go-mod \
		-e CARGO_HOME=/cache/cargo-home \
		-e CARGO_TARGET_DIR=/cache/cargo-target \
		$(TEST_IMAGE) \
		go test ./...

docker-test-userfaultfd: docker-test-image
	mkdir -p $(CACHE_DIR)/go-build $(CACHE_DIR)/go-mod $(CACHE_DIR)/cargo-home $(CACHE_DIR)/cargo-target
	$(DOCKER) run --rm --privileged --security-opt seccomp=unconfined \
		-v $(YARAX_ROOT):/workspace/yara-x \
		-v $(CACHE_DIR):/cache \
		-w /workspace/yara-x/go-wasm \
		-e GOCACHE=/cache/go-build \
		-e GOMODCACHE=/cache/go-mod \
		-e CARGO_HOME=/cache/cargo-home \
		-e CARGO_TARGET_DIR=/cache/cargo-target \
		-e YARAX_EXPERIMENTAL_UFFD=1 \
		$(TEST_IMAGE) \
		go test ./experimental -count=1

docker-bench-compare: docker-test-image
	mkdir -p $(CACHE_DIR)/go-build $(CACHE_DIR)/go-mod $(CACHE_DIR)/cargo-home $(CACHE_DIR)/cargo-target
	$(DOCKER) run --rm \
		-v $(YARAX_ROOT):/workspace/yara-x \
		-v $(CACHE_DIR):/cache \
		-w /workspace/yara-x \
		-e GOCACHE=/cache/go-build \
		-e GOMODCACHE=/cache/go-mod \
		-e CARGO_HOME=/cache/cargo-home \
		-e CARGO_TARGET_DIR=/cache/cargo-target \
		-e COMPARE_BENCH_COUNT \
		-e COMPARE_BENCH_SCAN_ITERS \
		-e COMPARE_BENCH_NEW_SCANNER_ITERS \
		-e COMPARE_BENCH_RULES_SCAN_ITERS \
		-e COMPARE_BENCH_READ_FROM_ITERS \
		$(TEST_IMAGE) \
		bash /workspace/yara-x/go-wasm/scripts/run_compare_benchmarks.sh
