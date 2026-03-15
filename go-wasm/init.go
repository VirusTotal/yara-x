package yara_x

import (
	"fmt"
	"io"

	wazeroexperimental "github.com/tetratelabs/wazero/experimental"
)

type initialiseConfig struct {
	source          guestWasmSource
	hasSource       bool
	memoryAllocator wazeroexperimental.MemoryAllocator
}

// InitialiseOption configures how [Initialise] loads the guest WASM module.
type InitialiseOption interface {
	applyInitialise(*initialiseConfig) error
}

type initialiseOptionFunc func(*initialiseConfig) error

func (f initialiseOptionFunc) applyInitialise(cfg *initialiseConfig) error {
	return f(cfg)
}

// GuestWASMPath tells [Initialise] to load the guest WASM module from the
// given filesystem path instead of the environment variable or embedded copy.
func GuestWASMPath(path string) InitialiseOption {
	return initialiseOptionFunc(func(cfg *initialiseConfig) error {
		if path == "" {
			return fmt.Errorf("guest wasm path is empty")
		}
		if cfg.hasSource {
			return fmt.Errorf("multiple guest wasm sources configured")
		}
		cfg.source = guestWasmSource{path: path}
		cfg.hasSource = true
		return nil
	})
}

// GuestWASMReader tells [Initialise] to load the guest WASM module from the
// provided reader instead of the environment variable or embedded copy.
func GuestWASMReader(r io.Reader) InitialiseOption {
	return initialiseOptionFunc(func(cfg *initialiseConfig) error {
		if r == nil {
			return fmt.Errorf("guest wasm reader is nil")
		}
		if cfg.hasSource {
			return fmt.Errorf("multiple guest wasm sources configured")
		}
		data, err := io.ReadAll(r)
		if err != nil {
			return fmt.Errorf("read guest wasm from reader: %w", err)
		}
		cfg.source = guestWasmSource{bytes: data}
		cfg.hasSource = true
		return nil
	})
}

// WithMemoryAllocator tells [Initialise] to instantiate guest modules with
// the provided wazero linear-memory allocator.
//
// This is primarily intended for advanced and experimental use cases, such as
// custom virtual-memory-backed guest buffers from
// [github.com/VirusTotal/yara-x/go-wasm/experimental].
func WithMemoryAllocator(allocator wazeroexperimental.MemoryAllocator) InitialiseOption {
	return initialiseOptionFunc(func(cfg *initialiseConfig) error {
		if allocator == nil {
			return fmt.Errorf("guest memory allocator is nil")
		}
		cfg.memoryAllocator = allocator
		return nil
	})
}

// Initialise eagerly loads and compiles the guest module so later API calls
// can reuse the prepared runtime without paying the one-time setup cost.
//
// If no explicit source option is provided, the bootstrap falls back to
// `YARAX_GUEST_WASM` and then the embedded guest module. When built with the
// `no_embed_wasm` tag, callers must provide a path or reader source, or set
// `YARAX_GUEST_WASM`.
func Initialise(opts ...InitialiseOption) error {
	if err := configureGuestWasmSource(opts...); err != nil {
		return err
	}
	_, err := ensureGuestProgram()
	return err
}
