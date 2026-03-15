//go:build no_embed_wasm

package module

import "errors"

var errEmbeddedWASMDisabled = errors.New("embedded guest wasm disabled by no_embed_wasm build tag")

// DecompressedWASM returns an error when the no_embed_wasm build tag disables
// the embedded guest module. Callers should set YARAX_GUEST_WASM to an
// external guest module path instead.
func DecompressedWASM() ([]byte, error) {
	return nil, errEmbeddedWASMDisabled
}
