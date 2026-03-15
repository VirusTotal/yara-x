//go:build !no_embed_wasm

package module

import (
	_ "embed"
	"fmt"
	"sync"

	"github.com/klauspost/compress/zstd"
)

var (
	//go:embed yarax_guest.wasm.zst
	compressedGuestWasm []byte

	decompressedGuestWasm     []byte
	errDecompressedGuestWasm  error
	decompressedGuestWasmOnce sync.Once
)

// DecompressedWASM returns the embedded guest module bytes after zstd
// decompression.
func DecompressedWASM() ([]byte, error) {
	decompressedGuestWasmOnce.Do(func() {
		decoder, err := zstd.NewReader(nil)
		if err != nil {
			errDecompressedGuestWasm = fmt.Errorf("create zstd decoder: %w", err)
			return
		}
		defer decoder.Close()

		decompressedGuestWasm, err = decoder.DecodeAll(compressedGuestWasm, nil)
		if err != nil {
			errDecompressedGuestWasm = fmt.Errorf("decompress embedded guest wasm: %w", err)
			return
		}
	})

	if errDecompressedGuestWasm != nil {
		return nil, errDecompressedGuestWasm
	}

	out := make([]byte, len(decompressedGuestWasm))
	copy(out, decompressedGuestWasm)
	return out, nil
}
