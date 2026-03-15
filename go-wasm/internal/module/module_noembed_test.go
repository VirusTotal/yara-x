//go:build no_embed_wasm

package module

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecompressedWASMDisabled(t *testing.T) {
	data, err := DecompressedWASM()
	require.Nil(t, data)
	require.Error(t, err)
	require.ErrorContains(t, err, "no_embed_wasm")
}
