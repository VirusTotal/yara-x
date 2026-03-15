package experimental_test

import (
	"os"
	"path/filepath"
	"testing"

	yara_x "github.com/VirusTotal/yara-x/go-wasm"
	"github.com/VirusTotal/yara-x/go-wasm/experimental"

	"github.com/stretchr/testify/require"
)

func TestScanFileWithExperimentalMmapAllocator(t *testing.T) {
	require.NoError(t, yara_x.Initialise(experimental.UseMmapMemoryAllocator()))

	rules, err := yara_x.Compile(`rule t { strings: $a = "mapped" condition: $a }`)
	require.NoError(t, err)
	defer rules.Destroy()
	scanner := yara_x.NewScanner(rules)
	defer scanner.Destroy()

	file := filepath.Join(t.TempDir(), "mapped.bin")
	require.NoError(t, os.WriteFile(file, []byte("mapped data"), 0o600))

	results, err := scanner.ScanFile(file)
	require.NoError(t, err)
	require.Len(t, results.MatchingRules(), 1)
}
