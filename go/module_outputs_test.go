package yara_x

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestModuleOutputsCollection(t *testing.T) {
	r, err := Compile(`import "test_proto2" import "pe" rule t { condition: false }`)
	require.NoError(t, err)
	s := NewScanner(r)
	defer s.Destroy()
	disabled, err := s.Scan(nil)
	require.NoError(t, err)
	require.Nil(t, disabled.ModuleOutputs())
	s.CollectModuleOutputs(true)
	result, err := s.Scan(nil)
	require.NoError(t, err)
	require.Empty(t, result.MatchingRules())
	require.Len(t, result.ModuleOutputs(), 2)
	var output map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(result.ModuleOutputs()["test_proto2"], &output))
	require.JSONEq(t, `1`, string(output["int32_one"]))
	require.JSONEq(t, `{"$bytes":["Zm9v"]}`, string(output["bytes_foo"]))
	require.Contains(t, result.ModuleOutputs(), "pe")
	s.CollectModuleOutputs(false)
	result, err = s.Scan(nil)
	require.NoError(t, err)
	require.Nil(t, result.ModuleOutputs())
}

func TestModuleOutputsEmpty(t *testing.T) {
	r, err := Compile(`rule t { condition: true }`)
	require.NoError(t, err)
	s := NewScanner(r)
	defer s.Destroy()
	s.CollectModuleOutputs(true)
	result, err := s.Scan(nil)
	require.NoError(t, err)
	require.NotNil(t, result.ModuleOutputs())
	require.Empty(t, result.ModuleOutputs())
}

func TestModuleOutputsSnapshots(t *testing.T) {
	r, err := Compile(`import "test_proto2" rule t { condition: false }`)
	require.NoError(t, err)
	s := NewScanner(r)
	s.CollectModuleOutputs(true)
	a, err := s.Scan([]byte("abc"))
	require.NoError(t, err)
	failed, err := s.ScanFile(filepath.Join(t.TempDir(), "missing"))
	require.Error(t, err)
	require.Nil(t, failed.ModuleOutputs())
	path := filepath.Join(t.TempDir(), "input")
	require.NoError(t, os.WriteFile(path, []byte("abcde"), 0600))
	b, err := s.ScanFile(path)
	require.NoError(t, err)
	s.Destroy()
	runtime.GC()
	for _, tc := range []struct {
		result *ScanResults
		size   string
	}{{a, "3"}, {b, "5"}} {
		var output map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(tc.result.ModuleOutputs()["test_proto2"], &output))
		require.JSONEq(t, tc.size, string(output["file_size"]))
	}
	delete(a.ModuleOutputs(), "test_proto2")
	require.Contains(t, b.ModuleOutputs(), "test_proto2")
}

func TestCopyNativeBytes(t *testing.T) {
	_, err := copyNativeBytes(nil, uint64(math.MaxInt)+1)
	require.Error(t, err)
	buf := []byte("abc")
	copied, err := copyNativeBytes(unsafe.Pointer(&buf[0]), 3)
	require.NoError(t, err)
	require.Equal(t, buf, copied)
	buf[0] = 'z'
	require.Equal(t, []byte("abc"), copied)
}
