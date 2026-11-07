package yara_x

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanner1(t *testing.T) {
	r, _ := Compile("rule t { condition: true }")
	s := NewScanner(r)
	scanResults, _ := s.Scan([]byte{})
	matchingRules := scanResults.MatchingRules()

	assert.Len(t, matchingRules, 1)
	assert.Equal(t, "t", matchingRules[0].Identifier())
	assert.Equal(t, "default", matchingRules[0].Namespace())
	assert.Empty(t, matchingRules[0].Patterns())

	scanResults, _ = s.Scan(nil)
	matchingRules = scanResults.MatchingRules()

	assert.Len(t, matchingRules, 1)
	assert.Equal(t, "t", matchingRules[0].Identifier())
	assert.Equal(t, "default", matchingRules[0].Namespace())
	assert.Empty(t, matchingRules[0].Patterns())
}

func TestScanner2(t *testing.T) {
	r, _ := Compile(`rule t { strings: $bar = "bar" condition: $bar }`)
	s := NewScanner(r)
	scanResults, _ := s.Scan([]byte("foobar"))
	matchingRules := scanResults.MatchingRules()

	assert.Len(t, matchingRules, 1)
	assert.Equal(t, "t", matchingRules[0].Identifier())
	assert.Equal(t, "default", matchingRules[0].Namespace())

	assert.Len(t, matchingRules[0].Patterns(), 1)
	assert.Equal(t, "$bar", matchingRules[0].Patterns()[0].Identifier())
	assert.Equal(t, uint64(3), matchingRules[0].Patterns()[0].Matches()[0].Offset())
	assert.Equal(t, uint64(3), matchingRules[0].Patterns()[0].Matches()[0].Length())
	xorKey, ok := matchingRules[0].Patterns()[0].Matches()[0].XorKey()
	assert.False(t, ok)
	assert.Equal(t, uint8(0), xorKey)

	s.Destroy()
	runtime.GC()
}

func TestScannerXorKey(t *testing.T) {
	r, _ := Compile(`rule t { strings: $foo = "foo" xor condition: $foo }`)
	s := NewScanner(r)
	scanResults, _ := s.Scan([]byte{0xCC, 0xC5, 0xC5})
	matchingRules := scanResults.MatchingRules()

	assert.Len(t, matchingRules, 1)
	assert.Len(t, matchingRules[0].Patterns(), 1)
	assert.Len(t, matchingRules[0].Patterns()[0].Matches(), 1)
	xorKey, ok := matchingRules[0].Patterns()[0].Matches()[0].XorKey()
	assert.True(t, ok)
	assert.Equal(t, uint8(0xAA), xorKey)
}

func TestScanner3(t *testing.T) {
	r, _ := Compile(
		`rule t { condition: var_bool }`,
		Globals(map[string]any{"var_bool": true}))

	s := NewScanner(r)
	scanResults, _ := s.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)

	s.SetGlobal("var_bool", false)
	scanResults, _ = s.Scan([]byte{})
	assert.Empty(t, scanResults.MatchingRules())
}

func TestScanner4(t *testing.T) {
	r, _ := Compile(
		`rule t { condition: var_int == 1}`,
		Globals(map[string]any{"var_int": 0}))

	s := NewScanner(r)
	scanResults, _ := s.Scan([]byte{})
	assert.Empty(t, scanResults.MatchingRules())

	require.NoError(t, s.SetGlobal("var_int", 1))
	scanResults, _ = s.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)

	require.NoError(t, s.SetGlobal("var_int", int32(1)))
	scanResults, _ = s.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)

	require.NoError(t, s.SetGlobal("var_int", int64(1)))
	scanResults, _ = s.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)
}

func TestScanFile(t *testing.T) {
	r, _ := Compile(`rule t { strings: $bar = "bar" condition: $bar }`)
	s := NewScanner(r)

	// Create a temporary file with some content
	f, err := os.CreateTemp(t.TempDir(), "example")
	require.NoError(t, err)
	defer os.Remove(f.Name())

	_, err = f.Write([]byte("foobar"))
	require.NoError(t, err)
	f.Close()

	scanResults, _ := s.ScanFile(f.Name())
	matchingRules := scanResults.MatchingRules()
	assert.Len(t, matchingRules, 1)
}

func TestScannerTimeout(t *testing.T) {
	r, _ := Compile("rule t { strings: $a = /a(.*)*a/ condition: $a }")
	s := NewScanner(r)
	s.SetTimeout(1 * time.Second)
	_, err := s.Scan(bytes.Repeat([]byte("a"), 10000))
	assert.ErrorIs(t, err, ErrTimeout)
}

func TestScannerMetadata(t *testing.T) {
	r, _ := Compile(`rule t {
			meta:
				some_int = 1
				some_float = 2.3034
				some_bool = true
				some_string = "hello"
				some_bytes = "\x00\x01\x02"
			condition:
				true
	}`)
	s := NewScanner(r)
	scanResults, _ := s.Scan([]byte{})
	matchingRules := scanResults.MatchingRules()

	assert.Len(t, matchingRules, 1)
	assert.Equal(t, "some_int", matchingRules[0].Metadata()[0].Identifier())
	assert.Equal(t, int64(1), matchingRules[0].Metadata()[0].Value())
	assert.Equal(t, "some_float", matchingRules[0].Metadata()[1].Identifier())
	assert.Equal(t, float64(2.3034), matchingRules[0].Metadata()[1].Value())
	assert.Equal(t, "some_bool", matchingRules[0].Metadata()[2].Identifier())
	assert.Equal(t, true, matchingRules[0].Metadata()[2].Value())
	assert.Equal(t, "some_string", matchingRules[0].Metadata()[3].Identifier())
	assert.Equal(t, "hello", matchingRules[0].Metadata()[3].Value())
	assert.Equal(t, "some_bytes", matchingRules[0].Metadata()[4].Identifier())
	assert.Equal(t, []byte{0, 1, 2}, matchingRules[0].Metadata()[4].Value())
}

func BenchmarkScan(b *testing.B) {
	rules, _ := Compile(`rule t {
		strings:
			$foo = "foo"
			$bar = "bar"
			$baz = "baz"
			$a = "a"
			$b = "b"
			$c = "c"
            $d = "d"
		condition: any of them
	}`)
	scanner := NewScanner(rules)
	for i := 0; i < b.N; i++ {
		results, _ := scanner.Scan([]byte("foo"))
		for _, rule := range results.MatchingRules() {
			_ = rule.Identifier()
		}
	}
}

func TestScannerFastScan(t *testing.T) {
	r, _ := Compile(`
    rule t {
        strings:
            $a = "foo"
        condition:
            $a
    }`)
	s := NewScanner(r)
	s.FastScan(true)
	scanResults, _ := s.Scan([]byte("foofoofoo"))
	matchingRules := scanResults.MatchingRules()

	assert.Len(t, matchingRules, 1)
	assert.Len(t, matchingRules[0].Patterns(), 1)
	assert.Len(t, matchingRules[0].Patterns()[0].Matches(), 1)
}

func TestScannerMaxMatchesPerPattern(t *testing.T) {
	r, _ := Compile(`
    rule t {
        strings:
            $a = "foo"
        condition:
            #a == 1
    }`)
	s := NewScanner(r)
	s.MaxMatchesPerPattern(1)
	scanResults, _ := s.Scan([]byte("foofoofoo"))
	matchingRules := scanResults.MatchingRules()

	assert.Len(t, matchingRules, 1)
}

func TestScannerSlidingWindow(t *testing.T) {
	r, _ := Compile(`
    rule t {
        strings:
            $a = "foo"
            $b = "bar"
        condition:
            $a and $b
    }`)
	s := NewScanner(r)

	// "foo" and "bar" are 9000 bytes apart.
	data := make([]byte, 10000)
	copy(data[0:], "foo")
	copy(data[9000:], "bar")

	scanResults, _ := s.Scan(data)
	assert.Len(t, scanResults.MatchingRules(), 1)

	assert.Error(t, s.SlidingWindow(0, 0))
	assert.Error(t, s.SlidingWindow(100, 100))
	assert.Error(t, s.SlidingWindow(100, -1))
	assert.NoError(t, s.SlidingWindow(1000, 100))

	scanResults, _ = s.Scan(data)
	assert.Len(t, scanResults.MatchingRules(), 0)

	// Now "bar" is close to "foo". The reported offsets are relative to the
	// start of the data, and only matches from the matching window are
	// reported.
	copy(data[8950:], "foo")
	scanResults, _ = s.Scan(data)
	matchingRules := scanResults.MatchingRules()
	assert.Len(t, matchingRules, 1)
	assert.Equal(t, uint64(8950), matchingRules[0].Patterns()[0].Matches()[0].Offset())
	assert.Len(t, matchingRules[0].Patterns()[0].Matches(), 1)

	// The window where the rule matched: windows start every 900 bytes, the
	// one starting at 8100 contains both 8950 and 9000.
	windows := matchingRules[0].MatchingWindows()
	assert.Len(t, windows, 1)
	assert.Equal(t, uint64(8100), windows[0].Start())
	assert.Equal(t, uint64(9100), windows[0].End())
}

func TestScannerSlidingWindowEdgeCases(t *testing.T) {
	r, _ := Compile(`
    rule t {
        strings:
            $a = "foo"
            $b = "bar"
        condition:
            $a and $b
    }`)

	data := make([]byte, 10000)
	copy(data[5000:], "foo")
	copy(data[5050:], "bar")

	// Without a sliding window there are no matching windows.
	s := NewScanner(r)
	scanResults, _ := s.Scan(data)
	assert.Len(t, scanResults.MatchingRules(), 1)
	assert.Len(t, scanResults.MatchingRules()[0].MatchingWindows(), 0)

	// Data that fits in one window is scanned as usual.
	assert.NoError(t, s.SlidingWindow(1000, 100))
	scanResults, _ = s.Scan([]byte("foo bar"))
	assert.Len(t, scanResults.MatchingRules(), 1)
	assert.Len(t, scanResults.MatchingRules()[0].MatchingWindows(), 0)

	// Files.
	path := filepath.Join(t.TempDir(), "data.bin")
	assert.NoError(t, os.WriteFile(path, data, 0o600))
	scanResults, err := s.ScanFile(path)
	assert.NoError(t, err)
	windows := scanResults.MatchingRules()[0].MatchingWindows()
	assert.Len(t, windows, 1)
	assert.Equal(t, uint64(4500), windows[0].Start())
	assert.Equal(t, uint64(5500), windows[0].End())

	// Changing the window between scans.
	assert.NoError(t, s.SlidingWindow(40, 10))
	scanResults, _ = s.Scan(data)
	assert.Len(t, scanResults.MatchingRules(), 0)
}

func TestScannerGarbageCollected(t *testing.T) {
	r, _ := Compile(`rule t { condition: true }`)
	collected := make(chan struct{})

	func() {
		s := NewScanner(r)
		runtime.AddCleanup(s, func(ch chan struct{}) { close(ch) }, collected)
		s.Scan([]byte{})
	}()

	// The scanner has a finalizer, so it takes at least two GC cycles to
	// free it: one for running the finalizer, and another one for freeing
	// the memory.
	for i := 0; i < 10; i++ {
		runtime.GC()
		select {
		case <-collected:
			return
		case <-time.After(10 * time.Millisecond):
		}
	}

	t.Fatal("scanner was not garbage collected")
}
