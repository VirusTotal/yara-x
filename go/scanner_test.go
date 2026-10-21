package yara_x

import (
	"bytes"
	"os"
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

var testZipData = []byte{
	0x50, 0x4b, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 0x33,
	0x63, 0xd0, 0x5c, 0xe7, 0xb0, 0x5a, 0x76, 0x35, 0x00, 0x00, 0x00,
	0x36, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x73, 0x75, 0x73,
	0x70, 0x69, 0x63, 0x69, 0x6f, 0x75, 0x73, 0x5f, 0x70, 0x61, 0x79,
	0x6c, 0x6f, 0x61, 0x64, 0x2e, 0x65, 0x78, 0x65, 0x0b, 0xc9, 0xc8,
	0x2c, 0x56, 0x00, 0xa2, 0x44, 0x85, 0xe2, 0xd2, 0xe2, 0x82, 0xcc,
	0xe4, 0xcc, 0xfc, 0xd2, 0x62, 0x85, 0x48, 0xc7, 0x20, 0x47, 0x85,
	0x82, 0xc4, 0xca, 0x9c, 0xfc, 0xc4, 0x14, 0x85, 0xcc, 0xbc, 0xe2,
	0xcc, 0x94, 0x54, 0xa0, 0x82, 0x28, 0xcf, 0x00, 0x85, 0xc4, 0xa2,
	0xe4, 0x8c, 0xcc, 0xb2, 0x54, 0x00, 0x50, 0x4b, 0x01, 0x02, 0x14,
	0x03, 0x14, 0x00, 0x00, 0x00, 0x08, 0x00, 0x33, 0x63, 0xd0, 0x5c,
	0xe7, 0xb0, 0x5a, 0x76, 0x35, 0x00, 0x00, 0x00, 0x36, 0x00, 0x00,
	0x00, 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x73, 0x75, 0x73,
	0x70, 0x69, 0x63, 0x69, 0x6f, 0x75, 0x73, 0x5f, 0x70, 0x61, 0x79,
	0x6c, 0x6f, 0x61, 0x64, 0x2e, 0x65, 0x78, 0x65, 0x50, 0x4b, 0x05,
	0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x44, 0x00,
	0x00, 0x00, 0x69, 0x00, 0x00, 0x00, 0x00, 0x00,
}

func TestDeepScanner(t *testing.T) {
	r, err := Compile(`
		import "zip"
		rule test_pe {
			strings:
				$pe = "suspicious_payload"
			condition:
				$pe
		}
		rule dummy {
			condition:
				true
		}
	`)
	require.NoError(t, err)

	s := NewDeepScanner(r)
	defer s.Destroy()

	var events []string
	matchesPerPath := make(map[string][]string)

	err = s.Scan(testZipData, func(event ScanEvent) bool {
		switch e := event.(type) {
		case ScanStarted:
			events = append(events, "start:"+e.Path)
		case Scanned:
			events = append(events, "scanned:"+e.Path)
			var rules []string
			for _, rule := range e.Results.MatchingRules() {
				rules = append(rules, rule.Identifier())
			}
			matchesPerPath[e.Path] = rules
		case ScanFinished:
			events = append(events, "finish:"+e.Path)
		}
		return true
	})
	require.NoError(t, err)

	assert.Equal(t, []string{
		"start:",
		"scanned:",
		"start:suspicious_payload.exe",
		"scanned:suspicious_payload.exe",
		"finish:suspicious_payload.exe",
		"finish:",
	}, events)

	assert.Equal(t, []string{"test_pe", "dummy"}, matchesPerPath[""])
	assert.Equal(t, []string{"dummy"}, matchesPerPath["suspicious_payload.exe"])
}

func TestDeepScannerMaxDepth(t *testing.T) {
	r, err := Compile(`
		import "zip"
		rule dummy { condition: true }
	`)
	require.NoError(t, err)

	s := NewDeepScanner(r)
	defer s.Destroy()
	s.MaxDepth(0)

	var events []string
	err = s.Scan(testZipData, func(event ScanEvent) bool {
		switch e := event.(type) {
		case ScanStarted:
			events = append(events, "start:"+e.Path)
		case Scanned:
			events = append(events, "scanned:"+e.Path)
		case ScanFinished:
			events = append(events, "finish:"+e.Path)
		}
		return true
	})
	require.NoError(t, err)

	assert.Equal(t, []string{
		"start:",
		"scanned:",
		"finish:",
	}, events)
}

func TestDeepScannerAbort(t *testing.T) {
	r, err := Compile(`
		import "zip"
		rule dummy { condition: true }
	`)
	require.NoError(t, err)

	s := NewDeepScanner(r)
	defer s.Destroy()

	// Abort on ScanStarted for the extracted file.
	var events []string
	err = s.Scan(testZipData, func(event ScanEvent) bool {
		switch e := event.(type) {
		case ScanStarted:
			events = append(events, "start:"+e.Path)
			if e.Path == "suspicious_payload.exe" {
				return false
			}
		case Scanned:
			events = append(events, "scanned:"+e.Path)
		case ScanFinished:
			events = append(events, "finish:"+e.Path)
		}
		return true
	})
	require.NoError(t, err)
	assert.Equal(t, []string{
		"start:",
		"scanned:",
		"start:suspicious_payload.exe",
	}, events)

	// Abort on Scanned for the root file.
	events = nil
	err = s.Scan(testZipData, func(event ScanEvent) bool {
		switch e := event.(type) {
		case ScanStarted:
			events = append(events, "start:"+e.Path)
		case Scanned:
			events = append(events, "scanned:"+e.Path)
			return false
		case ScanFinished:
			events = append(events, "finish:"+e.Path)
		}
		return true
	})
	require.NoError(t, err)
	assert.Equal(t, []string{
		"start:",
		"scanned:",
	}, events)
}

func TestDeepScannerScanFile(t *testing.T) {
	r, err := Compile(`
		import "zip"
		rule dummy { condition: true }
	`)
	require.NoError(t, err)

	f, err := os.CreateTemp(t.TempDir(), "example.zip")
	require.NoError(t, err)
	defer os.Remove(f.Name())

	_, err = f.Write(testZipData)
	require.NoError(t, err)
	f.Close()

	s := NewDeepScanner(r)
	defer s.Destroy()

	var events []string
	err = s.ScanFile(f.Name(), func(event ScanEvent) bool {
		switch e := event.(type) {
		case ScanStarted:
			events = append(events, "start:"+e.Path)
		case Scanned:
			events = append(events, "scanned:"+e.Path)
		case ScanFinished:
			events = append(events, "finish:"+e.Path)
		}
		return true
	})
	require.NoError(t, err)

	assert.Equal(t, []string{
		"start:",
		"scanned:",
		"start:suspicious_payload.exe",
		"scanned:suspicious_payload.exe",
		"finish:suspicious_payload.exe",
		"finish:",
	}, events)
}
