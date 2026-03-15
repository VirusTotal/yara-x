package yara_x

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestScanner1(t *testing.T) {
	r, _ := Compile("rule t { condition: true }")
	s := NewScanner(r)
	scanResults, _ := s.Scan([]byte{})
	matchingRules := scanResults.MatchingRules()

	assert.Len(t, matchingRules, 1)
	assert.Equal(t, "t", matchingRules[0].Identifier())
	assert.Equal(t, "default", matchingRules[0].Namespace())
	assert.Len(t, matchingRules[0].Patterns(), 0)

	scanResults, _ = s.Scan(nil)
	matchingRules = scanResults.MatchingRules()

	assert.Len(t, matchingRules, 1)
	assert.Equal(t, "t", matchingRules[0].Identifier())
	assert.Equal(t, "default", matchingRules[0].Namespace())
	assert.Len(t, matchingRules[0].Patterns(), 0)
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

	s.Destroy()
	runtime.GC()
}

func TestScanner3(t *testing.T) {
	r, _ := Compile(
		`rule t { condition: var_bool }`,
		Globals(map[string]interface{}{"var_bool": true}))

	s := NewScanner(r)
	scanResults, _ := s.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)

	s.SetGlobal("var_bool", false)
	scanResults, _ = s.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 0)
}

func TestScanner4(t *testing.T) {
	r, _ := Compile(
		`rule t { condition: var_int == 1}`,
		Globals(map[string]interface{}{"var_int": 0}))

	s := NewScanner(r)
	scanResults, _ := s.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 0)

	assert.NoError(t, s.SetGlobal("var_int", 1))
	scanResults, _ = s.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)

	assert.NoError(t, s.SetGlobal("var_int", int32(1)))
	scanResults, _ = s.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)

	assert.NoError(t, s.SetGlobal("var_int", int64(1)))
	scanResults, _ = s.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)
}

func TestScanFile(t *testing.T) {
	r, _ := Compile(`rule t { strings: $bar = "bar" condition: $bar }`)
	s := NewScanner(r)

	// Create a temporary file with some content
	f, err := os.CreateTemp("", "example")
	assert.NoError(t, err)
	defer os.Remove(f.Name())

	_, err = f.Write([]byte("foobar"))
	assert.NoError(t, err)
	f.Close()

	scanResults, _ := s.ScanFile(f.Name())
	matchingRules := scanResults.MatchingRules()
	assert.Len(t, matchingRules, 1)
}

func TestScanReader(t *testing.T) {
	r, err := Compile(`rule t { strings: $bar = "bar" condition: $bar }`)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	scanResults, err := s.ScanReader(bytes.NewBufferString("foobar"))
	assert.NoError(t, err)
	assert.Len(t, scanResults.MatchingRules(), 1)

	scanResults, err = s.Scan([]byte("foobar"))
	assert.NoError(t, err)
	assert.Len(t, scanResults.MatchingRules(), 1)
}

func TestRulesScanReader(t *testing.T) {
	r, err := Compile(`rule t { strings: $foo = "foo" condition: $foo }`)
	assert.NoError(t, err)
	defer r.Destroy()

	results, err := r.ScanReader(bytes.NewBufferString("foo"))
	assert.NoError(t, err)
	assert.Len(t, results.MatchingRules(), 1)
}

func TestScanReaderAt(t *testing.T) {
	r, err := Compile(`rule t { strings: $bar = "bar" condition: $bar }`)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	scanResults, err := s.ScanReaderAt(bytes.NewReader([]byte("foobar")), int64(len("foobar")))
	assert.NoError(t, err)
	assert.Len(t, scanResults.MatchingRules(), 1)
}

func TestRulesScanReaderAt(t *testing.T) {
	r, err := Compile(`rule t { strings: $foo = "foo" condition: $foo }`)
	assert.NoError(t, err)
	defer r.Destroy()

	results, err := r.ScanReaderAt(bytes.NewReader([]byte("foo")), int64(len("foo")))
	assert.NoError(t, err)
	assert.Len(t, results.MatchingRules(), 1)
}

func TestScanReaderAtRejectsNegativeSize(t *testing.T) {
	r, err := Compile(`rule t { condition: true }`)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	results, err := s.ScanReaderAt(bytes.NewReader(nil), -1)
	assert.Error(t, err)
	assert.Nil(t, results)
}

func TestScanReaderGlobals(t *testing.T) {
	r, err := Compile(
		`rule t { condition: var_bool }`,
		Globals(map[string]interface{}{"var_bool": false}),
	)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	assert.NoError(t, s.SetGlobal("var_bool", true))

	results, err := s.ScanReader(bytes.NewBufferString("ignored"))
	assert.NoError(t, err)
	assert.Len(t, results.MatchingRules(), 1)
}

func TestScanReaderGlobalsAllSupportedTypes(t *testing.T) {
	r, err := Compile(
		`rule t_string { condition: var_string == "foo" }
		 rule t_float { condition: var_float == 1.5 }
		 rule t_map { condition: var_map.answer == 42 }
		 rule t_array { condition: var_array[0] == "x" }`,
		Globals(map[string]interface{}{
			"var_string": "",
			"var_float":  0.0,
			"var_map":    map[string]interface{}{"answer": 0},
			"var_array":  []interface{}{"y"},
		}),
	)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	assert.NoError(t, s.SetGlobal("var_string", "foo"))
	assert.NoError(t, s.SetGlobal("var_float", 1.5))
	assert.NoError(t, s.SetGlobal("var_map", map[string]interface{}{"answer": 42}))
	assert.NoError(t, s.SetGlobal("var_array", []interface{}{"x"}))

	results, err := s.ScanReader(bytes.NewBuffer(nil))
	assert.NoError(t, err)
	assert.Len(t, results.MatchingRules(), 4)
}

func TestScannerTimeout(t *testing.T) {
	r, _ := Compile("rule t { strings: $a = /a(.*)*a/ condition: $a }")
	s := NewScanner(r)
	s.SetTimeout(time.Nanosecond)
	_, err := s.Scan(bytes.Repeat([]byte("a"), 10000))
	assert.ErrorIs(t, err, ErrTimeout)
}

func TestScannerTimeoutDoesNotShortCircuitFastScans(t *testing.T) {
	r, _ := Compile(`rule t { condition: true }`)
	s := NewScanner(r)
	s.SetTimeout(time.Second)

	results, err := s.Scan([]byte{})
	assert.NoError(t, err)
	assert.Len(t, results.MatchingRules(), 1)
}

func TestScanReaderTimeout(t *testing.T) {
	r, _ := Compile("rule t { strings: $a = /a(.*)*a/ condition: $a }")
	s := NewScanner(r)
	s.SetTimeout(time.Nanosecond)
	_, err := s.ScanReader(bytes.NewReader(bytes.Repeat([]byte("a"), 10000)))
	assert.ErrorIs(t, err, ErrTimeout)
}

func TestScanFileTimeoutDoesNotMaskErrors(t *testing.T) {
	r, _ := Compile(`rule t { condition: true }`)
	s := NewScanner(r)
	s.SetTimeout(time.Second)

	results, err := s.ScanFile("/definitely/missing/file")
	assert.Error(t, err)
	assert.NotErrorIs(t, err, ErrTimeout)
	assert.Empty(t, results.MatchingRules())
}

func TestScanReaderRejectsImportedModules(t *testing.T) {
	r, err := Compile(`
		import "pe"
		rule t { condition: true }
	`)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	results, err := s.ScanReader(bytes.NewBuffer(nil))
	assert.ErrorIs(t, err, errScanReaderModulesUnsupported)
	assert.Empty(t, results.MatchingRules())
}

func TestScannerSetModuleOutputUnknownModule(t *testing.T) {
	r, err := Compile(`rule t { condition: true }`)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	err = s.SetModuleOutput(&emptypb.Empty{})
	assert.Error(t, err)
	assert.ErrorContains(t, err, "unknown module")
}

func TestScannerProfilingAPIs(t *testing.T) {
	r, err := Compile(`rule t { strings: $a = "foo" condition: $a }`)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	results, err := s.Scan([]byte("foo"))
	assert.NoError(t, err)
	assert.Len(t, results.MatchingRules(), 1)

	var slowest []ProfilingInfo
	slowestPanic := captureScannerPanic(func() {
		slowest = s.SlowestRules(1)
	})
	if os.Getenv("YARAX_REQUIRE_PROFILING") != "" {
		assert.Nil(t, slowestPanic)
	}
	if slowestPanic != nil {
		assert.Contains(t, fmt.Sprint(slowestPanic), "requires that the YARA-X guest is built with rules profiling support")
	} else {
		assert.LessOrEqual(t, len(slowest), 1)
	}

	clearPanic := captureScannerPanic(func() {
		s.ClearProfilingData()
	})
	if os.Getenv("YARAX_REQUIRE_PROFILING") != "" {
		assert.Nil(t, clearPanic)
	}
	if clearPanic != nil {
		assert.Contains(t, fmt.Sprint(clearPanic), "requires that the YARA-X guest is built with rules profiling support")
	}
}

func TestScannerProfilingEnabledWithOverride(t *testing.T) {
	if os.Getenv("YARAX_REQUIRE_PROFILING") == "" {
		t.Skip("set YARAX_REQUIRE_PROFILING=1 with YARAX_GUEST_WASM pointing to a profiling guest")
	}

	r, err := Compile(`
		rule slow {
			condition:
				for any i in (0..1000000) : (
					uint8(i) == 0xCC
				)
		}
	`)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	for range 8 {
		results, err := s.Scan([]byte("foobar"))
		assert.NoError(t, err)
		assert.Empty(t, results.MatchingRules())
	}

	slowest := s.SlowestRules(10)
	if len(slowest) > 0 {
		assert.Equal(t, "default", slowest[0].Namespace)
		assert.Equal(t, "slow", slowest[0].Rule)
		assert.GreaterOrEqual(t, slowest[0].ConditionExecTime, time.Duration(0))
		assert.GreaterOrEqual(t, slowest[0].PatternMatchingTime, time.Duration(0))
	}

	s.ClearProfilingData()
	assert.NotPanics(t, func() { _ = s.SlowestRules(10) })
}

func captureScannerPanic(fn func()) (message interface{}) {
	defer func() {
		if r := recover(); r != nil {
			message = r
		}
	}()
	fn()
	return
}

func TestRulesAndResultZeroValueAPIs(t *testing.T) {
	var rules *Rules
	assert.Equal(t, 0, rules.Count())
	assert.Empty(t, rules.Imports())
	assert.Empty(t, rules.Slice())

	_, err := rules.WriteTo(bytes.NewBuffer(nil))
	assert.EqualError(t, err, "rules object is destroyed")

	var rule *Rule
	assert.Empty(t, rule.Tags())
	assert.Empty(t, rule.Metadata())
	assert.Empty(t, rule.Patterns())

	var pattern *Pattern
	assert.Empty(t, pattern.Matches())
}

func TestCallbackArgsDoNotLeakGuestMemory(t *testing.T) {
	r, err := Compile(`rule t { strings: $a = "foo" condition: $a }`)
	assert.NoError(t, err)
	defer r.Destroy()

	s := NewScanner(r)
	defer s.Destroy()

	for i := 0; i < 128; i++ {
		results, err := s.Scan([]byte("foo"))
		assert.NoError(t, err)
		assert.Len(t, results.MatchingRules(), 1)
	}

	sizeAfterWarmup := s.client.guest.Memory().Size()

	for i := 0; i < 2048; i++ {
		results, err := s.Scan([]byte("foo"))
		assert.NoError(t, err)
		assert.Len(t, results.MatchingRules(), 1)
	}

	sizeAfterPhaseOne := s.client.guest.Memory().Size()

	for i := 0; i < 2048; i++ {
		results, err := s.Scan([]byte("foo"))
		assert.NoError(t, err)
		assert.Len(t, results.MatchingRules(), 1)
	}

	sizeAfterPhaseTwo := s.client.guest.Memory().Size()

	assert.GreaterOrEqual(t, sizeAfterPhaseOne, sizeAfterWarmup)
	assert.Equal(t, sizeAfterPhaseOne, sizeAfterPhaseTwo)
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

func BenchmarkNewScanner(b *testing.B) {
	rules, _ := Compile(`rule t { strings: $foo = "foo" condition: $foo }`)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		scanner := NewScanner(rules)
		scanner.Destroy()
	}
}

func BenchmarkRulesScan(b *testing.B) {
	rules, _ := Compile(`rule t { strings: $foo = "foo" condition: $foo }`)
	data := []byte("foo")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		results, _ := rules.Scan(data)
		for _, rule := range results.MatchingRules() {
			_ = rule.Identifier()
		}
	}
}

func BenchmarkReadFrom(b *testing.B) {
	rules, _ := Compile(`rule t { condition: true }`)

	var buf bytes.Buffer
	_, _ = rules.WriteTo(&buf)
	serialized := buf.Bytes()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		loaded, _ := ReadFrom(bytes.NewReader(serialized))
		loaded.Destroy()
	}
}
