package benchcmp

import (
	"bytes"
	"sync"
	"testing"

	wasmbind "yaraxwasm"

	cgobind "github.com/VirusTotal/yara-x/go"
)

const compareRule = `rule t : primary fast {
		meta:
			some_int = 1
			some_float = 2.3034
			some_bool = true
			some_string = "hello"
			some_bytes = "\x00\x01\x02"
		strings:
			$foo = "foo"
			$bar = "bar"
			$baz = "baz"
			$a = "a"
			$b = "b"
			$c = "c"
			$d = "d"
		condition:
			any of them
}

rule u : alpha beta {
		meta:
			name = "secondary"
			enabled = true
			weight = 42
		strings:
			$foo = "foo"
			$abc = "abc"
			$abd = "abd"
			$bc = "bc"
		condition:
			2 of them
}`

var (
	compareData   = []byte("foobarbazabcd")
	benchmarkSink uint64
	wasmInitOnce  sync.Once
	errWASMInit   error
)

func ensureWASMInitialised(tb testing.TB) {
	tb.Helper()
	wasmInitOnce.Do(func() {
		errWASMInit = wasmbind.Initialise()
	})
	if errWASMInit != nil {
		tb.Fatalf("initialise wasm bindings: %v", errWASMInit)
	}
}

func mustCGORules(tb testing.TB) *cgobind.Rules {
	tb.Helper()
	rules, err := cgobind.Compile(compareRule)
	if err != nil {
		tb.Fatalf("compile cgo rules: %v", err)
	}
	return rules
}

func mustWASMRules(tb testing.TB) *wasmbind.Rules {
	tb.Helper()
	ensureWASMInitialised(tb)
	rules, err := wasmbind.Compile(compareRule)
	if err != nil {
		tb.Fatalf("compile wasm rules: %v", err)
	}
	return rules
}

func consumeCGOResults(tb testing.TB, results *cgobind.ScanResults, err error) {
	tb.Helper()
	if err != nil {
		tb.Fatalf("scan failed: %v", err)
	}
	for _, rule := range results.MatchingRules() {
		consumeCGORule(rule)
	}
}

func consumeWASMResults(tb testing.TB, results *wasmbind.ScanResults, err error) {
	tb.Helper()
	if err != nil {
		tb.Fatalf("scan failed: %v", err)
	}
	for _, rule := range results.MatchingRules() {
		consumeWASMRule(rule)
	}
}

func consumeCGORule(rule *cgobind.Rule) {
	benchmarkSink += uint64(len(rule.Identifier()))
	benchmarkSink += uint64(len(rule.Namespace()))

	for _, tag := range rule.Tags() {
		benchmarkSink += uint64(len(tag))
	}

	for _, metadata := range rule.Metadata() {
		benchmarkSink += uint64(len(metadata.Identifier()))
		benchmarkSink += consumeMetadataValue(metadata.Value())
	}

	for _, pattern := range rule.Patterns() {
		benchmarkSink += uint64(len(pattern.Identifier()))
		for _, match := range pattern.Matches() {
			benchmarkSink += match.Offset()
			benchmarkSink += match.Length()
		}
	}
}

func consumeWASMRule(rule *wasmbind.Rule) {
	benchmarkSink += uint64(len(rule.Identifier()))
	benchmarkSink += uint64(len(rule.Namespace()))

	for _, tag := range rule.Tags() {
		benchmarkSink += uint64(len(tag))
	}

	for _, metadata := range rule.Metadata() {
		benchmarkSink += uint64(len(metadata.Identifier()))
		benchmarkSink += consumeMetadataValue(metadata.Value())
	}

	for _, pattern := range rule.Patterns() {
		benchmarkSink += uint64(len(pattern.Identifier()))
		for _, match := range pattern.Matches() {
			benchmarkSink += match.Offset()
			benchmarkSink += match.Length()
		}
	}
}

func consumeMetadataValue(value interface{}) uint64 {
	switch v := value.(type) {
	case int:
		return uint64(v)
	case int32:
		return uint64(v)
	case int64:
		return uint64(v)
	case uint:
		return uint64(v)
	case uint32:
		return uint64(v)
	case uint64:
		return v
	case float32:
		return uint64(v * 1000)
	case float64:
		return uint64(v * 1000)
	case bool:
		if v {
			return 1
		}
		return 0
	case string:
		return uint64(len(v))
	case []byte:
		sum := uint64(len(v))
		for _, b := range v {
			sum += uint64(b)
		}
		return sum
	default:
		return 0
	}
}

func BenchmarkCGOScanReuseScanner(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	rules := mustCGORules(b)
	defer rules.Destroy()
	scanner := cgobind.NewScanner(rules)
	defer scanner.Destroy()
	b.SetBytes(int64(len(compareData)))
	b.ResetTimer()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		results, err := scanner.Scan(compareData)
		consumeCGOResults(b, results, err)
	}
}

func BenchmarkWASMScanReuseScanner(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	rules := mustWASMRules(b)
	defer rules.Destroy()
	scanner := wasmbind.NewScanner(rules)
	defer scanner.Destroy()
	b.SetBytes(int64(len(compareData)))
	b.ResetTimer()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		results, err := scanner.Scan(compareData)
		consumeWASMResults(b, results, err)
	}
}

func BenchmarkCGONewScanner(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	rules := mustCGORules(b)
	defer rules.Destroy()
	b.ResetTimer()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		scanner := cgobind.NewScanner(rules)
		scanner.Destroy()
	}
}

func BenchmarkWASMNewScanner(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	rules := mustWASMRules(b)
	defer rules.Destroy()
	b.ResetTimer()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		scanner := wasmbind.NewScanner(rules)
		scanner.Destroy()
	}
}

func BenchmarkCGORulesScan(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	rules := mustCGORules(b)
	defer rules.Destroy()
	b.SetBytes(int64(len(compareData)))
	b.ResetTimer()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		results, err := rules.Scan(compareData)
		consumeCGOResults(b, results, err)
	}
}

func BenchmarkWASMRulesScan(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	rules := mustWASMRules(b)
	defer rules.Destroy()
	b.SetBytes(int64(len(compareData)))
	b.ResetTimer()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		results, err := rules.Scan(compareData)
		consumeWASMResults(b, results, err)
	}
}

func BenchmarkCGOReadFrom(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	rules := mustCGORules(b)
	defer rules.Destroy()
	var buf bytes.Buffer
	if _, err := rules.WriteTo(&buf); err != nil {
		b.Fatalf("serialize cgo rules: %v", err)
	}
	serialized := append([]byte(nil), buf.Bytes()...)
	b.ResetTimer()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		loaded, err := cgobind.ReadFrom(bytes.NewReader(serialized))
		if err != nil {
			b.Fatalf("read cgo rules: %v", err)
		}
		loaded.Destroy()
	}
}

func BenchmarkWASMReadFrom(b *testing.B) {
	b.ReportAllocs()
	b.StopTimer()
	rules := mustWASMRules(b)
	defer rules.Destroy()
	var buf bytes.Buffer
	if _, err := rules.WriteTo(&buf); err != nil {
		b.Fatalf("serialize wasm rules: %v", err)
	}
	serialized := append([]byte(nil), buf.Bytes()...)
	b.ResetTimer()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		loaded, err := wasmbind.ReadFrom(bytes.NewReader(serialized))
		if err != nil {
			b.Fatalf("read wasm rules: %v", err)
		}
		loaded.Destroy()
	}
}
