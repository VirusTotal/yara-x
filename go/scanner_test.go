package yara_x

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"runtime"
	"testing"
	"time"
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