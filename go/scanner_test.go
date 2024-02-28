package yara_x

import (
	"bytes"
	"runtime"
	"testing"
	"time"
)
import "github.com/stretchr/testify/assert"

func TestScanner1(t *testing.T) {
	r, _ := Compile("rule t { condition: true }")
	s := NewScanner(r)
	matchingRules, _:= s.Scan([]byte{})

	assert.Len(t, matchingRules, 1)
	assert.Equal(t, "t", matchingRules[0].Identifier())
	assert.Equal(t, "default", matchingRules[0].Namespace())
	assert.Len(t, matchingRules[0].Patterns(), 0)
}

func TestScanner2(t *testing.T) {
	r, _ := Compile(`rule t { strings: $bar = "bar" condition: $bar }`)
	s := NewScanner(r)
	matchingRules, _ := s.Scan([]byte("foobar"))

	assert.Len(t, matchingRules, 1)
	assert.Equal(t, "t", matchingRules[0].Identifier())
	assert.Equal(t, "default", matchingRules[0].Namespace())

	assert.Len(t, matchingRules[0].Patterns(), 1)
	assert.Equal(t, "$bar", matchingRules[0].Patterns()[0].Identifier())
	assert.Equal(t, uint(3), matchingRules[0].Patterns()[0].Matches()[0].Offset())
	assert.Equal(t, uint(3), matchingRules[0].Patterns()[0].Matches()[0].Length())

	s.Destroy()
	runtime.GC()
}

func TestScanner3(t *testing.T) {
	r, _ := Compile(
		`rule t { condition: var_bool }`,
		GlobalVars(map[string]interface{}{"var_bool": true}))

	s := NewScanner(r)
	matchingRules, _ := s.Scan([]byte{})
	assert.Len(t, matchingRules, 1)

	s.SetGlobal("var_bool", false)
	matchingRules, _ = s.Scan([]byte{})
	assert.Len(t, matchingRules, 0)
}

func TestScannerTimeout(t *testing.T) {
	r, _ := Compile("rule t { strings: $a = /a(.*)*a/ condition: $a }")
	s := NewScanner(r)
	s.Timeout(1*time.Second)
	_, err := s.Scan(bytes.Repeat([]byte("a"), 9000))
	assert.ErrorIs(t, err, ErrTimeout)
}