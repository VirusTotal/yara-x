package yara_x

import "testing"
import "github.com/stretchr/testify/assert"


func TestScanner1(t *testing.T) {
	s := NewScanner(Compile("rule t { condition: true }"))
	matchingRules := s.Scan([]byte{})

	assert.Len(t, matchingRules, 1)
	assert.Equal(t, "t", matchingRules[0].Identifier())
	assert.Equal(t, "default", matchingRules[0].Namespace())
	assert.Len(t, matchingRules[0].Patterns(), 0)
}

func TestScanner2(t *testing.T) {
	s := NewScanner(Compile(`rule t { strings: $bar = "bar" condition: $bar }`))
	matchingRules := s.Scan([]byte("foobar"))

	assert.Len(t, matchingRules, 1)
	assert.Equal(t, "t", matchingRules[0].Identifier())
	assert.Equal(t, "default", matchingRules[0].Namespace())

	assert.Len(t, matchingRules[0].Patterns(), 1)
	assert.Equal(t, "$bar", matchingRules[0].Patterns()[0].Identifier())
	assert.Equal(t, uint(3), matchingRules[0].Patterns()[0].Matches()[0].Offset())
	assert.Equal(t, uint(3), matchingRules[0].Patterns()[0].Matches()[0].Length())
}