package yara_x

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNamespaces(t *testing.T) {
	c := NewCompiler()
	c.NewNamespace("foo")
	c.AddSource("rule test { condition: true }")
	c.NewNamespace("bar")
	c.AddSource("rule test { condition: true }")

	s := NewScanner(c.Build())
	matchingRules, _ := s.Scan([]byte{})

	assert.Len(t, matchingRules, 2)
}

func TestSerialization(t *testing.T) {
	c := NewCompiler()
	c.AddSource("rule test { condition: true }")
	b, _ := c.Build().Serialize()
	r, _ := Deserialize(b)

	s := NewScanner(r)
	matchingRules, _ := s.Scan([]byte{})

	assert.Len(t, matchingRules, 1)

	_, err := Deserialize(nil)
	assert.NoError(t, err)
}

func TestVariables(t *testing.T) {
	c := NewCompiler()

	c.DefineGlobalInt("var", 1234)
	c.AddSource("rule test { condition: var == 1234 }")
	matchingRules, _ := NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, matchingRules, 1)

	c.DefineGlobalInt("var", -1234)
	c.AddSource("rule test { condition: var == -1234 }")
	matchingRules, _ = NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, matchingRules, 1)

	c.DefineGlobalBool("var", true)
	c.AddSource("rule test { condition: var }")
	matchingRules, _ = NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, matchingRules, 1)

	c.DefineGlobalBool("var", false)
	c.AddSource("rule test { condition: var }")
	matchingRules, _ = NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, matchingRules, 0)

	c.DefineGlobalStr("var", "foo")
	c.AddSource("rule test { condition: var == \"foo\" }")
	matchingRules, _ = NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, matchingRules, 1)
}

func TestError(t *testing.T) {
	c := NewCompiler()
	err := c.AddSource("rule test { condition: foo }")
	assert.Error(t, err)
}
