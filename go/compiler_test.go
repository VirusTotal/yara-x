package yara_x

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNamespaces(t *testing.T) {
	c, err := NewCompiler()
	assert.NoError(t, err)

	c.NewNamespace("foo")
	c.AddSource("rule test { condition: true }")
	c.NewNamespace("bar")
	c.AddSource("rule test { condition: true }")

	s := NewScanner(c.Build())
	matchingRules, _ := s.Scan([]byte{})
	assert.Len(t, matchingRules, 2)
}

func TestUnsupportedModules(t *testing.T) {
	r, err := Compile(`
		import "unsupported_module"
		rule test { condition: true }`,
		IgnoreModule("unsupported_module"))

	assert.NoError(t, err)
	matchingRules, _ := r.Scan([]byte{})
	assert.Len(t, matchingRules, 1)
}

func TestRelaxedReSyntax(t *testing.T) {
	r, err := Compile(`
		rule test { strings: $a = /\Release/ condition: $a }`,
		RelaxedReSyntax(true))
	assert.NoError(t, err)
	matchingRules, _ := r.Scan([]byte("Release"))
	assert.Len(t, matchingRules, 1)
}


func TestErrorOnSlowPattern(t *testing.T) {
	_, err := Compile(`
		rule test { strings: $a = /a.*/ condition: $a }`,
		ErrorOnSlowPattern(true))
	assert.Error(t, err)
}

func TestSerialization(t *testing.T) {
	r, err := Compile("rule test { condition: true }")
	assert.NoError(t, err)

	b, _ := r.Serialize()
	r, _ = Deserialize(b)

	s := NewScanner(r)
	matchingRules, _ := s.Scan([]byte{})

	assert.Len(t, matchingRules, 1)
}

func TestVariables(t *testing.T) {
	r, _ := Compile(
		"rule test { condition: var == 1234 }",
		Globals(map[string]interface{}{"var": 1234}))

	matchingRules, _ := NewScanner(r).Scan([]byte{})
	assert.Len(t, matchingRules, 1)

	c, err := NewCompiler()
	assert.NoError(t, err)

	c.DefineGlobal("var", 1234)
	c.AddSource("rule test { condition: var == 1234 }")
	matchingRules, _ = NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, matchingRules, 1)

	c.DefineGlobal("var", -1234)
	c.AddSource("rule test { condition: var == -1234 }")
	matchingRules, _ = NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, matchingRules, 1)

	c.DefineGlobal("var", true)
	c.AddSource("rule test { condition: var }")
	matchingRules, _ = NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, matchingRules, 1)

	c.DefineGlobal("var", false)
	c.AddSource("rule test { condition: var }")
	matchingRules, _ = NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, matchingRules, 0)

	c.DefineGlobal("var", "foo")
	c.AddSource("rule test { condition: var == \"foo\" }")
	matchingRules, _ = NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, matchingRules, 1)

	c.DefineGlobal("var", 3.4)
	c.AddSource("rule test { condition: var == 3.4 }")
	matchingRules, _ = NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, matchingRules, 1)

	err = c.DefineGlobal("var", struct{}{})
	assert.EqualError(t, err, "variable `var` has unsupported type: struct {}")
}

func TestError(t *testing.T) {
	_, err := Compile("rule test { condition: foo }")
	assert.EqualError(t, err, `error[E107]: unknown identifier `+"`foo`"+`
 --> line:1:24
  |
1 | rule test { condition: foo }
  |                        ^^^ this identifier has not been declared
  |`)
}
