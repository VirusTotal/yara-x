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
	scanResults, _ := s.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 2)
}

func TestUnsupportedModules(t *testing.T) {
	r, err := Compile(`
		import "unsupported_module"
		rule test { condition: true }`,
		IgnoreModule("unsupported_module"))

	assert.NoError(t, err)
	scanResults, _ := r.Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)
}

func TestRelaxedReSyntax(t *testing.T) {
	r, err := Compile(`
		rule test { strings: $a = /\Release/ condition: $a }`,
		RelaxedReSyntax(true))
	assert.NoError(t, err)
	scanResults, _ := r.Scan([]byte("Release"))
	assert.Len(t, scanResults.MatchingRules(), 1)
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
	scanResults, _ := s.Scan([]byte{})

	assert.Len(t, scanResults.MatchingRules(), 1)
}

func TestVariables(t *testing.T) {
	r, _ := Compile(
		"rule test { condition: var == 1234 }",
		Globals(map[string]interface{}{"var": 1234}))

	scanResults, _ := NewScanner(r).Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)

	c, err := NewCompiler()
	assert.NoError(t, err)

	c.DefineGlobal("var", 1234)
	c.AddSource("rule test { condition: var == 1234 }")
	scanResults, _ = NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)

	c.DefineGlobal("var", -1234)
	c.AddSource("rule test { condition: var == -1234 }")
	scanResults, _ = NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)

	c.DefineGlobal("var", true)
	c.AddSource("rule test { condition: var }")
	scanResults, _ = NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)

	c.DefineGlobal("var", false)
	c.AddSource("rule test { condition: var }")
	scanResults, _ = NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 0)

	c.DefineGlobal("var", "foo")
	c.AddSource("rule test { condition: var == \"foo\" }")
	scanResults, _ = NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)

	c.DefineGlobal("var", 3.4)
	c.AddSource("rule test { condition: var == 3.4 }")
	scanResults, _ = NewScanner(c.Build()).Scan([]byte{})
	assert.Len(t, scanResults.MatchingRules(), 1)

	err = c.DefineGlobal("var", struct{}{})
	assert.EqualError(t, err, "variable `var` has unsupported type: struct {}")
}

func TestError(t *testing.T) {
	_, err := Compile("rule test { condition: foo }")
	expected := `error[E009]: unknown identifier ` + "`foo`" + `
 --> line:1:24
  |
1 | rule test { condition: foo }
  |                        ^^^ this identifier has not been declared
  |`
	assert.EqualError(t, err, expected)
}

func TestCompilerFeatures(t *testing.T) {
	rules := `import "test_proto2" rule test { condition: test_proto2.requires_foo_and_bar }`

  _, err := Compile(rules)
	assert.EqualError(t, err, `error[E034]: foo is required
 --> line:1:57
  |
1 | import "test_proto2" rule test { condition: test_proto2.requires_foo_and_bar }
  |                                                         ^^^^^^^^^^^^^^^^^^^^ this field was used without foo
  |`)

  _, err = Compile(rules, WithFeature("foo"))
  assert.EqualError(t, err, `error[E034]: bar is required
 --> line:1:57
  |
1 | import "test_proto2" rule test { condition: test_proto2.requires_foo_and_bar }
  |                                                         ^^^^^^^^^^^^^^^^^^^^ this field was used without bar
  |`)

  _, err = Compile(rules, WithFeature("foo"), WithFeature("bar"))
  assert.NoError(t, err)
}

func TestErrors(t *testing.T) {
	c, err := NewCompiler()
	assert.NoError(t, err)

	c.AddSource("rule test_1 { condition: true }")
	assert.Equal(t, []CompileError{}, c.Errors())

	c.AddSource("rule test_2 { condition: foo }", WithOrigin("test.yar"))
	assert.Equal(t, []CompileError{
		{
			Code:  "E009",
			Title: "unknown identifier `foo`",
			Labels: []Label{
				{
					Level:      "error",
					CodeOrigin: "test.yar",
					Span:       Span{Start: 25, End: 28},
					Text:       "this identifier has not been declared",
				},
			},
			Text: `error[E009]: unknown identifier ` + "`foo`" + `
 --> test.yar:1:26
  |
1 | rule test_2 { condition: foo }
  |                          ^^^ this identifier has not been declared
  |`,
		},
	}, c.Errors())
}

func TestWarnings(t *testing.T) {
	c, err := NewCompiler()
	assert.NoError(t, err)

	c.AddSource("rule test { strings: $a = {01 [0-1][0-1] 02 } condition: $a }")

	assert.Equal(t, []Warning{
		{
			Code:  "consecutive_jumps",
			Title: "consecutive jumps in hex pattern `$a`",
			Labels: []Label{
				{
					Level:      "warning",
					CodeOrigin: "",
					Span:       Span{Start: 30, End: 40},
					Text:       "these consecutive jumps will be treated as [0-2]",
				},
			},
			Text: `warning[consecutive_jumps]: consecutive jumps in hex pattern ` + "`$a`" + `
 --> line:1:31
  |
1 | rule test { strings: $a = {01 [0-1][0-1] 02 } condition: $a }
  |                               ---------- these consecutive jumps will be treated as [0-2]
  |`,
		},
		{
			Code:  "slow_pattern",
			Title: "slow pattern",
			Labels: []Label{
				{
					Level:      "warning",
					CodeOrigin: "",
					Span:       Span{Start: 21, End: 43},
					Text:       "this pattern may slow down the scan",
				},
			},
			Text: `warning[slow_pattern]: slow pattern
 --> line:1:22
  |
1 | rule test { strings: $a = {01 [0-1][0-1] 02 } condition: $a }
  |                      ---------------------- this pattern may slow down the scan
  |`,
		},
	}, c.Warnings())
}
