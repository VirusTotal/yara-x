package yara_x

import (
	"bytes"
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

func TestBannedModules(t *testing.T) {
	_, err := Compile(
		`import "pe"`,
		BanModule("pe", "pe module is banned", "pe module was used here"))

	expected := `error[E100]: pe module is banned
 --> line:1:1
  |
1 | import "pe"
  | ^^^^^^^^^^^ pe module was used here
  |`
	assert.EqualError(t, err, expected)
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

func TestErrorOnSlowLoop(t *testing.T) {
	_, err := Compile(`
		rule test { condition: for all x in (0..filesize): (x == 0) }`,
		ErrorOnSlowLoop(true))
	assert.Error(t, err)
}

func TestSerialization(t *testing.T) {
	r, err := Compile("rule test { condition: true }")
	assert.NoError(t, err)

	var buf bytes.Buffer

	// Write rules into buffer
	n, err := r.WriteTo(&buf)

	assert.NoError(t, err)
	assert.Len(t, buf.Bytes(), int(n))

	// Read rules from buffer
	r, _ = ReadFrom(&buf)

	// Make sure the rules work properly.
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

func TestErrors(t *testing.T) {
	c, err := NewCompiler()
	assert.NoError(t, err)

	c.AddSource("rule test_1 { condition: true }")
	assert.Equal(t, []CompileError{}, c.Errors())

	assert.Equal(t, []Warning{
		{
			Code:   "invariant_expr",
			Title:  "invariant boolean expression",
			Line:   1,
			Column: 26,
			Labels: []Label{
				{
					Level:  "warning",
					Line:   1,
					Column: 26,
					Span:   Span{Start: 25, End: 29},
					Text:   "this expression is always true",
				},
			},
			Footers: []Footer{
				{
					Level: "note",
					Text:  "rule `test_1` is always `true`",
				},
			},
			Text: `warning[invariant_expr]: invariant boolean expression
 --> line:1:26
  |
1 | rule test_1 { condition: true }
  |                          ---- this expression is always true
  |
  = note: rule ` + "`test_1` is always `true`",
		},
	}, c.Warnings())

	c.AddSource("rule test_2 { condition: foo }", WithOrigin("test.yar"))
	assert.Equal(t, []CompileError{
		{
			Code:   "E009",
			Title:  "unknown identifier `foo`",
			Line:   1,
			Column: 26,
			Labels: []Label{
				{
					Level:      "error",
					CodeOrigin: "test.yar",
					Line:       1,
					Column:     26,
					Span:       Span{Start: 25, End: 28},
					Text:       "this identifier has not been declared",
				},
			},
			Footers: []Footer{},
			Text: `error[E009]: unknown identifier ` + "`foo`" + `
 --> test.yar:1:26
  |
1 | rule test_2 { condition: foo }
  |                          ^^^ this identifier has not been declared
  |`,
		},
	}, c.Errors())
}

func TestRules(t *testing.T) {
	c, err := NewCompiler()
	assert.NoError(t, err)

	c.AddSource(`rule test_1 {
      condition:
        true
	}`)
	assert.NoError(t, err)

	c.AddSource(`rule test_2 {
      meta:
        foo = "foo"
        bar = 1
        baz = "\x00\x01"
        qux = true
      condition:
        true
	}`)
	assert.NoError(t, err)

	rules := c.Build()
	assert.Equal(t, 2, rules.Count())

	slice := rules.Slice()
	assert.Len(t, slice, 2)
	assert.Equal(t, "test_1", slice[0].Identifier())
	assert.Equal(t, "test_2", slice[1].Identifier())

	assert.Equal(t, "default", slice[0].Namespace())
	assert.Equal(t, "default", slice[1].Namespace())

	assert.Len(t, slice[0].Metadata(), 0)
	assert.Len(t, slice[1].Metadata(), 4)

	assert.Equal(t, "foo", slice[1].Metadata()[0].Identifier())
	assert.Equal(t, "foo", slice[1].Metadata()[0].Value().(string))

	assert.Equal(t, "bar", slice[1].Metadata()[1].Identifier())
	assert.Equal(t, int64(1), slice[1].Metadata()[1].Value().(int64))

	assert.Equal(t, "baz", slice[1].Metadata()[2].Identifier())
	assert.Equal(t, []byte{0x00, 0x01}, slice[1].Metadata()[2].Value().([]byte))

	assert.Equal(t, "qux", slice[1].Metadata()[3].Identifier())
	assert.Equal(t, true, slice[1].Metadata()[3].Value().(bool))
}

func TestImportsIter(t *testing.T) {
	c, err := NewCompiler()
	assert.NoError(t, err)

	c.AddSource(`
	import "pe"
	import "elf"
	rule test {
			condition:
				true
	}`)
	assert.NoError(t, err)

	rules := c.Build()
	imports := rules.Imports()

	assert.Len(t, imports, 2)
	assert.Equal(t, "pe", imports[0])
	assert.Equal(t, "elf", imports[1])
}

func TestWarnings(t *testing.T) {
	c, err := NewCompiler()
	assert.NoError(t, err)

	c.AddSource("rule test { strings: $a = {01 [0-1][0-1] 02 } condition: $a }")

	assert.Equal(t, []Warning{
		{
			Code:   "consecutive_jumps",
			Title:  "consecutive jumps in hex pattern `$a`",
			Line:   1,
			Column: 31,
			Labels: []Label{
				{
					Level:      "warning",
					CodeOrigin: "",
					Line:       1,
					Column:     31,
					Span:       Span{Start: 30, End: 40},
					Text:       "these consecutive jumps will be treated as [0-2]",
				},
			},
			Footers: []Footer{},
			Text: `warning[consecutive_jumps]: consecutive jumps in hex pattern ` + "`$a`" + `
 --> line:1:31
  |
1 | rule test { strings: $a = {01 [0-1][0-1] 02 } condition: $a }
  |                               ---------- these consecutive jumps will be treated as [0-2]
  |`,
		},
		{
			Code:   "slow_pattern",
			Title:  "slow pattern",
			Line:   1,
			Column: 22,
			Labels: []Label{
				{
					Level:      "warning",
					CodeOrigin: "",
					Line:       1,
					Column:     22,
					Span:       Span{Start: 21, End: 43},
					Text:       "this pattern may slow down the scan",
				},
			},
			Footers: []Footer{},
			Text: `warning[slow_pattern]: slow pattern
 --> line:1:22
  |
1 | rule test { strings: $a = {01 [0-1][0-1] 02 } condition: $a }
  |                      ---------------------- this pattern may slow down the scan
  |`,
		},
	}, c.Warnings())
}
