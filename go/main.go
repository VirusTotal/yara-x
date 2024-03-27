// Package yara_x provides Go bindings to the YARA-X library.
package yara_x

// #cgo !static_link pkg-config: yara_x_capi 
// #cgo static_link pkg-config: --static yara_x_capi
// #import <yara-x.h>
import "C"
import (
	"errors"
	"runtime"
	"unsafe"
)

// A CompileOption represent an option passed to [Compile].
type CompileOption func(c *Compiler) error

// Globals is an option for [Compile] that allows defining global variables.
//
// Keys in the map are variable names, and values are the initial value for
// each variable. The value associated to each variable can be modified at
// scan time with [Scanner.SetGlobal].
//
// Valid value types are: int, int32, int64, bool, string, float32 and float64.
func Globals(vars map[string]interface{}) CompileOption {
	return func(c *Compiler) error {
		for ident, value := range vars {
			if err := c.DefineGlobal(ident, value); err != nil {
				return err
			}
		}
		return nil
	}
}

// IgnoreModule is an option for [Compile] that allows ignoring a given module.
//
// This option can be passed multiple times with different module names.
// See [Compiler.IgnoreModule] for details.
func IgnoreModule(module string) CompileOption {
	return func(c *Compiler) error {
		c.IgnoreModule(module)
		return nil
	}
}

// Compile receives YARA source code and returns compiled [Rules] that can be
// used for scanning data.
func Compile(src string, opts ...CompileOption) (*Rules, error) {
	c := NewCompiler()

	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	if err := c.AddSource(src); err != nil {
		return nil, err
	}
	return c.Build(), nil
}

// Deserialize deserializes rules from a byte slice.
//
// The counterpart is [Rules.Serialize]
func Deserialize(data []byte) (*Rules, error) {
	var ptr *C.uint8_t
	if len(data) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&(data[0])))
	}

	r := &Rules{cRules: nil}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if C.yrx_rules_deserialize(ptr, C.size_t(len(data)), &r.cRules) != C.SUCCESS {
		return nil, errors.New(C.GoString(C.yrx_last_error()))
	}

	return r, nil
}

// Rules represents a set of compiled YARA rules.
type Rules struct{ cRules *C.YRX_RULES }

// Scan some data with the compiled rules.
//
// Returns a slice with the rules that matched.
func (r* Rules) Scan(data []byte) ([]*Rule, error) {
	scanner := NewScanner(r)
	return scanner.Scan(data)
}

// Serialize converts the compiled rules into a byte slice.
func (r *Rules) Serialize() ([]byte, error) {
	var buf *C.YRX_BUFFER
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if C.yrx_rules_serialize(r.cRules, &buf) != C.SUCCESS {
		return nil, errors.New(C.GoString(C.yrx_last_error()))
	}
	defer C.yrx_buffer_destroy(buf)
	runtime.KeepAlive(r)
	return C.GoBytes(unsafe.Pointer(buf.data), C.int(buf.length)), nil
}

// Destroy destroys the compiled YARA rules represented by [Rules].
//
// Calling this method directly is not necessary, it will be invoked by the
// garbage collector when the rules are not used anymore.
func (r *Rules) Destroy() {
	if r.cRules != nil {
		C.yrx_rules_destroy(r.cRules)
		r.cRules = nil
	}
	runtime.SetFinalizer(r, nil)
}

// Rule represents a YARA rule.
type Rule struct {
	namespace  string
	identifier string
	cPatterns  *C.YRX_PATTERNS
	patterns   []Pattern
}

// Creates a new Rule from it's C counterpart.
func newRule(cRule *C.YRX_RULE) *Rule {
	var str *C.uint8_t
	var len C.size_t

	if C.yrx_rule_namespace(cRule, &str, &len) != C.SUCCESS {
		panic("yrx_rule_namespace failed")
	}

	namespace := C.GoStringN((*C.char)(unsafe.Pointer(str)), C.int(len))

	if C.yrx_rule_identifier(cRule, &str, &len) != C.SUCCESS {
		panic("yrx_rule_name failed")
	}

	identifier := C.GoStringN((*C.char)(unsafe.Pointer(str)), C.int(len))

	rule := &Rule{
		namespace,
		identifier,
		C.yrx_rule_patterns(cRule),
		nil,
	}

	runtime.SetFinalizer(rule, (*Rule).destroy)
	return rule
}

func (r *Rule) destroy() {
	C.yrx_patterns_destroy(r.cPatterns)
	runtime.SetFinalizer(r, nil)
}

// Identifier returns the rule's identifier.
func (r *Rule) Identifier() string {
	return r.identifier
}

// Namespace returns the rule's namespace.
func (r *Rule) Namespace() string {
	return r.namespace
}

// Patterns returns the patterns defined by this rule.
func (r *Rule) Patterns() []Pattern {
	// If this method was called before, return the patterns already cached.
	if r.patterns != nil {
		return r.patterns
	}

	numPatterns := int(r.cPatterns.num_patterns)
	cPatterns := unsafe.Slice(r.cPatterns.patterns, numPatterns)
	r.patterns = make([]Pattern, numPatterns)

	for i, pattern := range cPatterns {
		numMatches := int(pattern.num_matches)
		cMatches := unsafe.Slice(pattern.matches, numMatches)
		matches := make([]Match, numMatches)

		for j, match := range cMatches {
			matches[j] = Match{
				offset: uint(match.offset),
				length: uint(match.length),
			}
		}

		r.patterns[i] = Pattern{
			identifier: C.GoString(pattern.identifier),
			matches:    matches,
		}
	}

	return r.patterns
}

// Pattern represents a pattern in a Rule.
type Pattern struct {
	identifier string
	matches    []Match
}

// Identifier returns the pattern's identifier (i.e: $a, $foo).
func (p *Pattern) Identifier() string {
	return p.identifier
}

// Matches returns the matches found for this pattern.
func (p *Pattern) Matches() []Match {
	return p.matches
}

// Match contains information about the offset where a match occurred and
// the length of the match.
type Match struct {
	offset uint
	length uint
}

// Offset returns the offset within the scanned data where a match occurred.
func (m *Match) Offset() uint {
	return m.offset
}

// Length returns the length of a match in bytes.
func (m *Match) Length() uint {
	return m.length
}
