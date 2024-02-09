// Package yara_x provides Go bindings to the YARA-X library.
//
// Use the static_link build tag for linking the YARA-X Rust library statically.
// Notice however that this only works if the Rust library itself links all
// its dependencies statically.
package yara_x

// #cgo CFLAGS: -I${SRCDIR}/../capi/include
// #cgo !static_link LDFLAGS: -L${SRCDIR}/../target/release -lyara_x_c
// #cgo static_link LDFLAGS: ${SRCDIR}/../target/release/libyara_x_c.a
// #import <yara-x.h>
import "C"
import (
	"runtime"
	"unsafe"
)

// Compile receives YARA source code and returns compiled Rules that can be
// used for scanning data.
func Compile(source string) *Rules {
	s := C.CString(source)
	r := &Rules{}
	C.yrx_compile(s, &(r.cRules))
	runtime.SetFinalizer(r, (*Rules).Destroy)
	return r
}

// Rules represents a set of compiled YARA rules.
type Rules struct{ cRules *C.YRX_RULES }

// Destroy destroys the compiled YARA rules represented by Rules.
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
	patterns  []Pattern
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

	cPatterns := C.yrx_rule_patterns(cRule)

	if cPatterns == nil {
		panic("yrx_rule_patterns failed")
	}

	rule := &Rule{namespace, identifier, cPatterns, nil}
	runtime.SetFinalizer(rule, (*Rule).destroy)
	return rule
}

func (r *Rule) destroy() {
	if r.cPatterns != nil {
		C.yrx_patterns_destroy(r.cPatterns)
		r.cPatterns = nil
	}
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
	if r.patterns != nil {
		return r.patterns
	}

	numPatterns := int(C.yrx_patterns_count(r.cPatterns))
	r.patterns = make([]Pattern, numPatterns)

	for i := 0; i < numPatterns; i++ {
		pattern := C.yrx_patterns_get(r.cPatterns, C.ulong(i))
		if pattern == nil {
			panic("yrx_patterns_get failed")
		}

		var str *C.uint8_t
		var len C.size_t

		if C.yrx_pattern_identifier(pattern, &str, &len) != C.SUCCESS {
			panic("yrx_pattern_identifier failed")
		}

		identifier := C.GoStringN((*C.char)(unsafe.Pointer(str)), C.int(len))

		var ptrMatches *C.YRX_MATCH
		var numMatches C.size_t

		if C.yrx_pattern_matches(pattern, &ptrMatches, &numMatches) != C.SUCCESS {
			panic("yrx_pattern_matches failed")
		}

		matches := make([]Match, int(numMatches))

		for i := 0; i < int(numMatches); i++ {
			match := *(*C.YRX_MATCH)(unsafe.Add(
				unsafe.Pointer(ptrMatches),
				i*C.sizeof_YRX_MATCH))
			matches[i] = Match{
				offset: uint(match.offset),
				length: uint(match.length),
			}
		}

		r.patterns[i] = Pattern{
			identifier: identifier,
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

// Identifier returns the pattern's identifier (i.e: `$a`, `$foo`).
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
