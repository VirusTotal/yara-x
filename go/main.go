// Package yara_x provides Go bindings to the YARA-X library.
package yara_x

// #cgo !static_link pkg-config: yara_x_capi
// #cgo static_link pkg-config: --static yara_x_capi
// #include <yara_x.h>
//
// uint64_t meta_i64(void* value) {
//   return ((YRX_METADATA_VALUE*) value)->i64;
// }
//
// double meta_f64(void* value) {
//   return ((YRX_METADATA_VALUE*) value)->f64;
// }
//
// bool meta_bool(void* value) {
//   return ((YRX_METADATA_VALUE*) value)->boolean;
// }
//
// char* meta_str(void* value) {
//   return ((YRX_METADATA_VALUE*) value)->string;
// }
//
// YRX_METADATA_BYTES* meta_bytes(void* value) {
//   return &(((YRX_METADATA_VALUE*) value)->bytes);
// }
import "C"
import (
	"errors"
	"runtime"
	"unsafe"
)

// Compile receives YARA source code and returns compiled [Rules] that can be
// used for scanning data.
func Compile(src string, opts ...CompileOption) (*Rules, error) {
	c, err := NewCompiler(opts...)
	if err != nil {
		return nil, err
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
func (r *Rules) Scan(data []byte) ([]*Rule, error) {
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
	cMetadata  *C.YRX_METADATA
	metadata   []Metadata
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
		C.yrx_rule_metadata(cRule),
		nil,
	}

	runtime.SetFinalizer(rule, (*Rule).destroy)
	return rule
}

func (r *Rule) destroy() {
	C.yrx_patterns_destroy(r.cPatterns)
	if r.cMetadata != nil {
		C.yrx_metadata_destroy(r.cMetadata)
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

// Metadata returns the rule's metadata
func (r *Rule) Metadata() []Metadata {
	// if this method was called before, return the metadata already cached.
	if r.metadata != nil {
		return r.metadata
	}

	numMetadata := int(r.cMetadata.num_entries)
	cMetadata := unsafe.Slice(r.cMetadata.entries, numMetadata)
	r.metadata = make([]Metadata, numMetadata)

	for i, metadata := range cMetadata {
		r.metadata[i].Identifier = C.GoString(metadata.identifier)
		switch metadata.value_type {
		case C.I64:
			r.metadata[i].Value = int64(
				C.meta_i64(unsafe.Pointer(&metadata.value)))
		case C.F64:
			r.metadata[i].Value = float64(
				C.meta_f64(unsafe.Pointer(&metadata.value)))
		case C.BOOLEAN:
			r.metadata[i].Value = bool(
				C.meta_bool(unsafe.Pointer(&metadata.value)))
		case C.STRING:
			r.metadata[i].Value = C.GoString(
				C.meta_str(unsafe.Pointer(&metadata.value)))
		case C.BYTES:
			bytes := C.meta_bytes(unsafe.Pointer(&metadata.value))
			r.metadata[i].Value = C.GoBytes(
				unsafe.Pointer(bytes.data),
				C.int(bytes.length),
			)
		}
	}

	return r.metadata
}

// Metadata represents a metadata in a Rule.
type Metadata struct {
	Identifier string
	Value      interface{}
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
