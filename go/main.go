// Package yara_x provides Go bindings to the YARA-X library.
package yara_x

// #cgo !static_link pkg-config: yara_x_capi
// #cgo static_link pkg-config: --static yara_x_capi
// #include <yara_x.h>
//
// static inline uint64_t meta_i64(void* value) {
//   return ((YRX_METADATA_VALUE*) value)->i64;
// }
//
// static inline double meta_f64(void* value) {
//   return ((YRX_METADATA_VALUE*) value)->f64;
// }
//
// static inline bool meta_bool(void* value) {
//   return ((YRX_METADATA_VALUE*) value)->boolean;
// }
//
// static inline const char* meta_str(void* value) {
//   return ((YRX_METADATA_VALUE*) value)->string;
// }
//
// static inline YRX_METADATA_BYTES* meta_bytes(void* value) {
//   return &(((YRX_METADATA_VALUE*) value)->bytes);
// }
//
// enum YRX_RESULT static inline _yrx_rules_iter(
//		const struct YRX_RULES *rules,
//		YRX_RULE_CALLBACK callback,
//		uintptr_t rules_handle)
// {
//   return yrx_rules_iter(rules, callback, (void*) rules_handle);
// }
//
// enum YRX_RESULT static inline _yrx_rules_iter_imports(
//		const struct YRX_RULES *rules,
//		YRX_IMPORT_CALLBACK callback,
//		uintptr_t imports_handle)
// {
//   return yrx_rules_iter_imports(rules, callback, (void*) imports_handle);
// }
//
// enum YRX_RESULT static inline _yrx_rule_iter_metadata(
//		const struct YRX_RULE *rule,
//		YRX_METADATA_CALLBACK callback,
//		uintptr_t metadata_handle)
// {
//   return yrx_rule_iter_metadata(rule, callback, (void*) metadata_handle);
// }
//
// enum YRX_RESULT static inline _yrx_rule_iter_patterns(
//		const struct YRX_RULE *rule,
//		YRX_PATTERN_CALLBACK callback,
//		uintptr_t patterns_handle)
// {
//   return yrx_rule_iter_patterns(rule, callback, (void*) patterns_handle);
// }
//
// enum YRX_RESULT static inline _yrx_pattern_iter_matches(
//		const struct YRX_PATTERN *pattern,
//		YRX_MATCH_CALLBACK callback,
//		uintptr_t matches_handle)
// {
//   return yrx_pattern_iter_matches(pattern, callback, (void*) matches_handle);
// }
//
// extern void ruleCallback(YRX_RULE*, uintptr_t);
// extern void importCallback(char*, uintptr_t);
// extern void metadataCallback(YRX_METADATA*, uintptr_t);
// extern void patternCallback(YRX_PATTERN*, uintptr_t);
// extern void matchCallback(YRX_MATCH*, uintptr_t);
//
import "C"

import (
	"errors"
	"io"
	"reflect"
	"runtime"
	"runtime/cgo"
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

// ReadFrom reads compiled rules from a reader.
//
// The counterpart is [Rules.WriteTo].
func ReadFrom(r io.Reader) (*Rules, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var ptr *C.uint8_t
	if len(data) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&(data[0])))
	}

	rules := &Rules{cRules: nil}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if C.yrx_rules_deserialize(ptr, C.size_t(len(data)), &rules.cRules) != C.SUCCESS {
		return nil, errors.New(C.GoString(C.yrx_last_error()))
	}

	return rules, nil
}

// Rules represents a set of compiled YARA rules.
type Rules struct{ cRules *C.YRX_RULES }

// Scan some data with the compiled rules.
func (r *Rules) Scan(data []byte) (*ScanResults, error) {
	scanner := NewScanner(r)
	defer scanner.Destroy()
	return scanner.Scan(data)
}

// WriteTo writes the compiled rules into a writer.
//
// The counterpart is [ReadFrom].
func (r *Rules) WriteTo(w io.Writer) (int64, error) {
	var buf *C.YRX_BUFFER
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if C.yrx_rules_serialize(r.cRules, &buf) != C.SUCCESS {
		return 0, errors.New(C.GoString(C.yrx_last_error()))
	}
	defer C.yrx_buffer_destroy(buf)
	runtime.KeepAlive(r)

	// We are going to write into `w` in chunks of 64MB.
	const chunkSize = 1 << 26

	// This is the slice that contains the next chunk that will be written.
	var chunk []byte

	// Modify the `chunk` slice, making it point to the buffer returned
	// by yrx_rules_serialize. This allows us to access the buffer from
	// Go without copying the data. This is safe because the slice won't
	// be used after the buffer is destroyed.
	chunkHdr := (*reflect.SliceHeader)(unsafe.Pointer(&chunk))
	chunkHdr.Data = uintptr(unsafe.Pointer(buf.data))
	chunkHdr.Len = chunkSize
	chunkHdr.Cap = chunkSize

	bufLen := C.ulong(buf.length)
	bytesWritten := int64(0)

	for {
		// If the data to be written is shorted than `chunkSize`, set the length
		// of the `chunk` slice to this length.
		if bufLen < chunkSize {
			chunkHdr.Len = int(bufLen)
			chunkHdr.Cap = int(bufLen)
		}
		if n, err := w.Write(chunk); err == nil {
			bytesWritten += int64(n)
		} else {
			return 0, err
		}
		// If `bufLen` is still greater than `chunkSize`, there's more data to
		// write, if not, we are done.
		if bufLen > chunkSize {
			chunkHdr.Data += chunkSize
			bufLen -= chunkSize
		} else {
			break
		}
	}

	return bytesWritten, nil
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

// This is the callback called by yrx_rules_iterate, when Rules.GetRules is
// called.
//export onRule
func onRule(rule *C.YRX_RULE, handle C.uintptr_t) {
	h := cgo.Handle(handle)
	rules, ok := h.Value().(*[]*Rule)
	if !ok {
		panic("onRule didn't receive a *[]Rule")
	}
	*rules = append(*rules, newRule(rule))
}

// Slice returns a slice with all the individual rules contained in this
// set of compiled rules.
func (r *Rules) Slice() []*Rule {
	rules := make([]*Rule, 0)
	handle := cgo.NewHandle(&rules)
	defer handle.Delete()

	C._yrx_rules_iter(
		r.cRules,
		C.YRX_RULE_CALLBACK(C.ruleCallback),
		C.uintptr_t(handle))

	runtime.KeepAlive(r)
	return rules
}

// Count returns the total number of rules.
//
// This is more a more efficient alternative to len(rules.Slice()).
func (r *Rules) Count() int {
	count := C.yrx_rules_count(r.cRules)
	runtime.KeepAlive(r)
	return int(count)
}

// Imports returns the names of the imported modules.
func (r *Rules) Imports() []string {
	imports := make([]string, 0)
	handle := cgo.NewHandle(&imports)
	defer handle.Delete()

	C._yrx_rules_iter_imports(
		r.cRules,
		C.YRX_RULE_CALLBACK(C.importCallback),
		C.uintptr_t(handle))

	runtime.KeepAlive(r)
	return imports
}

// Rule represents a YARA rule.
type Rule struct {
	namespace  string
	identifier string
	patterns   []Pattern
	metadata   []Metadata
}

// Pattern represents a pattern in a Rule.
type Pattern struct {
	identifier string
	matches    []Match
}

// Metadata represents a metadata in a Rule.
type Metadata struct {
	identifier string
	value      interface{}
}

// Match contains information about the offset where a match occurred and
// the length of the match.
type Match struct {
	offset uint64
	length uint64
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

	metadata := make([]Metadata, 0)
	metadataHandle := cgo.NewHandle(&metadata)
	defer metadataHandle.Delete()

	if C._yrx_rule_iter_metadata(
		cRule,
		C.YRX_PATTERN_CALLBACK(C.metadataCallback),
		C.uintptr_t(metadataHandle)) != C.SUCCESS {
		panic("yrx_rule_iter_metadata failed")
	}

	patterns := make([]Pattern, 0)
	patternsHandle := cgo.NewHandle(&patterns)
	defer patternsHandle.Delete()

	if C._yrx_rule_iter_patterns(
		cRule,
		C.YRX_PATTERN_CALLBACK(C.patternCallback),
		C.uintptr_t(patternsHandle)) != C.SUCCESS {
		panic("yrx_rule_iter_patterns failed")
	}

	rule := &Rule{
		namespace,
		identifier,
		patterns,
		metadata,
	}

	return rule
}

// Identifier returns the rule's identifier.
func (r *Rule) Identifier() string {
	return r.identifier
}

// Namespace returns the rule's namespace.
func (r *Rule) Namespace() string {
	return r.namespace
}

// Identifier associated to the metadata.
func (m *Metadata) Identifier() string {
	return m.identifier
}

// Value associated to the metadata.
func (m *Metadata) Value() interface{} {
	return m.value
}

// Metadata returns the rule's metadata
func (r *Rule) Metadata() []Metadata {
	return r.metadata
}

// Patterns returns the patterns defined by this rule.
func (r *Rule) Patterns() []Pattern {
	return r.patterns
}

// Identifier returns the pattern's identifier (i.e: $a, $foo).
func (p *Pattern) Identifier() string {
	return p.identifier
}

// Matches returns the matches found for this pattern.
func (p *Pattern) Matches() []Match {
	return p.matches
}

// Offset returns the offset within the scanned data where a match occurred.
func (m *Match) Offset() uint64 {
	return m.offset
}

// Length returns the length of a match in bytes.
func (m *Match) Length() uint64 {
	return m.length
}

// This is the callback called by yrx_rules_iter, when Rules.GetRules is
// called.
//
//export ruleCallback
func ruleCallback(rule *C.YRX_RULE, handle C.uintptr_t) {
	h := cgo.Handle(handle)
	rules, ok := h.Value().(*[]*Rule)
	if !ok {
		panic("ruleCallback didn't receive a *[]Rule")
	}
	*rules = append(*rules, newRule(rule))
}

// This is the callback called by yrx_rules_iter_imports, when Rules.Imports
// is called.
//
//export importCallback
func importCallback(moduleName *C.char, handle C.uintptr_t) {
	h := cgo.Handle(handle)
	imports, ok := h.Value().(*[]string)
	if !ok {
		panic("importCallback didn't receive a *[]string")
	}
	*imports = append(*imports, C.GoString(moduleName))
}

// This is the callback called by yrx_rules_iter_patterns
//
//export patternCallback
func patternCallback(pattern *C.YRX_PATTERN, handle C.uintptr_t) {
	h := cgo.Handle(handle)
	patterns, ok := h.Value().(*[]Pattern)

	if !ok {
		panic("patternCallback didn't receive a *[]Pattern")
	}

	var str *C.uint8_t
	var len C.size_t

	if C.yrx_pattern_identifier(pattern, &str, &len) != C.SUCCESS {
		panic("yrx_pattern_identifier failed")
	}

	matches := make([]Match, 0)
	matchesHandle := cgo.NewHandle(&matches)
	defer matchesHandle.Delete()

	if C._yrx_pattern_iter_matches(pattern,
		C.YRX_MATCH_CALLBACK(C.matchCallback),
		C.uintptr_t(matchesHandle)) != C.SUCCESS {
		panic("yrx_pattern_iter_matches failed")
	}

	*patterns = append(*patterns, Pattern{
		identifier: C.GoStringN((*C.char)(unsafe.Pointer(str)), C.int(len)),
		matches:    matches,
	})
}

// This is the callback called by yrx_rules_iter_patterns
//
//export metadataCallback
func metadataCallback(metadata *C.YRX_METADATA, handle C.uintptr_t) {
	h := cgo.Handle(handle)
	m, ok := h.Value().(*[]Metadata)
	if !ok {
		panic("matchCallback didn't receive a *[]Metadata")
	}

	var value interface{}

	switch metadata.value_type {
	case C.I64:
		value = int64(C.meta_i64(unsafe.Pointer(&metadata.value)))
	case C.F64:
		value = float64(C.meta_f64(unsafe.Pointer(&metadata.value)))
	case C.BOOLEAN:
		value = bool(C.meta_bool(unsafe.Pointer(&metadata.value)))
	case C.STRING:
		value = C.GoString(C.meta_str(unsafe.Pointer(&metadata.value)))
	case C.BYTES:
		bytes := C.meta_bytes(unsafe.Pointer(&metadata.value))
		value = C.GoBytes(
			unsafe.Pointer(bytes.data),
			C.int(bytes.length),
		)
	}

	*m = append(*m, Metadata{
		identifier: C.GoString(metadata.identifier),
		value:      value,
	})
}

// This is the callback called by yrx_rules_iter_patterns
//
//export matchCallback
func matchCallback(match *C.YRX_MATCH, handle C.uintptr_t) {
	h := cgo.Handle(handle)
	matches, ok := h.Value().(*[]Match)
	if !ok {
		panic("matchCallback didn't receive a *[]Match")
	}
	*matches = append(*matches, Match{
		offset: uint64(match.offset),
		length: uint64(match.length),
	})
}
