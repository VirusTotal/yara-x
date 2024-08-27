package yara_x

// #include <yara_x.h>
import "C"
import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// A CompileOption represent an option passed to [NewCompiler] and [Compile].
type CompileOption func(c *Compiler) error

// The Globals option for [NewCompiler] and [Compile] allows you to define
// global variables.
//
// Keys in the map represent variable names, and values are their initial
// values. Values associated with variables can be modified at scan time using
// [Scanner.SetGlobal]. If this option is used multiple times, global variables
// will be the union of all specified maps. If the same variable appears in
// multiple maps, the value from the last map will prevail.
//
// Alternatively, you can use [Compiler.DefineGlobal] to define global variables.
// However, variables defined this way are not retained after [Compiler.Build] is
// called, unlike variables defined with the Globals option.
//
// Valid value types include: int, int32, int64, bool, string, float32 and
// float64.
func Globals(vars map[string]interface{}) CompileOption {
	return func(c *Compiler) error {
		for ident, value := range vars {
			c.vars[ident] = value
		}
		return nil
	}
}

// IgnoreModule is an option for [NewCompiler] and [Compile] that allows
// ignoring a given module.
//
// This option can be passed multiple times with different module names.
// Alternatively, you can use [Compiler.IgnoreModule], but modules ignored this
// way are not retained after [Compiler.Build] is called, unlike modules ignored
// with the IgnoreModule option.
func IgnoreModule(module string) CompileOption {
	return func(c *Compiler) error {
		c.ignoredModules[module] = true
		return nil
	}
}

// RelaxedReSyntax is an option for [NewCompiler] and [Compile] that
// determines whether the compiler should adopt a more relaxed approach
// while parsing regular expressions.
//
// YARA-X enforces stricter regular expression syntax compared to YARA.
// For instance, YARA accepts invalid escape sequences and treats them
// as literal characters (e.g., \R is interpreted as a literal 'R'). It
// also allows some special characters to appear unescaped, inferring
// their meaning from the context (e.g., `{` and `}` in `/foo{}bar/` are
// literal, but in `/foo{0,1}bar/` they form the repetition operator
// `{0,1}`).
//
// When this option is set, YARA-X mimics YARA's behavior, allowing
// constructs that YARA-X doesn't accept by default.
func RelaxedReSyntax(yes bool) CompileOption {
	return func(c *Compiler) error {
		c.relaxedReSyntax = yes
		return nil
	}
}

// ErrorOnSlowPattern is an option for [NewCompiler] and [Compile] that
// tells the compiler to treat slow patterns as errors instead of warnings.
func ErrorOnSlowPattern(yes bool) CompileOption {
		return func(c *Compiler) error {
  		c.errorOnSlowPattern = yes
  		return nil
  	}
}

// A structure that contains the options passed to [Compiler.AddSource].
type sourceOptions struct {
	origin string
}

// A SourceOption represent an option passed to [Compiler.AddSource].
type SourceOption func(opt *sourceOptions) error

// WithOrigin is an option for [Compiler.AddSource] that specifies the
// origin of the source code.
//
// The origin is usually the path of the file containing the source code,
// but it can be any arbitrary string that conveys information of the
// source's origin. This origin appears in error reports, for instance, if
// if origin is "some_file.yar", error reports will look like:
//
//  error: syntax error
//   --> some_file.yar:4:17
//    |
//  4 | ... more details
//
//
// Example:
//
//  c := NewCompiler()
//  c.AddSource("rule some_rule { condition: true }", WithOrigin("some_file.yar"))
func WithOrigin(origin string) SourceOption {
		return func(opts *sourceOptions) error {
			opts.origin = origin
			return nil
		}
}

// CompileError represents each of the errors returned by [Compiler.Errors].
type CompileError struct {
	// Error code (e.g: "E001").
	Code string
	// Error title (e.g: "unknown identifier `foo`").
	Title string
	// Each of the labels in the error report.
	Labels []Label
	// The error's full report, as shown by the command-line tool.
	Text string
}

// Label represents a label in a [CompileError].
type Label struct {
	// Label's level (e.g: "error", "warning", "info", "note", "help").
	Level string
	CodeOrigin string
	// The code span covered by the label.
	Span Span
	// Text associated to the label.
	Text string
}

// Span represents the starting and ending point of some piece of source
// code.
type Span struct {
	Start int
	End int
}

// Error returns the error's full report.
func (c CompileError) Error() string {
	return c.Text
}

// Compiler represent a YARA compiler.
type Compiler struct {
	cCompiler       *C.YRX_COMPILER
	relaxedReSyntax bool
	errorOnSlowPattern bool
	ignoredModules  map[string]bool
	vars map[string]interface{}
}

// NewCompiler creates a new compiler.
func NewCompiler(opts... CompileOption) (*Compiler, error) {
	c := &Compiler{
		ignoredModules: make(map[string]bool),
		vars: make(map[string]interface{}),
	}

	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}

	flags := C.uint32_t(0)
	if c.relaxedReSyntax {
		flags |= C.YRX_RELAXED_RE_SYNTAX
	}

	if c.errorOnSlowPattern {
		flags |= C.YRX_ERROR_ON_SLOW_PATTERN
	}

	C.yrx_compiler_create(flags, &c.cCompiler)

	if err := c.initialize(); err != nil {
		return nil, err
	}

	runtime.SetFinalizer(c, (*Compiler).Destroy)
	return c, nil
}

func (c *Compiler) initialize() error {
	for name, _ := range c.ignoredModules {
		c.IgnoreModule(name)
	}
	for ident, value := range c.vars {
		if err := c.DefineGlobal(ident, value); err != nil {
			return err
		}
	}
	return nil
}

// AddSource adds some YARA source code to be compiled.
//
// This function can be called multiple times.
//
// Examples:
//
//  c := NewCompiler()
//  c.AddSource("rule foo { condition: true }")
//  c.AddSource("rule bar { condition: true }")
//  c.AddSource("rule baz { condition: true }", WithOrigin("baz.yar"))
func (c *Compiler) AddSource(src string, opts... SourceOption) error {
	options := &sourceOptions{}
	for _, opt := range opts {
		opt(options)
	}

	cSrc := C.CString(src)
	defer C.free(unsafe.Pointer(cSrc))

	var cOrigin *C.char
  if options.origin != "" {
  	cOrigin = C.CString(options.origin)
  	defer C.free(unsafe.Pointer(cOrigin))
  }

	// The call to runtime.LockOSThread() is necessary to make sure that
	// yrx_compiler_add_source and yrx_last_error are called from the same OS
	// thread. Otherwise, yrx_last_error could return an error message that
	// doesn't correspond to this invocation of yrx_compiler_add_source. This
	// can happen because the Go runtime can switch this goroutine to a
	// different thread in-between the two calls to the C API.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if C.yrx_compiler_add_source_with_origin(c.cCompiler, cSrc, cOrigin) == C.SYNTAX_ERROR {
		return errors.New(C.GoString(C.yrx_last_error()))
	}
	// After the call to yrx_compiler_add_source, c is not live anymore and
	// the garbage collector could try to free it and call the finalizer while
	// yrx_compiler_add_source is being executed. This ensure that c is alive
	// until yrx_compiler_add_source finishes.
	runtime.KeepAlive(c)
	return nil
}

// IgnoreModule tells the compiler to ignore the module with the given name.
//
// Any YARA rule using the module will be ignored, as well as rules that depends
// on some other rule that uses the module. The compiler will issue warnings
// about the ignored rules, but otherwise the compilation will succeed.
func (c *Compiler) IgnoreModule(module string) {
	cModule := C.CString(module)
	defer C.free(unsafe.Pointer(cModule))
	result := C.yrx_compiler_ignore_module(c.cCompiler, cModule)
	if result != C.SUCCESS {
		panic("yrx_compiler_add_unsupported_module failed")
	}
	runtime.KeepAlive(c)
}

// NewNamespace creates a new namespace.
//
// Later calls to [Compiler.AddSource] will put the rules under the newly created
// namespace.
//
// Examples:
//
//  c := NewCompiler()
//  // Add some rule named "foo" under the default namespace
//  c.AddSource("rule foo { condition: true }")
//
//  // Create a new namespace named "bar"
//  c.NewNamespace("bar")
//
//  // It's ok to add another rule named "foo", as it is in a different
//  // namespace than the previous one.
//  c.AddSource("rule foo { condition: true }")
func (c *Compiler) NewNamespace(namespace string) {
	cNamespace := C.CString(namespace)
	defer C.free(unsafe.Pointer(cNamespace))
	result := C.yrx_compiler_new_namespace(c.cCompiler, cNamespace)
	if result != C.SUCCESS {
		panic("yrx_compiler_new_namespace failed")
	}
	runtime.KeepAlive(c)
}

// DefineGlobal defines a global variable and sets its initial value.
//
// Global variables must be defined before using [Compiler.AddSource]
// for adding any YARA source code that uses those variables. The variable
// will retain its initial value when the compiled [Rules] are used for
// scanning data, however each scanner can change the variable's initial
// value by calling [Scanner.SetGlobal].
//
// Valid value types are: int, int32, int64, bool, string, float32 and float64.
func (c *Compiler) DefineGlobal(ident string, value interface{}) error {
	cIdent := C.CString(ident)
	defer C.free(unsafe.Pointer(cIdent))
	var ret C.int

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	switch v := value.(type) {
	case int:
		ret = C.int(C.yrx_compiler_define_global_int(c.cCompiler, cIdent, C.int64_t(v)))
	case int32:
		ret = C.int(C.yrx_compiler_define_global_int(c.cCompiler, cIdent, C.int64_t(v)))
	case int64:
		ret = C.int(C.yrx_compiler_define_global_int(c.cCompiler, cIdent, C.int64_t(v)))
	case bool:
		ret = C.int(C.yrx_compiler_define_global_bool(c.cCompiler, cIdent, C.bool(v)))
	case string:
		cValue := C.CString(v)
		defer C.free(unsafe.Pointer(cValue))
		ret = C.int(C.yrx_compiler_define_global_str(c.cCompiler, cIdent, cValue))
	case float32:
		ret = C.int(C.yrx_compiler_define_global_float(c.cCompiler, cIdent, C.double(v)))
	case float64:
		ret = C.int(C.yrx_compiler_define_global_float(c.cCompiler, cIdent, C.double(v)))
	default:
		return fmt.Errorf("variable `%s` has unsupported type: %T", ident, v)
	}

	runtime.KeepAlive(c)

	if ret == C.VARIABLE_ERROR {
		return errors.New(C.GoString(C.yrx_last_error()))
	}

	return nil
}


// Errors that occurred during the compilation, across multiple calls to
// [Compiler.AddSource].
func (c *Compiler) Errors() []CompileError {
	var buf *C.YRX_BUFFER
	if C.yrx_compiler_errors_json(c.cCompiler, &buf) != C.SUCCESS {
		panic("yrx_compiler_errors_json failed")
	}

	defer C.yrx_buffer_destroy(buf)
	runtime.KeepAlive(c)

	jsonErrors := C.GoBytes(unsafe.Pointer(buf.data), C.int(buf.length))

	var result []CompileError

	if err := json.Unmarshal(jsonErrors, &result); err != nil {
		panic(err)
	}

	return result
}

// Build creates a [Rules] object containing a compiled version of all the
// YARA rules previously added to the compiler.
//
// Once this function is called the compiler is reset to its initial state
// (i.e: the state it had after NewCompiler returned).
func (c *Compiler) Build() *Rules {
	r := &Rules{cRules: C.yrx_compiler_build(c.cCompiler)}
	c.initialize()
	runtime.SetFinalizer(r, (*Rules).Destroy)
	runtime.KeepAlive(c)
	return r
}

// Destroy destroys the compiler.
//
// Calling Destroy is not required, but it's useful for explicitly freeing
// the memory used by the compiler.
func (c *Compiler) Destroy() {
	if c.cCompiler != nil {
		C.yrx_compiler_destroy(c.cCompiler)
		c.cCompiler = nil
	}
	runtime.SetFinalizer(c, nil)
}
