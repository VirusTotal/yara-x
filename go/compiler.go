package yara_x

// #include <yara-x.h>
import "C"
import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"
)

// Compiler represent a YARA compiler.
type Compiler struct {
	cCompiler *C.YRX_COMPILER
}

// NewCompiler creates a new compiler.
func NewCompiler() *Compiler {
	c := &Compiler{}
	C.yrx_compiler_create(&c.cCompiler)
	runtime.SetFinalizer(c, (*Compiler).Destroy)
	return c
}

// AddSource adds some YARA source code to be compiled.
//
// This function can be called multiple times.
//
// Example:
//
//  c := NewCompiler()
//  c.AddSource("rule foo { condition: true }")
//  c.AddSource("rule bar { condition: true }")
//
func (c *Compiler) AddSource(src string) error {
	cSrc := C.CString(src)
	defer C.free(unsafe.Pointer(cSrc))
	// The call to runtime.LockOSThread() is necessary to make sure that
	// yrx_compiler_add_source and yrx_last_error are called from the same OS
	// thread. Otherwise, yrx_last_error could return an error message that
	// doesn't correspond to this invocation of yrx_compiler_add_source. This
	// can happen because the Go runtime can switch this goroutine to a
	// different thread in-between the two calls to the C API.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if C.yrx_compiler_add_source(c.cCompiler, cSrc) == C.SYNTAX_ERROR {
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
	result := C.yrx_compiler_add_unsupported_module(c.cCompiler, cModule)
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

// Build creates a [Rules] object containing a compiled version of all the
// YARA rules previously added to the compiler.
//
// Once this function is called the compiler is reset to its initial state,
// as if it was a newly created compiler.
func (c *Compiler) Build() *Rules {
	r := &Rules{cRules: C.yrx_compiler_build(c.cCompiler)}
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
