package yara_x

// #include <yara-x.h>
import "C"
import (
	"errors"
	"runtime"
	"unsafe"
)

type Compiler struct {
	cCompiler *C.YRX_COMPILER
}

func NewCompiler() *Compiler {
	c := &Compiler{}
	C.yrx_compiler_create(&c.cCompiler)
	runtime.SetFinalizer(c, (*Compiler).Destroy)
	return c
}

func (c *Compiler) AddSource(src string) error {
	cSrc := C.CString(src)
	defer C.free(unsafe.Pointer(cSrc))
	var err error
	if C.yrx_compiler_add_source(c.cCompiler, cSrc) == C.SYNTAX_ERROR {
		err = errors.New(C.GoString(C.yrx_compiler_last_error(c.cCompiler)))
	}
	// After the call to yrx_compiler_add_source, c is not live anymore and
	// the garbage collector could try to free it and call the finalizer while
	// yrx_compiler_add_source is being executed. This ensure that c is alive
	// until yrx_compiler_add_source finishes.
	runtime.KeepAlive(c)
	return err
}

func (c *Compiler) NewNamespace(namespace string) {
	cNamespace := C.CString(namespace)
	defer C.free(unsafe.Pointer(cNamespace))
	result := C.yrx_compiler_new_namespace(c.cCompiler, cNamespace)
	if result != C.SUCCESS {
		panic("yrx_compiler_new_namespace failed")
	}
	runtime.KeepAlive(c)
}

func (c *Compiler) DefineGlobalInt(ident string, value int64) error {
	cIdent := C.CString(ident)
	defer C.free(unsafe.Pointer(cIdent))
	var err error
	if C.yrx_compiler_define_global_int(c.cCompiler, cIdent, C.int64_t(value)) == C.VARIABLE_ERROR {
		err = errors.New(C.GoString(C.yrx_compiler_last_error(c.cCompiler)))
	}
	runtime.KeepAlive(c)
	return err
}

func (c *Compiler) DefineGlobalBool(ident string, value bool) error {
	cIdent := C.CString(ident)
	defer C.free(unsafe.Pointer(cIdent))
	var err error
	if C.yrx_compiler_define_global_bool(c.cCompiler, cIdent, C.bool(value)) == C.VARIABLE_ERROR {
		err = errors.New(C.GoString(C.yrx_compiler_last_error(c.cCompiler)))
	}
	runtime.KeepAlive(c)
	return err
}

func (c *Compiler) DefineGlobalStr(ident string, value string) error {
	cIdent := C.CString(ident)
	defer C.free(unsafe.Pointer(cIdent))
	cValue := C.CString(value)
	defer C.free(unsafe.Pointer(cValue))
	var err error
	if C.yrx_compiler_define_global_str(c.cCompiler, cIdent, cValue) == C.VARIABLE_ERROR {
		err = errors.New(C.GoString(C.yrx_compiler_last_error(c.cCompiler)))
	}
	runtime.KeepAlive(c)
	return err
}

func (c *Compiler) Build() *Rules {
	r := &Rules{cRules: C.yrx_compiler_build(c.cCompiler)}
	runtime.SetFinalizer(r, (*Rules).Destroy)
	runtime.KeepAlive(c)
	return r
}

func (c *Compiler) Destroy() {
	if c.cCompiler != nil {
		C.yrx_compiler_destroy(c.cCompiler)
		c.cCompiler = nil
	}
	runtime.SetFinalizer(c, nil)
}