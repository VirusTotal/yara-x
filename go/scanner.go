package yara_x

import "C"
import (
	"runtime"
	"runtime/cgo"
	"unsafe"
)

// #include <yara-x.h>
// void onMatchingRule(YRX_RULE*, void*);
import "C"

// Scanner scans data with a set of compiled YARA rules.
type Scanner struct {
	// Pointer to C-side scanner.
	inner *C.YRX_SCANNER
	// The Scanner holds a pointer to the Rules it uses in order to prevent
	// Rules from being garbage collected while the scanner is in use. If Rules
	// is garbage collected the associated C.YRX_RULES object is destroyed
	// before the C.YRX_SCANNER object.
	rules *Rules
	// Handle to the scanner itself that is passed to C callbacks. Notice that
	// this is not actually the handle but a pointer to the handle, and the
	// memory that stores the handle is allocated via C.malloc because the
	// pointer is passed to C code. We don't want the garbage collector messing
	// with the memory that holds the handle.
	//
	// Go 1.21 introduces https://pkg.go.dev/runtime#Pinner.Pin, which allows
	// to pin a Go object in memory, guaranteeing that the garbage collector
	// won't move it to another memory location. We could pin the Scanner
	// struct and pass a pointer to the scanner to the C code, making this
	// handle unnecessary. At this time (Feb 2024) Go 1.21 is only 6 months
	// old, and we want to support older versions.
	handle *cgo.Handle
	// Rules that matched during the last scan.
	matchingRules []*Rule
}

type ScanResults struct{}

// NewScanner creates a Scanner that will use the provided YARA rules.
//
// It's safe to pass the same Rules to multiple scanners, and use each scanner
// on a separate goroutine for performing multiple scans in parallel with the
// same set of rules.
func NewScanner(r *Rules) *Scanner {
	s := &Scanner{rules: r}
	// TODO: handle error returned by yrx_scanner_create
	C.yrx_scanner_create(r.cRules, &s.inner)

	// Allocate the memory that will hold the handle. This memory is allocated
	// using C.malloc because a pointer to it is passed to C code, and we don't
	// want the garbage collector messing with it.
	s.handle = (*cgo.Handle)(C.malloc(C.size_t(unsafe.Sizeof(s.handle))))

	// Create a new handle that points to the scanner, and store it in the
	// newly allocated memory.
	*s.handle = cgo.NewHandle(s)

	C.yrx_scanner_on_matching_rule(
		s.inner,
		C.YRX_ON_MATCHING_RULE(C.onMatchingRule),
		unsafe.Pointer(s.handle))

	runtime.SetFinalizer(s, (*Scanner).Destroy)
	return s
}

// Scan scans the provided data with the Rules associated to the Scanner.
func (s *Scanner) Scan(buf []byte) []*Rule {
	var ptr *C.uint8_t
	// When `buf` is an empty slice `ptr` will be nil. That's ok, because
	// yrx_scanner_scan allows the data pointer to be null as long as the data
	// size is 0.
	if len(buf) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&(buf[0])))
	}
	s.matchingRules = nil
	// TODO: handle errors
	C.yrx_scanner_scan(s.inner, ptr, C.size_t(len(buf)))
	// Ensure that s is not finalized until yrx_scanner_scan returns.
	runtime.KeepAlive(s)
	return s.matchingRules
}

// Destroy destroys the scanner.
//
// Calling this method directly is not necessary, it will be invoked by the
// garbage collector when the scanner is not used anymore.
func (s *Scanner) Destroy() {
	if s.inner != nil {
		C.yrx_scanner_destroy(s.inner)
		s.handle.Delete()
		C.free(unsafe.Pointer(s.handle))
		s.inner = nil
	}
	runtime.SetFinalizer(s, nil)
}

// This is the callback function called every time a YARA rule matches.
//
//export onMatchingRule
func onMatchingRule(rule *C.YRX_RULE, handlePtr unsafe.Pointer) {
	handle := *(*cgo.Handle)(handlePtr)
	scanner, ok := handle.Value().(*Scanner)
	if !ok {
		panic("onMatchingRule didn't receive a Scanner")
	}
	scanner.matchingRules = append(scanner.matchingRules, newRule(rule))
}




