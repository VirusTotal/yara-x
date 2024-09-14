package yara_x

// #include <yara_x.h>
//
// enum YRX_RESULT static inline _yrx_scanner_on_matching_rule(
//     struct YRX_SCANNER *scanner,
//     YRX_RULE_CALLBACK callback,
//     uintptr_t user_data) {
//   return yrx_scanner_on_matching_rule(scanner, callback, (void*) user_data);
// }
//
// void onMatchingRule(YRX_RULE*, uintptr_t);
import "C"

import (
	"errors"
	"fmt"
	"math"
	"runtime"
	"runtime/cgo"
	"time"
	"unsafe"
)

import (
	"google.golang.org/protobuf/proto"
)

// Scanner scans data with a set of compiled YARA rules.
type Scanner struct {
	// Pointer to C-side scanner.
	cScanner *C.YRX_SCANNER
	// The Scanner holds a pointer to the Rules it uses in order to prevent
	// Rules from being garbage collected while the scanner is in use. If Rules
	// is garbage collected the associated C.YRX_RULES object is destroyed
	// before the C.YRX_SCANNER object.
	rules *Rules
	// Handle to the scanner itself that is passed to C callbacks.
	//
	// Go 1.21 introduces https://pkg.go.dev/runtime#Pinner.Pin, which allows
	// to pin a Go object in memory, guaranteeing that the garbage collector
	// won't move it to another memory location. We could pin the Scanner
	// struct and pass a pointer to the scanner to the C code, making this
	// handle unnecessary. At this time (Feb 2024) Go 1.21 is only 6 months
	// old, and we want to support older versions.
	handle cgo.Handle

	// Rules that matched during the last scan.
	matchingRules []*Rule
}

// ScanResults contains the results of a call to [Scanner.Scan] or [Rules.Scan].
type ScanResults struct {
	matchingRules []*Rule
}

// MatchingRules returns the rules that matched during the scan.
func (s ScanResults) MatchingRules() []*Rule {
	return s.matchingRules
}

// This is the callback function called every time a YARA rule matches.
//
//export onMatchingRule
func onMatchingRule(rule *C.YRX_RULE, handle C.uintptr_t) {
	h := cgo.Handle(handle)
	scanner, ok := h.Value().(*Scanner)
	if !ok {
		panic("onMatchingRule didn't receive a Scanner")
	}
	scanner.matchingRules = append(scanner.matchingRules, newRule(rule))
}

// NewScanner creates a Scanner that will use the provided YARA rules.
//
// It's safe to pass the same Rules to multiple scanners, and use each scanner
// on a separate goroutine for performing multiple scans in parallel with the
// same set of rules.
func NewScanner(r *Rules) *Scanner {
	s := &Scanner{rules: r}
	if C.yrx_scanner_create(r.cRules, &s.cScanner) != C.SUCCESS {
		panic("yrx_scanner_create failed")
	}

	s.handle = cgo.NewHandle(s)

	C._yrx_scanner_on_matching_rule(
		s.cScanner,
		C.YRX_RULE_CALLBACK(C.onMatchingRule),
		C.uintptr_t(s.handle))

	runtime.SetFinalizer(s, (*Scanner).Destroy)
	return s
}

// SetTimeout sets a timeout for scan operations.
//
// The [Scanner.Scan] method will return a timeout error once the provided timeout
// duration has elapsed. The scanner will make every effort to stop promptly
// after the designated timeout duration. However, in some cases, particularly
// with rules containing only a few patterns, the scanner could potentially
// continue running for a longer period than the specified timeout.
func (s *Scanner) SetTimeout(timeout time.Duration) {
	C.yrx_scanner_set_timeout(s.cScanner, C.uint64_t(math.Ceil(timeout.Seconds())))
	runtime.KeepAlive(s)
}

var ErrTimeout = errors.New("timeout")

// SetGlobal sets the value of a global variable.
//
// The variable must has been previously defined by calling [Compiler.DefineGlobal]
// and the type it has during the definition must match the type of the new
// value.
//
// The variable will retain the new value in subsequent scans, unless this
// method is called again for setting a new value.
func (s *Scanner) SetGlobal(ident string, value interface{}) error {
	cIdent := C.CString(ident)
	defer C.free(unsafe.Pointer(cIdent))
	var ret C.int

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	switch v := value.(type) {
	case int:
		ret = C.int(C.yrx_scanner_set_global_int(s.cScanner, cIdent, C.int64_t(v)))
	case int32:
		ret = C.int(C.yrx_scanner_set_global_int(s.cScanner, cIdent, C.int64_t(v)))
	case int64:
		ret = C.int(C.yrx_scanner_set_global_int(s.cScanner, cIdent, C.int64_t(v)))
	case bool:
		ret = C.int(C.yrx_scanner_set_global_bool(s.cScanner, cIdent, C.bool(v)))
	case string:
		cValue := C.CString(v)
		defer C.free(unsafe.Pointer(cValue))
		ret = C.int(C.yrx_scanner_set_global_str(s.cScanner, cIdent, cValue))
	case float64:
		ret = C.int(C.yrx_scanner_set_global_float(s.cScanner, cIdent, C.double(v)))
	default:
		return fmt.Errorf("variable `%s` has unsupported type: %T", ident, v)
	}

	runtime.KeepAlive(s)

	if ret == C.VARIABLE_ERROR {
		return errors.New(C.GoString(C.yrx_last_error()))
	}

	return nil
}

// SetModuleOutput sets the output data for a YARA module.
//
// Each YARA module generates an output consisting of a data structure that
// contains information about the scanned file. This data structure is represented
// by a Protocol Buffer. Typically, you won't need to provide this data yourself,
// as the YARA module automatically generates different outputs for each file
// it scans.
//
// However, there are two scenarios in which you may want to provide the output
// for a module yourself:
//
// 1) When the module does not produce any output on its own.
// 2) When you already know the output of the module for the upcoming file to
// be scanned, and you prefer to reuse this data instead of generating it again.
//
// Case 1) applies to certain modules lacking a main function, thus incapable of
// producing any output on their own. For such modules, you must set the output
// before scanning the associated data. Since the module's output typically varies
// with each scanned file, you need to call this method prior to each invocation
// of [Scanner.Scan]. Once [Scanner.Scan] is executed, the module's output is
// consumed and will be empty unless set again before the subsequent call.
//
// Case 2) applies when you have previously stored the module's output for certain
// scanned data. In such cases, when rescanning the data, you can utilize this
// method to supply the module's output, thereby preventing redundant computation
// by the module. This optimization enhances performance by eliminating the need
// for the module to reparse the scanned data.
//
// The data argument must be a Protocol Buffer message corresponding to any of
// the existing YARA modules.
func (s *Scanner) SetModuleOutput(data proto.Message) error {
	var err error
	var buf []byte

	if buf, err = proto.Marshal(data); err != nil {
		return err
	}

	var ptr *C.uint8_t
	if len(buf) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&(buf[0])))
	}

	name := C.CString(string(data.ProtoReflect().Descriptor().FullName()))
	defer C.free(unsafe.Pointer(name))

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if r := C.yrx_scanner_set_module_output(s.cScanner, name, ptr, C.size_t(len(buf))); r != C.SUCCESS {
		err = errors.New(C.GoString(C.yrx_last_error()))
	}

	runtime.KeepAlive(s)
	return err
}

// Scan scans the provided data with the Rules associated to the Scanner.
func (s *Scanner) Scan(buf []byte) (*ScanResults, error) {
	var ptr *C.uint8_t
	// When `buf` is an empty slice `ptr` will be nil. That's ok, because
	// yrx_scanner_scan allows the data pointer to be null as long as the data
	// size is 0.
	if len(buf) > 0 {
		ptr = (*C.uint8_t)(unsafe.Pointer(&(buf[0])))
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var err error
	switch r := C.yrx_scanner_scan(s.cScanner, ptr, C.size_t(len(buf))); r {
	case C.SUCCESS:
		err = nil
	case C.SCAN_TIMEOUT:
		err = ErrTimeout
	default:
		err = errors.New(C.GoString(C.yrx_last_error()))
	}

	scanResults := &ScanResults{s.matchingRules}
	s.matchingRules = nil

	return scanResults, err
}

// Destroy destroys the scanner.
//
// Calling this method directly is not necessary, it will be invoked by the
// garbage collector when the scanner is not used anymore.
func (s *Scanner) Destroy() {
	if s.cScanner != nil {
		C.yrx_scanner_destroy(s.cScanner)
		s.handle.Delete()
		s.cScanner = nil
	}
	s.rules = nil
	runtime.SetFinalizer(s, nil)
}
