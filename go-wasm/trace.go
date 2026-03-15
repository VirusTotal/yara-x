package yara_x

import (
	"fmt"
	"os"
	"sync"
)

var (
	uffdScanTraceEnabledOnce sync.Once
	uffdScanTraceEnabled     bool
)

func logUFFDTracef(format string, args ...interface{}) {
	uffdScanTraceEnabledOnce.Do(func() {
		uffdScanTraceEnabled = os.Getenv("YARAX_UFFD_TRACE") != ""
	})
	if !uffdScanTraceEnabled {
		return
	}
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}
