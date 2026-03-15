//go:build linux

package experimental

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

func madviseHugepage(addr unsafe.Pointer, length uintptr) error {
	if addr == nil || length == 0 {
		return nil
	}
	if length > uintptr(^uint(0)>>1) {
		return fmt.Errorf("madvise length %d exceeds platform int range", length)
	}
	view := unsafe.Slice((*byte)(addr), int(length))
	return unix.Madvise(view, unix.MADV_HUGEPAGE)
}
