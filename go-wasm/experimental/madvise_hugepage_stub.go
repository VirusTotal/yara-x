//go:build !linux

package experimental

import "unsafe"

func madviseHugepage(addr unsafe.Pointer, length uintptr) error {
	return nil
}
