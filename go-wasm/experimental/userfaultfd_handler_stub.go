//go:build !linux

package experimental

import (
	"errors"
	"io"
	"unsafe"
)

type userfaultfdHandler struct{}

func newUserfaultfdHandler(addr unsafe.Pointer, length uintptr, src io.ReaderAt, size int64) (*userfaultfdHandler, error) {
	_ = addr
	_ = length
	_ = src
	_ = size
	return nil, errors.New("userfaultfd-backed guest reader mapping is unsupported on this platform")
}

func (h *userfaultfdHandler) Close() error {
	_ = h
	return nil
}
