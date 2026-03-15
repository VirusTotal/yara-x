//go:build !(aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris)

package experimental

import (
	"errors"
	"io"
	"unsafe"
)

import (
	yara_x "github.com/VirusTotal/yara-x/go-wasm"
)

func newMmapRegion(reserveBytes uint64) (reservedRegion, error) {
	return nil, describeAllocationFailure(reserveBytes, errors.New("mmap-backed guest memory is unsupported on this platform"))
}

func mapFileToGuest(addr unsafe.Pointer, mappedLength uint32, path string) (yara_x.GuestMappedRegion, error) {
	_ = addr
	_ = mappedLength
	_ = path
	return nil, errors.New("mmap-backed guest file mapping is unsupported on this platform")
}

func mapReaderAtToGuest(addr unsafe.Pointer, mappedLength uint32, src io.ReaderAt, size int64) (yara_x.GuestMappedRegion, error) {
	_ = addr
	_ = mappedLength
	_ = src
	_ = size
	return nil, errors.New("userfaultfd-backed guest reader mapping is unsupported on this platform")
}
