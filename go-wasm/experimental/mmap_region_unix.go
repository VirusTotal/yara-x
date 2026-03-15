//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package experimental

import (
	"fmt"
	"io"
	"unsafe"

	yara_x "github.com/VirusTotal/yara-x/go-wasm"

	"golang.org/x/sys/unix"
)

type mmapRegion struct {
	raw  []byte
	data []byte
}

func newMmapRegion(reserveBytes uint64) (reservedRegion, error) {
	reserveLen, err := intBytes(reserveBytes)
	if err != nil {
		return nil, describeAllocationFailure(reserveBytes, err)
	}
	rawLen := reserveLen + experimentalHugePageSize - 1
	raw, err := unix.Mmap(
		-1,
		0,
		rawLen,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_ANON,
	)
	if err != nil {
		return nil, describeAllocationFailure(reserveBytes, err)
	}
	rawAddr := uintptr(unsafe.Pointer(unsafe.SliceData(raw)))
	alignedAddr := (rawAddr + uintptr(experimentalHugePageSize-1)) &^ uintptr(experimentalHugePageSize-1)
	alignedOffset := int(alignedAddr - rawAddr)
	data := raw[alignedOffset : alignedOffset+reserveLen : alignedOffset+reserveLen]
	return &mmapRegion{raw: raw, data: data}, nil
}

func (r *mmapRegion) slice(size uint64) []byte {
	sizeLen, err := intBytes(size)
	if err != nil || sizeLen > len(r.data) {
		return nil
	}
	return r.data[:sizeLen:sizeLen]
}

func (r *mmapRegion) free() {
	if len(r.raw) == 0 {
		return
	}
	_ = unix.Munmap(r.raw)
	r.raw = nil
	r.data = nil
}

func (r *mmapRegion) mappingInfo() (uintptr, uintptr, bool) {
	if r == nil || len(r.data) == 0 {
		return 0, 0, false
	}
	return uintptr(unsafe.Pointer(unsafe.SliceData(r.data))), uintptr(len(r.data)), true
}

type mappedFileRegion struct {
	addr   unsafe.Pointer
	length uintptr
}

func mapFileToGuest(addr unsafe.Pointer, mappedLength uint32, path string) (yara_x.GuestMappedRegion, error) {
	if mappedLength == 0 {
		logUFFDTracef("mapFileToGuest zero-length mapping path=%q", path)
		return &mappedFileRegion{}, nil
	}
	logUFFDTracef("mapFileToGuest addr=%#x mapped_len=%d path=%q", uintptr(addr), mappedLength, path)

	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		logUFFDTracef("mapFileToGuest open failed path=%q err=%v", path, err)
		return nil, err
	}
	defer unix.Close(fd)

	if _, err := unix.MmapPtr(
		fd,
		0,
		addr,
		uintptr(mappedLength),
		unix.PROT_READ,
		unix.MAP_PRIVATE|unix.MAP_FIXED,
	); err != nil {
		logUFFDTracef("mapFileToGuest MmapPtr failed addr=%#x mapped_len=%d err=%v", uintptr(addr), mappedLength, err)
		return nil, err
	}
	logUFFDTracef("mapFileToGuest mapped addr=%#x mapped_len=%d", uintptr(addr), mappedLength)

	return &mappedFileRegion{
		addr:   addr,
		length: uintptr(mappedLength),
	}, nil
}

func (r *mappedFileRegion) Close() error {
	if r == nil || r.addr == nil || r.length == 0 {
		return nil
	}

	_, err := unix.MmapPtr(
		-1,
		0,
		r.addr,
		r.length,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_FIXED|unix.MAP_ANON,
	)
	if err != nil {
		return err
	}

	r.addr = nil
	r.length = 0
	return nil
}

type userfaultfdMappedRegion struct {
	addr    unsafe.Pointer
	length  uintptr
	handler *userfaultfdHandler
}

func mapReaderAtToGuest(addr unsafe.Pointer, mappedLength uint32, src io.ReaderAt, size int64) (yara_x.GuestMappedRegion, error) {
	if mappedLength == 0 {
		logUFFDTracef("mapReaderAtToGuest zero-length mapping size=%d src=%T", size, src)
		return &userfaultfdMappedRegion{}, nil
	}
	if size < 0 {
		return nil, fmt.Errorf("invalid negative reader size %d", size)
	}
	logUFFDTracef("mapReaderAtToGuest addr=%#x mapped_len=%d size=%d src=%T", uintptr(addr), mappedLength, size, src)

	length := uintptr(mappedLength)
	if _, err := unix.MmapPtr(
		-1,
		0,
		addr,
		length,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_FIXED|unix.MAP_ANON,
	); err != nil {
		logUFFDTracef("mapReaderAtToGuest anonymous remap failed addr=%#x mapped_len=%d err=%v", uintptr(addr), mappedLength, err)
		return nil, err
	}
	logUFFDTracef("mapReaderAtToGuest installed anonymous window addr=%#x mapped_len=%d", uintptr(addr), mappedLength)
	if err := madviseHugepage(addr, length); err != nil {
		logUFFDTracef("mapReaderAtToGuest MADV_HUGEPAGE failed addr=%#x mapped_len=%d err=%v", uintptr(addr), mappedLength, err)
	}

	handler, err := newUserfaultfdHandler(addr, length, src, size)
	if err != nil {
		logUFFDTracef("mapReaderAtToGuest newUserfaultfdHandler failed addr=%#x mapped_len=%d err=%v", uintptr(addr), mappedLength, err)
		return nil, err
	}
	logUFFDTracef("mapReaderAtToGuest userfaultfd handler active addr=%#x mapped_len=%d", uintptr(addr), mappedLength)

	return &userfaultfdMappedRegion{
		addr:    addr,
		length:  length,
		handler: handler,
	}, nil
}

func (r *userfaultfdMappedRegion) Close() error {
	if r == nil || r.addr == nil || r.length == 0 {
		return nil
	}
	logUFFDTracef("userfaultfdMappedRegion.Close addr=%#x length=%d", uintptr(r.addr), r.length)

	var firstErr error
	if r.handler != nil {
		if err := r.handler.Close(); err != nil {
			firstErr = err
		}
	}

	if _, err := unix.MmapPtr(
		-1,
		0,
		r.addr,
		r.length,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_PRIVATE|unix.MAP_FIXED|unix.MAP_ANON,
	); err != nil && firstErr == nil {
		firstErr = err
	}

	r.addr = nil
	r.length = 0
	r.handler = nil
	return firstErr
}
