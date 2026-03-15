package experimental

import (
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"unsafe"

	yara_x "github.com/VirusTotal/yara-x/go-wasm"

	"github.com/tetratelabs/wazero/api"
	wazeroexperimental "github.com/tetratelabs/wazero/experimental"
)

const experimentalHugePageSize = 2 << 20

type reservedRegion interface {
	slice(size uint64) []byte
	free()
	mappingInfo() (start uintptr, length uintptr, ok bool)
}

type reservedRegionBackend interface {
	allocateRegion(reserveBytes uint64) (reservedRegion, error)
}

type linearMemory struct {
	allocator *MmapMemoryAllocator
	region    reservedRegion
}

func (m *linearMemory) Reallocate(size uint64) []byte {
	if m == nil || m.region == nil {
		return nil
	}
	return m.region.slice(size)
}

func (m *linearMemory) Free() {
	if m == nil || m.region == nil {
		return
	}
	if m.allocator != nil {
		m.allocator.unregisterRegion(m.region)
	}
	m.region.free()
	m.region = nil
}

type sliceRegion struct {
	data []byte
}

func newSliceRegion(reserveBytes uint64) (reservedRegion, error) {
	reserveLen, err := intBytes(reserveBytes)
	if err != nil {
		return nil, err
	}
	return &sliceRegion{data: make([]byte, reserveLen)}, nil
}

func (r *sliceRegion) slice(size uint64) []byte {
	sizeLen, err := intBytes(size)
	if err != nil || sizeLen > len(r.data) {
		return nil
	}
	return r.data[:sizeLen:sizeLen]
}

func (r *sliceRegion) free() {
	r.data = nil
}

func (r *sliceRegion) mappingInfo() (uintptr, uintptr, bool) {
	return 0, 0, false
}

type mmapBackend struct{}

func (mmapBackend) allocateRegion(reserveBytes uint64) (reservedRegion, error) {
	return newMmapRegion(reserveBytes)
}

// MmapMemoryAllocator is an experimental wazero linear-memory allocator backed
// by a reserved virtual-memory region.
//
// It is intended as a foundation for future guest-memory backends, including
// lazy page population schemes such as userfaultfd.
type MmapMemoryAllocator struct {
	backend reservedRegionBackend
	mu      sync.Mutex
	regions map[uintptr]uintptr
}

// NewMmapMemoryAllocator returns an allocator that backs guest linear memory
// with anonymous mmap when available, and falls back to a stable Go slice when
// mmap cannot be created.
func NewMmapMemoryAllocator() *MmapMemoryAllocator {
	return &MmapMemoryAllocator{backend: mmapBackend{}}
}

// MapFileToGuest implements
// [github.com/VirusTotal/yara-x/go-wasm.GuestFileMapper].
func (a *MmapMemoryAllocator) MapFileToGuest(mem api.Memory, guestOffset, mappedLength uint32, path string) (yara_x.GuestMappedRegion, error) {
	logUFFDTracef("allocator.MapFileToGuest guest_offset=%d mapped_len=%d path=%q", guestOffset, mappedLength, path)
	addr, err := a.guestWindowAddress(mem, guestOffset, mappedLength)
	if err != nil {
		logUFFDTracef("allocator.MapFileToGuest guestWindowAddress failed: %v", err)
		return nil, err
	}
	return mapFileToGuest(addr, mappedLength, path)
}

// MapReaderAtToGuest implements
// [github.com/VirusTotal/yara-x/go-wasm.GuestReaderAtMapper].
func (a *MmapMemoryAllocator) MapReaderAtToGuest(mem api.Memory, guestOffset, mappedLength uint32, src io.ReaderAt, size int64) (yara_x.GuestMappedRegion, error) {
	logUFFDTracef("allocator.MapReaderAtToGuest guest_offset=%d mapped_len=%d size=%d src=%T", guestOffset, mappedLength, size, src)
	addr, err := a.guestWindowAddress(mem, guestOffset, mappedLength)
	if err != nil {
		logUFFDTracef("allocator.MapReaderAtToGuest guestWindowAddress failed: %v", err)
		return nil, err
	}
	logUFFDTracef("allocator.MapReaderAtToGuest using addr=%#x mapped_len=%d", uintptr(addr), mappedLength)
	return mapReaderAtToGuest(addr, mappedLength, src, size)
}

// Allocate implements [github.com/tetratelabs/wazero/experimental.MemoryAllocator].
func (a *MmapMemoryAllocator) Allocate(capacity, max uint64) wazeroexperimental.LinearMemory {
	reserveBytes := reserveLength(capacity, max)
	backend := a.backend
	if backend == nil {
		backend = mmapBackend{}
	}
	region, err := backend.allocateRegion(reserveBytes)
	if err != nil {
		region, err = newSliceRegion(reserveBytes)
		if err != nil {
			return &linearMemory{}
		}
	}
	a.registerRegion(region)
	return &linearMemory{allocator: a, region: region}
}

// UseMmapMemoryAllocator returns an
// [github.com/VirusTotal/yara-x/go-wasm.InitialiseOption] that enables
// the experimental mmap-backed guest memory allocator.
func UseMmapMemoryAllocator() yara_x.InitialiseOption {
	return yara_x.WithMemoryAllocator(NewMmapMemoryAllocator())
}

func reserveLength(capacity, max uint64) uint64 {
	if max == 0 {
		max = capacity
	}
	if max < capacity {
		max = capacity
	}
	if max == 0 {
		max = 1
	}
	return max
}

func intBytes(size uint64) (int, error) {
	if size > uint64(math.MaxInt) {
		return 0, errors.New("byte size exceeds platform int range")
	}
	return int(size), nil
}

func describeAllocationFailure(reserveBytes uint64, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("reserve %d bytes for guest memory: %w", reserveBytes, err)
}

func (a *MmapMemoryAllocator) registerRegion(region reservedRegion) {
	if a == nil || region == nil {
		return
	}
	start, length, ok := region.mappingInfo()
	if !ok || length == 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.regions == nil {
		a.regions = make(map[uintptr]uintptr)
	}
	a.regions[start] = start + length
}

func (a *MmapMemoryAllocator) unregisterRegion(region reservedRegion) {
	if a == nil || region == nil {
		return
	}
	start, _, ok := region.mappingInfo()
	if !ok || start == 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.regions, start)
}

func (a *MmapMemoryAllocator) guestWindowAddress(mem api.Memory, guestOffset, mappedLength uint32) (unsafe.Pointer, error) {
	if mappedLength == 0 {
		logUFFDTracef("allocator.guestWindowAddress zero-length window")
		return nil, nil
	}

	view, ok := mem.Read(guestOffset, mappedLength)
	if !ok {
		logUFFDTracef("allocator.guestWindowAddress mem.Read failed guest_offset=%d mapped_len=%d", guestOffset, mappedLength)
		return nil, fmt.Errorf("guest mapping window [%d,%d) is out of bounds", guestOffset, guestOffset+mappedLength)
	}
	addr := uintptr(unsafe.Pointer(unsafe.SliceData(view)))
	logUFFDTracef("allocator.guestWindowAddress read window addr=%#x guest_offset=%d mapped_len=%d regions=%d", addr, guestOffset, mappedLength, len(a.regions))

	a.mu.Lock()
	defer a.mu.Unlock()
	for start, end := range a.regions {
		if addr >= start && addr+uintptr(mappedLength) <= end {
			logUFFDTracef("allocator.guestWindowAddress matched reserved region start=%#x end=%#x", start, end)
			return unsafe.Pointer(addr), nil
		}
	}
	logUFFDTracef("allocator.guestWindowAddress no matching reserved region for addr=%#x len=%d", addr, mappedLength)
	return nil, errors.New("guest memory is not backed by an mmap-reserved region")
}
