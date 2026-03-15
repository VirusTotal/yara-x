package yara_x

import (
	"io"

	"github.com/tetratelabs/wazero/api"
	wazeroexperimental "github.com/tetratelabs/wazero/experimental"
)

// GuestMappedRegion represents a temporary guest-memory mapping managed by a
// custom [wazeroexperimental.MemoryAllocator].
//
// This is an advanced extension point intended for experimental guest-memory
// backends. Callers should prefer higher-level APIs.
type GuestMappedRegion interface {
	// Close removes the temporary mapping and restores the underlying guest
	// memory region.
	Close() error
}

// GuestFileMapper is an optional extension for custom guest-memory allocators
// that can map a local file directly into a guest linear-memory subrange.
//
// When configured via [WithMemoryAllocator], [Scanner.ScanFile] may use this to
// avoid copying file contents into guest memory.
type GuestFileMapper interface {
	wazeroexperimental.MemoryAllocator

	// MapFileToGuest replaces the guest-memory range `[guestOffset,
	// guestOffset+mappedLength)` with a mapping of the given local file.
	//
	// The supplied `mappedLength` is page-rounded. Callers still scan only the
	// original file length.
	MapFileToGuest(mem api.Memory, guestOffset, mappedLength uint32, path string) (GuestMappedRegion, error)
}

// GuestReaderAtMapper is an optional extension for custom guest-memory
// allocators that can expose an [io.ReaderAt] through a guest linear-memory
// subrange.
//
// When configured via [WithMemoryAllocator], [Scanner.ScanReaderAt] may use
// this to scan data without copying it into guest memory first.
type GuestReaderAtMapper interface {
	wazeroexperimental.MemoryAllocator

	// MapReaderAtToGuest prepares the guest-memory range `[guestOffset,
	// guestOffset+mappedLength)` so that reads from it are served by `src`.
	//
	// The supplied `mappedLength` is page-rounded, while `size` is the logical
	// scan length requested by the caller.
	MapReaderAtToGuest(mem api.Memory, guestOffset, mappedLength uint32, src io.ReaderAt, size int64) (GuestMappedRegion, error)
}
