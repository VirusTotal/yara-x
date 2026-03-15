package experimental

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/require"
)

func TestMmapMemoryAllocatorKeepsStableBackingAcrossGrowth(t *testing.T) {
	allocator := NewMmapMemoryAllocator()
	mem := allocator.Allocate(64<<10, 256<<10)
	t.Cleanup(mem.Free)

	first := mem.Reallocate(64 << 10)
	require.Len(t, first, 64<<10)
	first[0] = 0x7a

	second := mem.Reallocate(128 << 10)
	require.Len(t, second, 128<<10)
	require.Equal(t, byte(0x7a), second[0])
	require.Equal(t, unsafe.SliceData(first), unsafe.SliceData(second))
}
