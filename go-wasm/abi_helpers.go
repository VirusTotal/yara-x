package yara_x

import (
	"fmt"
	"math"
	"time"
	"unsafe"
)

func u32FromUint64(value uint64, name string) (uint32, error) {
	if value > math.MaxUint32 {
		return 0, fmt.Errorf("%s %d exceeds uint32", name, value)
	}
	return uint32(value), nil
}

func u32FromLen(length int, name string) (uint32, error) {
	if length < 0 {
		return 0, fmt.Errorf("%s %d is negative", name, length)
	}
	if uint64(length) > math.MaxUint32 {
		return 0, fmt.Errorf("%s %d exceeds uint32", name, length)
	}
	//nolint:gosec // The value is range-checked against uint32 bounds above.
	return uint32(length), nil
}

func durationFromNanos(value uint64, name string) (time.Duration, error) {
	if value > math.MaxInt64 {
		return 0, fmt.Errorf("%s %d exceeds int64", name, value)
	}
	return time.Duration(value), nil
}

func i32FromBits(value uint32) int32 {
	return *(*int32)(unsafe.Pointer(&value))
}

func i64FromBits(value uint64) int64 {
	return *(*int64)(unsafe.Pointer(&value))
}

func u64FromI64Bits(value int64) uint64 {
	return *(*uint64)(unsafe.Pointer(&value))
}
