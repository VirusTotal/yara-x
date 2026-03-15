package experimental

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	userfaultfdTraceSampleLimit   = 8
	userfaultfdTraceLogEveryPages = 16384
)

var (
	uffdTraceEnabledOnce sync.Once
	uffdTraceEnabled     bool
)

type userfaultfdTrace struct {
	enabled        bool
	logEveryFaults uint64
	faults         uint64
	moveCalls      uint64
	totalMoveBytes uint64
	minMoveBytes   int64
	maxMoveBytes   int64
	partialMoves   uint64
	minOffset      int64
	maxOffset      int64
	lastOffset     int64
	firstOffsets   []int64
	writer         io.Writer
	closeWriter    func() error
}

func logUFFDTracef(format string, args ...interface{}) {
	uffdTraceEnabledOnce.Do(func() {
		uffdTraceEnabled = os.Getenv("YARAX_UFFD_TRACE") != ""
	})
	if !uffdTraceEnabled {
		return
	}
	fmt.Fprintf(os.Stderr, "experimental: "+format+"\n", args...)
}

func newUserfaultfdTraceFromEnv() *userfaultfdTrace {
	raw := strings.TrimSpace(os.Getenv("YARAX_UFFD_TRACE"))
	if raw == "" || raw == "0" || strings.EqualFold(raw, "false") {
		return nil
	}

	logEvery := uint64(userfaultfdTraceLogEveryPages)
	if rawEvery := strings.TrimSpace(os.Getenv("YARAX_UFFD_TRACE_EVERY")); rawEvery != "" {
		if parsed, err := strconv.ParseUint(rawEvery, 10, 64); err == nil && parsed > 0 {
			logEvery = parsed
		}
	}

	writer := io.Writer(os.Stderr)
	var closeWriter func() error
	if path := strings.TrimSpace(os.Getenv("YARAX_UFFD_TRACE_FILE")); path != "" {
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err == nil {
			writer = file
			closeWriter = file.Close
		}
	}

	return &userfaultfdTrace{
		enabled:        true,
		logEveryFaults: logEvery,
		minMoveBytes:   -1,
		minOffset:      -1,
		maxOffset:      -1,
		lastOffset:     -1,
		firstOffsets:   make([]int64, 0, userfaultfdTraceSampleLimit),
		writer:         writer,
		closeWriter:    closeWriter,
	}
}

func (t *userfaultfdTrace) record(offset, size int64) {
	if t == nil || !t.enabled {
		return
	}
	t.faults++
	t.lastOffset = offset
	if t.minOffset == -1 || offset < t.minOffset {
		t.minOffset = offset
	}
	if offset > t.maxOffset {
		t.maxOffset = offset
	}
	if len(t.firstOffsets) < userfaultfdTraceSampleLimit {
		t.firstOffsets = append(t.firstOffsets, offset)
	}
	if t.logEveryFaults > 0 && t.faults%t.logEveryFaults == 0 {
		fmt.Fprintf(
			t.writer,
			"userfaultfd trace: faults=%d last_offset=%d min_offset=%d max_offset=%d size=%d\n",
			t.faults,
			t.lastOffset,
			t.minOffset,
			t.maxOffset,
			size,
		)
	}
}

func (t *userfaultfdTrace) recordMove(moveBytes, requestedBytes int64) {
	if t == nil || !t.enabled {
		return
	}
	t.moveCalls++
	if moveBytes < 0 {
		moveBytes = 0
	}
	t.totalMoveBytes += uint64(moveBytes)
	if t.minMoveBytes == -1 || moveBytes < t.minMoveBytes {
		t.minMoveBytes = moveBytes
	}
	if moveBytes > t.maxMoveBytes {
		t.maxMoveBytes = moveBytes
	}
	if moveBytes != requestedBytes {
		t.partialMoves++
		fmt.Fprintf(
			t.writer,
			"userfaultfd move anomaly: move_bytes=%d requested_bytes=%d move_calls=%d\n",
			moveBytes,
			requestedBytes,
			t.moveCalls,
		)
	}
}

func (t *userfaultfdTrace) logSummary(size int64) {
	if t == nil || !t.enabled {
		return
	}
	fmt.Fprintf(
		t.writer,
		"userfaultfd trace summary: faults=%d move_calls=%d total_move_bytes=%d min_move_bytes=%d max_move_bytes=%d partial_move_calls=%d min_offset=%d max_offset=%d last_offset=%d size=%d first_offsets=%v\n",
		t.faults,
		t.moveCalls,
		t.totalMoveBytes,
		t.minMoveBytes,
		t.maxMoveBytes,
		t.partialMoves,
		t.minOffset,
		t.maxOffset,
		t.lastOffset,
		size,
		t.firstOffsets,
	)
	if t.closeWriter != nil {
		_ = t.closeWriter()
		t.closeWriter = nil
	}
}
