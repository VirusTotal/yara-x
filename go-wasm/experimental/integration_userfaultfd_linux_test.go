//go:build linux

package experimental_test

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"os"
	"runtime/pprof"
	"runtime/trace"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	yara_x "github.com/VirusTotal/yara-x/go-wasm"
	"github.com/VirusTotal/yara-x/go-wasm/experimental"

	"github.com/stretchr/testify/require"
)

var (
	experimentalInitOnce sync.Once
	experimentalInitErr  error
)

const testUffdChunkSize = 2 << 20

type patternedReaderAt struct {
	size         int64
	insertOffset int64
	pattern      []byte
	cursor       int64
	readCalls    uint64
	minReqLen    uint64
	maxReqLen    uint64
	partialCalls uint64
}

func (r *patternedReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= r.size {
		logPatternedReaderf("patternedReaderAt.ReadAt off=%d len=%d -> EOF", off, len(p))
		return 0, io.EOF
	}

	limit := int64(len(p))
	if remaining := r.size - off; remaining < limit {
		limit = remaining
	}

	clear(p[:limit])
	patternStart := maxInt64(off, r.insertOffset)
	patternEnd := minInt64(off+limit, r.insertOffset+int64(len(r.pattern)))
	if patternStart < patternEnd {
		copyStart := patternStart - off
		patternOffset := patternStart - r.insertOffset
		copy(p[copyStart:copyStart+(patternEnd-patternStart)], r.pattern[patternOffset:patternOffset+(patternEnd-patternStart)])
	}

	call := atomic.AddUint64(&r.readCalls, 1)
	r.observeReqLen(uint64(len(p)))
	if call <= 16 || call%1024 == 0 || (patternStart < patternEnd) {
		logPatternedReaderf(
			"patternedReaderAt.ReadAt call=%d off=%d req_len=%d limit=%d pattern_overlap=%t",
			call,
			off,
			len(p),
			limit,
			patternStart < patternEnd,
		)
	}

	if limit < int64(len(p)) {
		return int(limit), io.EOF
	}
	return int(limit), nil
}

func newPatternedReaderAt(size int64, insertOffset int64, pattern []byte) *patternedReaderAt {
	return &patternedReaderAt{
		size:         size,
		insertOffset: insertOffset,
		pattern:      pattern,
	}
}

func (r *patternedReaderAt) Read(p []byte) (int, error) {
	n, err := r.ReadAt(p, r.cursor)
	r.cursor += int64(n)
	return n, err
}

func (r *patternedReaderAt) observeReqLen(reqLen uint64) {
	if reqLen == 0 {
		return
	}
	if reqLen < uint64(testUffdChunkSize) {
		atomic.AddUint64(&r.partialCalls, 1)
	}
	for {
		current := atomic.LoadUint64(&r.minReqLen)
		if current != 0 && current <= reqLen {
			break
		}
		if atomic.CompareAndSwapUint64(&r.minReqLen, current, reqLen) {
			break
		}
	}
	for {
		current := atomic.LoadUint64(&r.maxReqLen)
		if current >= reqLen {
			break
		}
		if atomic.CompareAndSwapUint64(&r.maxReqLen, current, reqLen) {
			break
		}
	}
}

func (r *patternedReaderAt) stats() (calls, minReqLen, maxReqLen, partialCalls uint64) {
	return atomic.LoadUint64(&r.readCalls),
		atomic.LoadUint64(&r.minReqLen),
		atomic.LoadUint64(&r.maxReqLen),
		atomic.LoadUint64(&r.partialCalls)
}

func minInt64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func logPatternedReaderf(format string, args ...interface{}) {
	if os.Getenv("YARAX_UFFD_TRACE") == "" {
		return
	}
	fmt.Fprintf(os.Stderr, "patternedReaderAt: "+format+"\n", args...)
}

func parseUffdSummary(t *testing.T, tracePath string) map[string]uint64 {
	t.Helper()

	data, err := os.ReadFile(tracePath)
	require.NoError(t, err)

	var summaryLine string
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(line, "userfaultfd trace summary:") {
			summaryLine = line
			break
		}
	}
	require.NotEmpty(t, summaryLine, "expected userfaultfd trace summary in %s", tracePath)
	t.Logf("userfaultfd_summary %s", summaryLine)

	stats := make(map[string]uint64)
	for _, field := range strings.Fields(summaryLine) {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		parsed, err := strconv.ParseUint(strings.TrimRight(value, ","), 10, 64)
		if err == nil {
			stats[key] = parsed
		}
	}
	return stats
}

func initialiseExperimentalAllocator(t *testing.T) {
	t.Helper()
	experimentalInitOnce.Do(func() {
		experimentalInitErr = yara_x.Initialise(experimental.UseMmapMemoryAllocator())
	})
	if experimentalInitErr != nil && !strings.Contains(experimentalInitErr.Error(), "already locked after initialization") {
		require.NoError(t, experimentalInitErr)
	}
}

func maybeStartTimedProfiles(t *testing.T) {
	t.Helper()

	cpuPath := strings.TrimSpace(os.Getenv("YARAX_UFFD_CPU_PROFILE_FILE"))
	tracePath := strings.TrimSpace(os.Getenv("YARAX_UFFD_RUNTIME_TRACE_FILE"))
	if cpuPath == "" && tracePath == "" {
		return
	}

	duration := 30 * time.Second
	if raw := strings.TrimSpace(os.Getenv("YARAX_UFFD_PROFILE_DURATION")); raw != "" {
		if parsed, err := time.ParseDuration(raw); err == nil && parsed > 0 {
			duration = parsed
		}
	}

	var (
		stopOnce sync.Once
		stopFns  []func()
	)

	if cpuPath != "" {
		file, err := os.Create(cpuPath)
		require.NoError(t, err)
		require.NoError(t, pprof.StartCPUProfile(file))
		stopFns = append(stopFns, func() {
			pprof.StopCPUProfile()
			_ = file.Close()
		})
	}

	if tracePath != "" {
		file, err := os.Create(tracePath)
		require.NoError(t, err)
		require.NoError(t, trace.Start(file))
		stopFns = append(stopFns, func() {
			trace.Stop()
			_ = file.Close()
		})
	}

	stopProfiles := func() {
		stopOnce.Do(func() {
			for _, stop := range stopFns {
				stop()
			}
		})
	}

	time.AfterFunc(duration, stopProfiles)
	t.Cleanup(stopProfiles)
	t.Logf("timed profiling enabled for %s (cpu=%q trace=%q)", duration, cpuPath, tracePath)
}

func TestScanReaderAtWithExperimentalUserfaultfdAllocator(t *testing.T) {
	if os.Getenv("YARAX_EXPERIMENTAL_UFFD") != "1" {
		t.Skip("set YARAX_EXPERIMENTAL_UFFD=1 to run userfaultfd-backed integration tests")
	}

	initialiseExperimentalAllocator(t)
	maybeStartTimedProfiles(t)

	data := bytes.Repeat([]byte("prefix-"), 900)
	data = append(data, []byte("readerat-mapped-sentinel")...)
	data = append(data, bytes.Repeat([]byte("-suffix"), 900)...)

	rules, err := yara_x.Compile(`rule t { strings: $a = "readerat-mapped-sentinel" condition: $a }`)
	require.NoError(t, err)
	defer rules.Destroy()

	scanner := yara_x.NewScanner(rules)
	defer scanner.Destroy()

	results, err := scanner.ScanReaderAt(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)
	require.Len(t, results.MatchingRules(), 1)
}

func TestScanReaderAtWithPatternedReaderMatchesExpectedOffset(t *testing.T) {
	if os.Getenv("YARAX_EXPERIMENTAL_UFFD") != "1" {
		t.Skip("set YARAX_EXPERIMENTAL_UFFD=1 to run userfaultfd-backed integration tests")
	}

	initialiseExperimentalAllocator(t)
	maybeStartTimedProfiles(t)

	const totalSize = int64(30 << 20)
	pattern := []byte("readerat-random-offset-match")
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	insertOffset := rng.Int63n(totalSize - int64(len(pattern)) + 1)
	t.Logf("virtual_size=%d insert_offset=%d pattern_length=%d", totalSize, insertOffset, len(pattern))

	tracePath := t.TempDir() + "/userfaultfd-trace.log"
	t.Setenv("YARAX_UFFD_TRACE", "1")
	t.Setenv("YARAX_UFFD_TRACE_FILE", tracePath)
	t.Setenv("YARAX_UFFD_TRACE_EVERY", "1000000000")

	reader := newPatternedReaderAt(totalSize, insertOffset, pattern)

	rules, err := yara_x.Compile(`rule t { strings: $a = "readerat-random-offset-match" condition: $a }`)
	require.NoError(t, err)
	defer rules.Destroy()

	scanner := yara_x.NewScanner(rules)
	defer scanner.Destroy()

	results, err := scanner.ScanReaderAt(reader, totalSize)
	require.NoError(t, err)
	require.Len(t, results.MatchingRules(), 1)

	matches := results.MatchingRules()[0].Patterns()
	require.Len(t, matches, 1)
	patternMatches := matches[0].Matches()
	require.Len(t, patternMatches, 1)
	require.Equal(t, uint64(insertOffset), patternMatches[0].Offset())

	calls, minReqLen, maxReqLen, partialCalls := reader.stats()
	expectedMinChunkCalls := (insertOffset + int64(len(pattern)) - 1) / int64(testUffdChunkSize)
	expectedMinChunkCalls++
	expectedMaxChunkCalls := (totalSize + int64(testUffdChunkSize) - 1) / int64(testUffdChunkSize)
	t.Logf(
		"reader_stats calls=%d expected_chunk_call_range=[%d,%d] expected_chunk_size=%d min_req_len=%d max_req_len=%d partial_calls=%d",
		calls,
		expectedMinChunkCalls,
		expectedMaxChunkCalls,
		testUffdChunkSize,
		minReqLen,
		maxReqLen,
		partialCalls,
	)

	uffdStats := parseUffdSummary(t, tracePath)
	t.Logf(
		"uffd_stats faults=%d move_calls=%d total_move_bytes=%d min_move_bytes=%d max_move_bytes=%d partial_move_calls=%d",
		uffdStats["faults"],
		uffdStats["move_calls"],
		uffdStats["total_move_bytes"],
		uffdStats["min_move_bytes"],
		uffdStats["max_move_bytes"],
		uffdStats["partial_move_calls"],
	)

	require.Greater(t, calls, uint64(0))
	require.GreaterOrEqual(t, int64(calls), expectedMinChunkCalls)
	require.LessOrEqual(t, int64(calls), expectedMaxChunkCalls)
	require.Equal(t, uint64(testUffdChunkSize), minReqLen)
	require.Equal(t, uint64(testUffdChunkSize), maxReqLen)
	require.Zero(t, partialCalls)

	require.Greater(t, uffdStats["faults"], uint64(0))
	require.GreaterOrEqual(t, int64(uffdStats["faults"]), expectedMinChunkCalls)
	require.LessOrEqual(t, int64(uffdStats["faults"]), expectedMaxChunkCalls)
	require.Equal(t, calls, uffdStats["faults"])
	require.Equal(t, calls, uffdStats["move_calls"])
	require.Equal(t, uint64(testUffdChunkSize), uffdStats["min_move_bytes"])
	require.Equal(t, uint64(testUffdChunkSize), uffdStats["max_move_bytes"])
	require.Zero(t, uffdStats["partial_move_calls"])
}
