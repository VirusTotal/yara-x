package yara_x

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/wazero/api"
	wazeroexperimental "github.com/tetratelabs/wazero/experimental"

	"github.com/VirusTotal/yara-x/go-wasm/internal/module"
)

type testErrReader struct {
	err error
}

func (r testErrReader) Read(_ []byte) (int, error) {
	return 0, r.err
}

func resetGuestBootstrapForTesting(t *testing.T) {
	t.Helper()

	if sharedGuestProgram != nil {
		require.NoError(t, sharedGuestProgram.rt.Close(sharedGuestProgram.ctx))
	}

	guestWasmSourceMu.Lock()
	defer guestWasmSourceMu.Unlock()

	guestWasmBytes = nil
	errGuestWasm = nil
	guestWasmOnce = sync.Once{}
	guestWasmSourceCfg = guestWasmSource{}
	guestMemoryAllocCfg = nil
	guestMemoryAlloc = nil
	guestWasmLocked = false
	sharedGuestProgram = nil
	errSharedGuest = nil
	sharedGuestOnce = sync.Once{}
	versionOnce = sync.Once{}
	versionText = ""
	errVersion = nil
}

type countingMemoryAllocator struct {
	count int
}

type nopMappedRegion struct{}

func (nopMappedRegion) Close() error { return nil }

type fakeFileMappingAllocator struct {
	countingMemoryAllocator
	mapCalls int
}

type fakeReaderAtMappingAllocator struct {
	countingMemoryAllocator
	mapCalls int
}

type testLinearMemory struct {
	buf []byte
}

func (m *testLinearMemory) Reallocate(size uint64) []byte {
	sizeLen := int(size)
	if uint64(cap(m.buf)) < size {
		next := make([]byte, sizeLen)
		copy(next, m.buf)
		m.buf = next
	} else {
		m.buf = m.buf[:sizeLen]
	}
	return m.buf
}

func (m *testLinearMemory) Free() {
	m.buf = nil
}

func (a *countingMemoryAllocator) Allocate(capacity, max uint64) wazeroexperimental.LinearMemory {
	a.count++
	_ = max
	mem := &testLinearMemory{}
	mem.Reallocate(capacity)
	return mem
}

func (a *fakeFileMappingAllocator) MapFileToGuest(mem api.Memory, guestOffset, mappedLength uint32, path string) (GuestMappedRegion, error) {
	a.mapCalls++
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	requireLen := len(data)
	if mappedLength < uint32(requireLen) {
		return nil, fmt.Errorf("mapped guest window too small")
	}
	if !mem.Write(guestOffset, data) {
		return nil, fmt.Errorf("write fake mapped file to guest memory failed")
	}
	return nopMappedRegion{}, nil
}

func (a *fakeReaderAtMappingAllocator) MapReaderAtToGuest(mem api.Memory, guestOffset, mappedLength uint32, src io.ReaderAt, size int64) (GuestMappedRegion, error) {
	a.mapCalls++
	if size < 0 {
		return nil, fmt.Errorf("invalid negative size")
	}
	data := make([]byte, int(size))
	if _, err := src.ReadAt(data, 0); err != nil && !(errors.Is(err, io.EOF) && len(data) > 0) {
		return nil, err
	}
	if mappedLength < uint32(len(data)) {
		return nil, fmt.Errorf("mapped guest window too small")
	}
	if !mem.Write(guestOffset, data) {
		return nil, fmt.Errorf("write fake mapped reader to guest memory failed")
	}
	return nopMappedRegion{}, nil
}

func TestGuestABIBufferLifecycle(t *testing.T) {
	client, err := newGuestClient()
	if err != nil {
		t.Fatalf("new guest client: %v", err)
	}
	defer client.close()

	compiler, err := client.callHandle(
		"go_yrx_compiler_create",
		0,
	)
	if err != nil {
		t.Fatalf("compiler create call failed: %v", err)
	}
	defer func() { _, _ = client.call("go_yrx_compiler_destroy", uint64(compiler)) }()

	src := "rule t { condition: true }"
	srcPtr, srcLen, err := client.writeString(src)
	if err != nil {
		t.Fatalf("write source: %v", err)
	}
	defer client.free(srcPtr, srcLen, 1)

	if err := client.callStatus("go_yrx_compiler_add_source_with_origin", uint64(compiler), uint64(srcPtr), uint64(srcLen), 0, 0); err != nil {
		t.Fatalf("add source call failed: %v", err)
	}

	rules, err := client.callHandle("go_yrx_compiler_build", uint64(compiler))
	if err != nil {
		t.Fatalf("build call failed: %v", err)
	}
	defer func() { _, _ = client.call("go_yrx_rules_destroy", uint64(rules)) }()

	bufHandle, err := client.callHandle("go_yrx_rules_serialize", uint64(rules))
	if err != nil {
		t.Fatalf("serialize call failed: %v", err)
	}

	serialized, err := client.readAndFreeBuffer(bufHandle)
	if err != nil {
		t.Fatalf("read serialized buffer failed: %v", err)
	}
	assert.NotEmpty(t, serialized)
}

func TestInitialise(t *testing.T) {
	assert.NoError(t, Initialise())
	assert.NotNil(t, sharedGuestProgram)

	assert.NoError(t, Initialise())

	client, err := newGuestClient()
	if err != nil {
		t.Fatalf("new guest client after initialise: %v", err)
	}
	client.close()
}

func TestInitialiseWithGuestWASMPath(t *testing.T) {
	resetGuestBootstrapForTesting(t)
	t.Cleanup(func() { resetGuestBootstrapForTesting(t) })

	wasm, err := module.DecompressedWASM()
	require.NoError(t, err)

	tmp, err := os.CreateTemp(t.TempDir(), "yarax-guest-*.wasm")
	require.NoError(t, err)
	require.NoError(t, tmp.Close())
	require.NoError(t, os.WriteFile(tmp.Name(), wasm, 0o600))

	require.NoError(t, Initialise(GuestWASMPath(tmp.Name())))
	assert.NotNil(t, sharedGuestProgram)

	client, err := newGuestClient()
	require.NoError(t, err)
	client.close()
}

func TestInitialiseWithGuestWASMReader(t *testing.T) {
	resetGuestBootstrapForTesting(t)
	t.Cleanup(func() { resetGuestBootstrapForTesting(t) })

	wasm, err := module.DecompressedWASM()
	require.NoError(t, err)

	require.NoError(t, Initialise(GuestWASMReader(bytes.NewReader(wasm))))
	assert.NotNil(t, sharedGuestProgram)

	client, err := newGuestClient()
	require.NoError(t, err)
	client.close()
}

func TestInitialiseRejectsMultipleGuestWAMSSources(t *testing.T) {
	resetGuestBootstrapForTesting(t)
	t.Cleanup(func() { resetGuestBootstrapForTesting(t) })

	err := Initialise(
		GuestWASMPath("/tmp/yarax.wasm"),
		GuestWASMReader(bytes.NewReader([]byte("wasm"))),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "multiple guest wasm sources configured")
}

func TestInitialiseRejectsReconfigurationAfterBootstrap(t *testing.T) {
	resetGuestBootstrapForTesting(t)
	t.Cleanup(func() { resetGuestBootstrapForTesting(t) })

	require.NoError(t, Initialise())
	err := Initialise(GuestWASMReader(bytes.NewReader([]byte("wasm"))))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already locked after initialization")
}

func TestInitialiseReaderOptionError(t *testing.T) {
	resetGuestBootstrapForTesting(t)
	t.Cleanup(func() { resetGuestBootstrapForTesting(t) })

	err := Initialise(GuestWASMReader(testErrReader{err: io.ErrUnexpectedEOF}))
	require.Error(t, err)
	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestInitialiseWithMemoryAllocator(t *testing.T) {
	resetGuestBootstrapForTesting(t)
	t.Cleanup(func() { resetGuestBootstrapForTesting(t) })

	allocator := &countingMemoryAllocator{}

	require.NoError(t, Initialise(WithMemoryAllocator(allocator)))
	assert.NotNil(t, sharedGuestProgram)
	assert.Zero(t, allocator.count)

	client, err := newGuestClient()
	require.NoError(t, err)
	client.close()

	assert.Greater(t, allocator.count, 0)
}

func TestScanFileUsesMappedGuestFilePathWhenAvailable(t *testing.T) {
	resetGuestBootstrapForTesting(t)
	t.Cleanup(func() { resetGuestBootstrapForTesting(t) })

	allocator := &fakeFileMappingAllocator{}
	require.NoError(t, Initialise(WithMemoryAllocator(allocator)))

	rules, err := Compile(`rule t { strings: $a = "mapped" condition: $a }`)
	require.NoError(t, err)
	defer rules.Destroy()
	scanner := NewScanner(rules)
	defer scanner.Destroy()

	file := filepath.Join(t.TempDir(), "mapped.bin")
	require.NoError(t, os.WriteFile(file, []byte("mapped data"), 0o600))

	results, err := scanner.ScanFile(file)
	require.NoError(t, err)
	require.Len(t, results.MatchingRules(), 1)
	require.Equal(t, 1, allocator.mapCalls)
}

func TestScanReaderAtUsesMappedGuestReaderAtPathWhenAvailable(t *testing.T) {
	resetGuestBootstrapForTesting(t)
	t.Cleanup(func() { resetGuestBootstrapForTesting(t) })

	allocator := &fakeReaderAtMappingAllocator{}
	require.NoError(t, Initialise(WithMemoryAllocator(allocator)))

	rules, err := Compile(`rule t { strings: $a = "mapped" condition: $a }`)
	require.NoError(t, err)
	defer rules.Destroy()
	scanner := NewScanner(rules)
	defer scanner.Destroy()

	results, err := scanner.ScanReaderAt(bytes.NewReader([]byte("mapped data")), int64(len("mapped data")))
	require.NoError(t, err)
	require.Len(t, results.MatchingRules(), 1)
	require.Equal(t, 1, allocator.mapCalls)
}

func TestGuestABIVersion(t *testing.T) {
	client, err := newGuestClient()
	if err != nil {
		t.Fatalf("new guest client: %v", err)
	}
	defer client.close()

	version, err := client.callU32(guestExportABIVersion)
	if err != nil {
		t.Fatalf("read guest ABI version: %v", err)
	}

	assert.Equal(t, uint32(guestABIVersion), version)
}

func TestCallResultKeepsErrorBufferAfterInterleavedCall(t *testing.T) {
	client, err := newGuestClient()
	if err != nil {
		t.Fatalf("new guest client: %v", err)
	}
	defer client.close()

	compiler, err := client.callHandle(
		"go_yrx_compiler_create",
		0,
	)
	if err != nil {
		t.Fatalf("compiler create failed: %v", err)
	}
	defer func() { _, _ = client.call("go_yrx_compiler_destroy", uint64(compiler)) }()

	result, err := client.callResult(
		"go_yrx_compiler_add_source_with_origin",
		uint64(compiler),
		0,
		1,
		0,
		0,
	)
	if err != nil {
		t.Fatalf("call result failed: %v", err)
	}
	assert.Equal(t, int32(yrxInvalidArgument), result.code)
	assert.NotZero(t, result.payload)

	otherCompiler, err := client.callHandle(
		"go_yrx_compiler_create",
		0,
	)
	if err != nil {
		t.Fatalf("interleaved compiler create failed: %v", err)
	}
	defer func() { _, _ = client.call("go_yrx_compiler_destroy", uint64(otherCompiler)) }()

	err = client.errorFromResult(result)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "null pointer with non-zero length")
	}
}

func TestWithBufferViewDestroysHandleOnSuccess(t *testing.T) {
	client, err := newGuestClient()
	if err != nil {
		t.Fatalf("new guest client: %v", err)
	}
	defer client.close()

	handle, err := client.callHandle(guestExportVersion)
	if err != nil {
		t.Fatalf("get version buffer handle: %v", err)
	}

	var got []byte
	err = client.withBufferView(handle, func(data []byte) error {
		got = slices.Clone(data)
		return nil
	})
	if err != nil {
		t.Fatalf("with buffer view: %v", err)
	}
	assert.NotEmpty(t, got)

	handle2, err := client.callHandle(guestExportVersion)
	if err != nil {
		t.Fatalf("get second version buffer handle: %v", err)
	}
	buf2, err := client.readAndFreeBuffer(handle2)
	if err != nil {
		t.Fatalf("read second version buffer: %v", err)
	}
	assert.Equal(t, string(got), string(buf2))
}

func TestWithBufferViewDestroysHandleOnError(t *testing.T) {
	client, err := newGuestClient()
	if err != nil {
		t.Fatalf("new guest client: %v", err)
	}
	defer client.close()

	handle, err := client.callHandle(guestExportVersion)
	if err != nil {
		t.Fatalf("get version buffer handle: %v", err)
	}

	want := errors.New("sentinel")
	err = client.withBufferView(handle, func([]byte) error {
		return want
	})
	assert.ErrorIs(t, err, want)

	handle2, err := client.callHandle(guestExportVersion)
	if err != nil {
		t.Fatalf("get second version buffer handle: %v", err)
	}
	buf2, err := client.readAndFreeBuffer(handle2)
	if err != nil {
		t.Fatalf("read second version buffer: %v", err)
	}
	assert.NotEmpty(t, buf2)
}

func TestReadAndFreeBufferReturnsDetachedCopy(t *testing.T) {
	client, err := newGuestClient()
	if err != nil {
		t.Fatalf("new guest client: %v", err)
	}
	defer client.close()

	handle, err := client.callHandle(guestExportVersion)
	if err != nil {
		t.Fatalf("get version buffer handle: %v", err)
	}

	buf, err := client.readAndFreeBuffer(handle)
	if err != nil {
		t.Fatalf("read and free version buffer: %v", err)
	}

	handle2, err := client.callHandle(guestExportVersion)
	if err != nil {
		t.Fatalf("get second version buffer handle: %v", err)
	}
	defer func() { _, _ = client.call(guestExportBufferDestroy, uint64(handle2)) }()

	ptr2, err := client.callU32(guestExportBufferPtr, uint64(handle2))
	if err != nil {
		t.Fatalf("read second buffer ptr: %v", err)
	}
	require.True(t, client.memory().Write(ptr2, []byte("X")))
	assert.NotEqual(t, byte('X'), buf[0])
}

func TestErrorFromResultReturnsErrTimeoutWithoutReadingPayload(t *testing.T) {
	client, err := newGuestClient()
	if err != nil {
		t.Fatalf("new guest client: %v", err)
	}
	defer client.close()

	err = client.errorFromResult(packedCallResult{
		code:    yrxScanTimeout,
		payload: math.MaxUint32,
	})
	assert.ErrorIs(t, err, ErrTimeout)
}

func TestMetadataJSONContract(t *testing.T) {
	rules, err := Compile(`rule t {
		meta:
			i = 1
			f = 2.5
			b = true
			s = "hello"
			x = "\x01\x02"
		condition:
			true
	}`)
	assert.NoError(t, err)
	defer rules.Destroy()

	res, err := rules.Scan(nil)
	assert.NoError(t, err)
	assert.Len(t, res.MatchingRules(), 1)

	meta := res.MatchingRules()[0].Metadata()
	assert.Len(t, meta, 5)

	assert.Equal(t, int64(1), meta[0].Value())
	assert.Equal(t, float64(2.5), meta[1].Value())
	assert.Equal(t, true, meta[2].Value())
	assert.Equal(t, "hello", meta[3].Value())
	assert.Equal(t, []byte{0x01, 0x02}, meta[4].Value())
}

func TestLookupCallbacksSelectiveSync(t *testing.T) {
	rules, err := Compile(`
		import "test_proto2"
		rule t {
			condition:
				test_proto2.int32_zero == 0 and
				test_proto2.array_string[1] == "bar" and
				test_proto2.map_string_struct["foo"].nested_int64_one == 1
		}`)
	assert.NoError(t, err)
	defer rules.Destroy()

	results, err := rules.Scan([]byte("foo"))
	assert.NoError(t, err)
	assert.Len(t, results.MatchingRules(), 1)
}

func TestModuleExportCallbacksSelectiveSync(t *testing.T) {
	rules, err := Compile(`
		import "test_proto2"
		rule t {
			condition:
				test_proto2.uppercase("foo") == "FOO"
		}`)
	assert.NoError(t, err)
	defer rules.Destroy()

	results, err := rules.Scan([]byte("foo"))
	assert.NoError(t, err)
	assert.Len(t, results.MatchingRules(), 1)
}

func TestParallelScanners(t *testing.T) {
	rules, err := Compile(`rule t { strings: $a = "foo" condition: $a }`)
	assert.NoError(t, err)
	defer rules.Destroy()

	s1 := NewScanner(rules)
	defer s1.Destroy()
	s2 := NewScanner(rules)
	defer s2.Destroy()

	var wg sync.WaitGroup
	wg.Add(2)

	results := make([]*ScanResults, 2)
	errs := make([]error, 2)

	go func() {
		defer wg.Done()
		results[0], errs[0] = s1.Scan([]byte("foo"))
	}()

	go func() {
		defer wg.Done()
		results[1], errs[1] = s2.Scan([]byte("foo"))
	}()

	wg.Wait()

	assert.NoError(t, errs[0])
	assert.NoError(t, errs[1])
	assert.Len(t, results[0].MatchingRules(), 1)
	assert.Len(t, results[1].MatchingRules(), 1)
}

func TestConcurrentScansAndCompilesStress(t *testing.T) {
	rules, err := Compile(`rule t { strings: $a = "foo" condition: $a }`)
	assert.NoError(t, err)
	defer rules.Destroy()

	const scanWorkers = 4
	const scanIterations = 32
	const compileWorkers = 4
	const compileIterations = 16

	scanners := make([]*Scanner, 0, scanWorkers)
	for i := 0; i < scanWorkers; i++ {
		scanner := NewScanner(rules)
		scanners = append(scanners, scanner)
	}
	defer func() {
		for _, scanner := range scanners {
			scanner.Destroy()
		}
	}()

	errs := make(chan error, scanWorkers*scanIterations+compileWorkers*compileIterations)
	var wg sync.WaitGroup

	for i, scanner := range scanners {
		wg.Add(1)
		go func(worker int, s *Scanner) {
			defer wg.Done()
			for iter := 0; iter < scanIterations; iter++ {
				results, err := s.Scan([]byte("foo"))
				if err != nil {
					errs <- fmt.Errorf("scan worker %d iteration %d: %w", worker, iter, err)
					return
				}
				if len(results.MatchingRules()) != 1 {
					errs <- fmt.Errorf("scan worker %d iteration %d: got %d matches", worker, iter, len(results.MatchingRules()))
					return
				}
			}
		}(i, scanner)
	}

	for worker := 0; worker < compileWorkers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for iter := 0; iter < compileIterations; iter++ {
				compiler, err := NewCompiler()
				if err != nil {
					errs <- fmt.Errorf("compile worker %d iteration %d: new compiler: %w", worker, iter, err)
					return
				}

				if err := compiler.AddSource(`rule ok { condition: true }`); err != nil {
					compiler.Destroy()
					errs <- fmt.Errorf("compile worker %d iteration %d: add source: %w", worker, iter, err)
					return
				}

				built := compiler.Build()
				if got := len(built.Slice()); got != 1 {
					built.Destroy()
					compiler.Destroy()
					errs <- fmt.Errorf("compile worker %d iteration %d: got %d rules", worker, iter, got)
					return
				}

				built.Destroy()
				compiler.Destroy()
			}
		}(worker)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatal(err)
	}
}

func TestConcurrentCompileErrorIsolation(t *testing.T) {
	var wg sync.WaitGroup
	wg.Add(2)

	errs := make(chan error, 2)

	go func() {
		defer wg.Done()
		_, err := Compile(`rule broken { condition: foo }`)
		errs <- err
	}()

	go func() {
		defer wg.Done()
		rules, err := Compile(`rule ok { condition: true }`)
		if err == nil {
			rules.Destroy()
		}
		errs <- err
	}()

	wg.Wait()
	close(errs)

	var gotSyntaxError bool
	var gotUnexpected error

	for err := range errs {
		switch {
		case err == nil:
		case containsUnknownIdentifier(err):
			gotSyntaxError = true
		default:
			gotUnexpected = err
		}
	}

	assert.NoError(t, gotUnexpected)
	assert.True(t, gotSyntaxError, "expected one concurrent compile to preserve the syntax error")
}

func containsUnknownIdentifier(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, &CompileError{Type: CompileErrorTypeUnknownIdentifier})
}

func BenchmarkGuestInstantiation(b *testing.B) {
	client, err := newGuestClient()
	if err != nil {
		b.Fatalf("warm shared guest program: %v", err)
	}
	client.close()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		client, err := newGuestClient()
		if err != nil {
			b.Fatalf("new guest client: %v", err)
		}
		client.close()
	}
}
