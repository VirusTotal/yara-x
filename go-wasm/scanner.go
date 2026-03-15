package yara_x

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"time"

	easyjson "github.com/mailru/easyjson"
	"google.golang.org/protobuf/proto"
)

// Scanner scans data with a set of compiled YARA rules.
type Scanner struct {
	client          *guestClient
	handle          uint32
	rulesHandle     uint32
	rules           *Rules
	timeout         time.Duration
	globals         map[string]scannerGlobalValue
	hasModuleOutput bool
}

type scannerGlobalKind uint8

const (
	scannerGlobalInt scannerGlobalKind = iota
	scannerGlobalBool
	scannerGlobalString
	scannerGlobalFloat
	scannerGlobalJSON
)

const scanReaderBlockSize = 64 << 10
const experimentalGuestHugePageSize uint32 = 2 << 20

type scannerGlobalValue struct {
	kind scannerGlobalKind
	i64  int64
	b    bool
	str  string
	f64  float64
	json easyjson.RawMessage
}

// ScanResults contains the results of a call to [Scanner.Scan] or [Rules.Scan].
type ScanResults struct {
	matchingRules []*Rule
}

// MatchingRules returns the rules that matched during the scan.
func (s ScanResults) MatchingRules() []*Rule {
	return s.matchingRules
}

// NewScanner creates a Scanner that will use the provided YARA rules.
func NewScanner(r *Rules) *Scanner {
	if r == nil {
		panic("rules object is destroyed")
	}

	serialized, err := r.serializeBytes()
	if err != nil {
		panic(err)
	}

	client, err := newGuestClient()
	if err != nil {
		panic(err)
	}

	ptr, length, err := client.allocAndWrite(serialized, 1)
	if err != nil {
		client.close()
		panic(err)
	}
	defer client.free(ptr, length, 1)

	rulesHandle, err := client.callHandle(
		"go_yrx_rules_deserialize",
		uint64(ptr),
		uint64(length),
	)
	if err != nil {
		client.close()
		panic(err)
	}

	scannerHandle, err := client.callHandle(
		"go_yrx_scanner_create",
		uint64(rulesHandle),
		client.guestID,
	)
	if err != nil {
		_, _ = client.call("go_yrx_rules_destroy", uint64(rulesHandle))
		client.close()
		panic(err)
	}

	s := &Scanner{
		client:      client,
		handle:      scannerHandle,
		rulesHandle: rulesHandle,
		rules:       r,
		globals:     map[string]scannerGlobalValue{},
	}

	runtime.SetFinalizer(s, (*Scanner).Destroy)
	return s
}

// SetTimeout sets a timeout for scan operations.
func (s *Scanner) SetTimeout(timeout time.Duration) {
	if timeout < 0 {
		timeout = 0
	}
	if err := s.client.callStatus(
		"go_yrx_scanner_set_timeout",
		uint64(s.handle),
		uint64(math.Ceil(timeout.Seconds())),
	); err != nil {
		panic(err)
	}
	s.timeout = timeout
}

// SetConsoleOutput sets the destination for messages emitted by the `console`
// module during subsequent scans on this scanner.
//
// Passing nil disables console output. If the writer also implements
// `Flush() error` or `Flush()`, it is flushed after each emitted message.
func (s *Scanner) SetConsoleOutput(w io.Writer) {
	if s == nil || s.client == nil {
		panic("scanner is destroyed")
	}
	s.client.setConsoleOutput(w)
}

// ErrTimeout is returned when a scan operation exceeds the configured timeout.
var ErrTimeout = errors.New("timeout")

var errScanReaderModulesUnsupported = errors.New("ScanReader does not support rules that import modules")
var errScanReaderModuleOutputUnsupported = errors.New("ScanReader does not support module outputs")

// SetGlobal sets the value of a global variable.
func (s *Scanner) SetGlobal(ident string, value interface{}) error {
	identPtr, identLen, err := s.client.writeString(ident)
	if err != nil {
		return err
	}
	defer s.client.free(identPtr, identLen, 1)

	switch v := value.(type) {
	case int:
		err = s.client.callStatus("go_yrx_scanner_set_global_int", uint64(s.handle), uint64(identPtr), uint64(identLen), u64FromI64Bits(int64(v)))
	case int32:
		err = s.client.callStatus("go_yrx_scanner_set_global_int", uint64(s.handle), uint64(identPtr), uint64(identLen), u64FromI64Bits(int64(v)))
	case int64:
		err = s.client.callStatus("go_yrx_scanner_set_global_int", uint64(s.handle), uint64(identPtr), uint64(identLen), u64FromI64Bits(v))
	case bool:
		var b uint64
		if v {
			b = 1
		}
		err = s.client.callStatus("go_yrx_scanner_set_global_bool", uint64(s.handle), uint64(identPtr), uint64(identLen), b)
	case string:
		valuePtr, valueLen, allocErr := s.client.writeString(v)
		if allocErr != nil {
			return allocErr
		}
		defer s.client.free(valuePtr, valueLen, 1)
		err = s.client.callStatus("go_yrx_scanner_set_global_str", uint64(s.handle), uint64(identPtr), uint64(identLen), uint64(valuePtr), uint64(valueLen))
	case float64:
		err = s.client.callStatus("go_yrx_scanner_set_global_float", uint64(s.handle), uint64(identPtr), uint64(identLen), math.Float64bits(v))
	case map[string]interface{}, []interface{}:
		jsonBytes, marshalErr := json.Marshal(v)
		if marshalErr != nil {
			return fmt.Errorf("failed to marshal %q to json: %w", ident, marshalErr)
		}
		valuePtr, valueLen, allocErr := s.client.allocAndWrite(jsonBytes, 1)
		if allocErr != nil {
			return allocErr
		}
		defer s.client.free(valuePtr, valueLen, 1)
		err = s.client.callStatus("go_yrx_scanner_set_global_json", uint64(s.handle), uint64(identPtr), uint64(identLen), uint64(valuePtr), uint64(valueLen))
	default:
		return fmt.Errorf("variable `%s` has unsupported type: %T", ident, v)
	}

	if err != nil {
		return err
	}

	mirrored, mirrorErr := newScannerGlobalValue(value)
	if mirrorErr != nil {
		return mirrorErr
	}
	if s.globals == nil {
		s.globals = map[string]scannerGlobalValue{}
	}
	s.globals[ident] = mirrored

	return nil
}

// ScanReader scans data streamed from an [io.Reader].
//
// This uses YARA-X block scanning internally, so it inherits the same
// limitations: imported modules are not supported, module outputs cannot be
// supplied, and matches that span block boundaries may be missed.
func (s *Scanner) ScanReader(r io.Reader) (*ScanResults, error) {
	if r == nil {
		return nil, errors.New("reader is nil")
	}
	if len(s.rules.Imports()) > 0 {
		return &ScanResults{}, errScanReaderModulesUnsupported
	}
	if s.hasModuleOutput {
		return &ScanResults{}, errScanReaderModuleOutputUnsupported
	}

	s.client.resetConsoleError()

	blockScanner, err := s.client.callHandle(
		"go_yrx_block_scanner_create",
		uint64(s.rulesHandle),
		s.client.guestID,
	)
	if err != nil {
		return nil, err
	}
	defer func() {
		_, _ = s.client.call("go_yrx_block_scanner_destroy", uint64(blockScanner))
	}()

	if s.timeout > 0 {
		if err := s.client.callStatus(
			"go_yrx_block_scanner_set_timeout",
			uint64(blockScanner),
			uint64(math.Ceil(s.timeout.Seconds())),
		); err != nil {
			return nil, err
		}
	}

	for ident, value := range s.globals {
		if err := s.setBlockScannerGlobal(blockScanner, ident, value); err != nil {
			return nil, err
		}
	}

	buf := make([]byte, scanReaderBlockSize)
	var offset uint64
	noProgress := 0

	for {
		n, readErr := r.Read(buf)
		if n > 0 {
			noProgress = 0

			dataPtr, dataLen, err := s.client.allocAndWrite(buf[:n], 1)
			if err != nil {
				return nil, err
			}

			result, callErr := s.client.callResult(
				"go_yrx_block_scanner_scan",
				uint64(blockScanner),
				offset,
				uint64(dataPtr),
				uint64(dataLen),
			)
			s.client.free(dataPtr, dataLen, 1)
			if callErr != nil {
				return nil, callErr
			}
			if result.code == yrxScanTimeout {
				return &ScanResults{}, ErrTimeout
			}
			if result.code != yrxSuccess {
				return &ScanResults{}, s.client.errorFromResult(result)
			}

			offset += uint64(dataLen)
		} else if readErr == nil {
			noProgress++
			if noProgress > 8 {
				return nil, io.ErrNoProgress
			}
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, readErr
		}
	}

	result, err := s.client.callResult("go_yrx_block_scanner_finish", uint64(blockScanner))
	if err != nil {
		return nil, err
	}
	scanResults, err := s.finishScan(result)
	if err != nil {
		return scanResults, err
	}
	if err := s.client.takeConsoleError(); err != nil {
		return scanResults, err
	}
	return scanResults, nil
}

func (s *Scanner) setBlockScannerGlobal(
	blockScanner uint32,
	ident string,
	value scannerGlobalValue,
) error {
	identPtr, identLen, err := s.client.writeString(ident)
	if err != nil {
		return err
	}
	defer s.client.free(identPtr, identLen, 1)

	switch value.kind {
	case scannerGlobalInt:
		return s.client.callStatus(
			"go_yrx_block_scanner_set_global_int",
			uint64(blockScanner),
			uint64(identPtr),
			uint64(identLen),
			u64FromI64Bits(value.i64),
		)
	case scannerGlobalBool:
		var b uint64
		if value.b {
			b = 1
		}
		return s.client.callStatus(
			"go_yrx_block_scanner_set_global_bool",
			uint64(blockScanner),
			uint64(identPtr),
			uint64(identLen),
			b,
		)
	case scannerGlobalString:
		valuePtr, valueLen, err := s.client.writeString(value.str)
		if err != nil {
			return err
		}
		defer s.client.free(valuePtr, valueLen, 1)
		return s.client.callStatus(
			"go_yrx_block_scanner_set_global_str",
			uint64(blockScanner),
			uint64(identPtr),
			uint64(identLen),
			uint64(valuePtr),
			uint64(valueLen),
		)
	case scannerGlobalFloat:
		return s.client.callStatus(
			"go_yrx_block_scanner_set_global_float",
			uint64(blockScanner),
			uint64(identPtr),
			uint64(identLen),
			math.Float64bits(value.f64),
		)
	case scannerGlobalJSON:
		valuePtr, valueLen, err := s.client.allocAndWrite(value.json, 1)
		if err != nil {
			return err
		}
		defer s.client.free(valuePtr, valueLen, 1)
		return s.client.callStatus(
			"go_yrx_block_scanner_set_global_json",
			uint64(blockScanner),
			uint64(identPtr),
			uint64(identLen),
			uint64(valuePtr),
			uint64(valueLen),
		)
	default:
		return fmt.Errorf("unsupported mirrored scanner global kind %d", value.kind)
	}
}

func newScannerGlobalValue(value interface{}) (scannerGlobalValue, error) {
	switch v := value.(type) {
	case int:
		return scannerGlobalValue{kind: scannerGlobalInt, i64: int64(v)}, nil
	case int32:
		return scannerGlobalValue{kind: scannerGlobalInt, i64: int64(v)}, nil
	case int64:
		return scannerGlobalValue{kind: scannerGlobalInt, i64: v}, nil
	case bool:
		return scannerGlobalValue{kind: scannerGlobalBool, b: v}, nil
	case string:
		return scannerGlobalValue{kind: scannerGlobalString, str: v}, nil
	case float64:
		return scannerGlobalValue{kind: scannerGlobalFloat, f64: v}, nil
	case map[string]interface{}, []interface{}:
		jsonBytes, err := json.Marshal(v)
		if err != nil {
			return scannerGlobalValue{}, err
		}
		return scannerGlobalValue{
			kind: scannerGlobalJSON,
			json: easyjson.RawMessage(jsonBytes),
		}, nil
	default:
		return scannerGlobalValue{}, fmt.Errorf("unsupported mirrored scanner global type: %T", v)
	}
}

// SetModuleOutput sets the serialized output for a module used by subsequent
// scans on this scanner.
func (s *Scanner) SetModuleOutput(data proto.Message) error {
	buf, err := proto.Marshal(data)
	if err != nil {
		return err
	}

	name := string(data.ProtoReflect().Descriptor().FullName())
	namePtr, nameLen, err := s.client.writeString(name)
	if err != nil {
		return err
	}
	defer s.client.free(namePtr, nameLen, 1)

	dataPtr, dataLen, err := s.client.allocAndWrite(buf, 1)
	if err != nil {
		return err
	}
	defer s.client.free(dataPtr, dataLen, 1)

	err = s.client.callStatus(
		"go_yrx_scanner_set_module_output",
		uint64(s.handle),
		uint64(namePtr),
		uint64(nameLen),
		uint64(dataPtr),
		uint64(dataLen),
	)
	if err == nil {
		s.hasModuleOutput = true
	}
	return err
}

func (s *Scanner) readMatchingRules(bufHandle uint32) ([]*Rule, error) {
	var encoded ruleJSONList
	if err := s.client.withBufferView(bufHandle, func(payload []byte) error {
		return unmarshalWireJSON(payload, &encoded)
	}); err != nil {
		return nil, err
	}

	rules := make([]*Rule, 0, len(encoded))
	for _, item := range encoded {
		rule, err := decodeRuleJSON(item)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}

	return rules, nil
}

func (s *Scanner) finishScan(result packedCallResult) (*ScanResults, error) {
	switch result.code {
	case yrxSuccess:
		matchingRules, err := s.readMatchingRules(result.payload)
		if err != nil {
			return nil, err
		}
		return &ScanResults{matchingRules: matchingRules}, nil
	case yrxScanTimeout:
		return &ScanResults{}, ErrTimeout
	default:
		return &ScanResults{}, s.client.errorFromResult(result)
	}
}

func (s *Scanner) scanGuestRange(dataPtr, dataLen uint32) (*ScanResults, error) {
	s.client.resetConsoleError()
	result, err := s.client.callResult("go_yrx_scanner_scan", uint64(s.handle), uint64(dataPtr), uint64(dataLen))
	if err != nil {
		return nil, err
	}
	s.hasModuleOutput = false

	scanResults, err := s.finishScan(result)
	if err != nil {
		return scanResults, err
	}
	if err := s.client.takeConsoleError(); err != nil {
		return scanResults, err
	}
	return scanResults, nil
}

// Scan scans the provided data with the Rules associated to the Scanner.
func (s *Scanner) Scan(buf []byte) (*ScanResults, error) {
	dataPtr, dataLen, err := s.client.allocAndWrite(buf, 1)
	if err != nil {
		return nil, err
	}
	defer s.client.free(dataPtr, dataLen, 1)

	return s.scanGuestRange(dataPtr, dataLen)
}

// ScanReaderAt scans data exposed through an [io.ReaderAt].
//
// When the configured guest-memory allocator supports it, the reader may be
// exposed directly through guest memory without copying. Otherwise, the input
// is copied into guest memory before scanning.
func (s *Scanner) ScanReaderAt(reader io.ReaderAt, size int64) (*ScanResults, error) {
	if reader == nil {
		return nil, errors.New("reader is nil")
	}
	if size < 0 {
		return nil, errors.New("scan size must be non-negative")
	}
	if size > int64(math.MaxUint32) {
		return nil, fmt.Errorf("scan size %d exceeds wasm32 guest address space", size)
	}
	logUFFDTracef("ScanReaderAt start size=%d reader=%T guest_id=%d", size, reader, s.client.guestID)

	if scanResults, err, ok := s.scanMappedReaderAt(reader, size); ok {
		logUFFDTracef("ScanReaderAt completed via mapped path size=%d err=%v", size, err)
		return scanResults, err
	}
	logUFFDTracef("ScanReaderAt falling back to copied path size=%d reader=%T", size, reader)
	return s.scanCopiedReaderAt(reader, size)
}

// ScanFile scans a file with the Rules associated to the Scanner.
func (s *Scanner) ScanFile(path string) (*ScanResults, error) {
	if scanResults, err, ok := s.scanMappedFile(path); ok {
		return scanResults, err
	}

	s.client.resetConsoleError()
	pathPtr, pathLen, err := s.client.writeString(path)
	if err != nil {
		return nil, err
	}
	defer s.client.free(pathPtr, pathLen, 1)

	result, err := s.client.callResult("go_yrx_scanner_scan_file", uint64(s.handle), uint64(pathPtr), uint64(pathLen))
	if err != nil {
		return nil, err
	}
	s.hasModuleOutput = false

	scanResults, err := s.finishScan(result)
	if err != nil {
		return scanResults, err
	}
	if err := s.client.takeConsoleError(); err != nil {
		return scanResults, err
	}
	return scanResults, nil
}

func (s *Scanner) scanMappedFile(path string) (*ScanResults, error, bool) {
	mapper, ok := s.client.program.memoryAllocator.(GuestFileMapper)
	if !ok {
		return nil, nil, false
	}

	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, nil, false
	}
	if info.Size() <= 0 || info.Size() > int64(math.MaxUint32) {
		return nil, nil, false
	}

	fileLen, err := u32FromLen(int(info.Size()), "mapped file length")
	if err != nil {
		return nil, nil, false
	}
	mappedLen, err := roundUpToPage(fileLen)
	if err != nil {
		return nil, nil, false
	}

	s.client.resetConsoleError()

	ptr, err := s.client.alloc(mappedLen, pageSize)
	if err != nil {
		return nil, err, true
	}
	defer s.client.free(ptr, mappedLen, pageSize)

	region, err := mapper.MapFileToGuest(s.client.memory(), ptr, mappedLen, path)
	if err != nil {
		return nil, nil, false
	}
	scanResults, scanErr := s.scanGuestRange(ptr, fileLen)
	closeErr := region.Close()
	if scanErr != nil {
		return scanResults, scanErr, true
	}
	if closeErr != nil {
		return scanResults, closeErr, true
	}
	return scanResults, nil, true
}

func (s *Scanner) scanMappedReaderAt(reader io.ReaderAt, size int64) (*ScanResults, error, bool) {
	mapper, ok := s.client.program.memoryAllocator.(GuestReaderAtMapper)
	if !ok {
		logUFFDTracef("scanReaderAt: allocator does not implement GuestReaderAtMapper")
		return nil, nil, false
	}

	fileLen, err := u32FromLen(int(size), "mapped reader length")
	if err != nil {
		return nil, nil, false
	}
	mappedLen, err := roundUpToMultiple(fileLen, experimentalGuestHugePageSize)
	if err != nil {
		return nil, nil, false
	}

	ptr, err := s.client.alloc(mappedLen, experimentalGuestHugePageSize)
	if err != nil {
		return nil, err, true
	}
	defer s.client.free(ptr, mappedLen, experimentalGuestHugePageSize)

	region, err := mapper.MapReaderAtToGuest(s.client.memory(), ptr, mappedLen, reader, size)
	if err != nil {
		logUFFDTracef("scanReaderAt: falling back to copy path after MapReaderAtToGuest error: %v", err)
		return nil, nil, false
	}
	logUFFDTracef("scanReaderAt: mapped guest window ptr=%d mapped_len=%d size=%d", ptr, mappedLen, size)

	scanResults, scanErr := s.scanGuestRange(ptr, fileLen)
	closeErr := region.Close()
	if scanErr != nil {
		return scanResults, scanErr, true
	}
	if closeErr != nil {
		return scanResults, closeErr, true
	}
	return scanResults, nil, true
}

func (s *Scanner) scanCopiedReaderAt(reader io.ReaderAt, size int64) (*ScanResults, error) {
	logUFFDTracef("scanCopiedReaderAt start size=%d reader=%T", size, reader)
	dataLen, err := u32FromLen(int(size), "reader length")
	if err != nil {
		return nil, err
	}

	dataPtr, err := s.client.alloc(dataLen, 1)
	if err != nil {
		return nil, err
	}
	defer s.client.free(dataPtr, dataLen, 1)

	offset := uint32(0)
	noProgress := 0

	for offset < dataLen {
		remaining := dataLen - offset
		chunkLen := uint32(scanReaderBlockSize)
		if remaining < chunkLen {
			chunkLen = remaining
		}

		s.client.mu.Lock()
		view, ok := s.client.memory().Read(dataPtr+offset, chunkLen)
		s.client.mu.Unlock()
		if !ok {
			return nil, fmt.Errorf("read guest buffer window [%d,%d) failed", dataPtr+offset, dataPtr+offset+chunkLen)
		}

		n, readErr := reader.ReadAt(view, int64(offset))
		if n > 0 {
			offset += uint32(n)
			noProgress = 0
			if offset <= uint32(scanReaderBlockSize*4) || offset == dataLen || offset%(64<<20) == 0 {
				logUFFDTracef("scanCopiedReaderAt progress offset=%d/%d last_read=%d err=%v", offset, dataLen, n, readErr)
			}
		} else if readErr == nil {
			noProgress++
			if noProgress > 8 {
				return nil, io.ErrNoProgress
			}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) && offset == dataLen {
				break
			}
			return nil, readErr
		}
	}

	logUFFDTracef("scanCopiedReaderAt finished filling guest buffer size=%d", size)
	return s.scanGuestRange(dataPtr, dataLen)
}

func roundUpToPage(length uint32) (uint32, error) {
	return roundUpToMultiple(length, pageSize)
}

func roundUpToMultiple(length, multiple uint32) (uint32, error) {
	if length == 0 {
		return 0, nil
	}
	remainder := length % multiple
	if remainder == 0 {
		return length, nil
	}
	rounded := uint64(length) + uint64(multiple-remainder)
	if rounded > math.MaxUint32 {
		return 0, fmt.Errorf("rounded guest mapping length %d exceeds wasm32 address space", rounded)
	}
	return uint32(rounded), nil
}

// ProfilingInfo contains profiling information about a YARA rule.
type ProfilingInfo struct {
	Namespace           string
	Rule                string
	PatternMatchingTime time.Duration
	ConditionExecTime   time.Duration
}

type profilingInfoJSON struct {
	Namespace           string  `json:"n"`
	Rule                string  `json:"r"`
	PatternMatchingTime float64 `json:"p"`
	ConditionExecTime   float64 `json:"c"`
}

// SlowestRules returns information about the slowest rules.
func (s *Scanner) SlowestRules(n int) []ProfilingInfo {
	count, err := u32FromLen(n, "slowest-rules count")
	if err != nil {
		panic(err)
	}
	result, err := s.client.callResult("go_yrx_scanner_slowest_rules_json", uint64(s.handle), uint64(count))
	if err != nil {
		panic(err)
	}
	if result.code == yrxNotSupported {
		panic("SlowestRules requires that the YARA-X guest is built with rules profiling support")
	}
	if result.code != yrxSuccess {
		panic(s.client.errorFromResult(result))
	}

	bufHandle := result.payload
	var decoded profilingInfoJSONList
	if err := s.client.withBufferView(bufHandle, func(payload []byte) error {
		return unmarshalWireJSON(payload, &decoded)
	}); err != nil {
		panic(err)
	}

	profiling := make([]ProfilingInfo, 0, len(decoded))
	for _, item := range decoded {
		profiling = append(profiling, ProfilingInfo{
			Namespace:           item.Namespace,
			Rule:                item.Rule,
			PatternMatchingTime: time.Duration(item.PatternMatchingTime * float64(time.Second)),
			ConditionExecTime:   time.Duration(item.ConditionExecTime * float64(time.Second)),
		})
	}

	return profiling
}

// ClearProfilingData resets the profiling data collected during rule execution.
func (s *Scanner) ClearProfilingData() {
	result, err := s.client.callResult("go_yrx_scanner_clear_profiling_data", uint64(s.handle))
	if err != nil {
		panic(err)
	}
	if result.code == yrxNotSupported {
		panic("ClearProfilingData requires that the YARA-X guest is built with rules profiling support")
	}
	if result.code != yrxSuccess {
		panic(s.client.errorFromResult(result))
	}
}

// Destroy destroys the scanner.
func (s *Scanner) Destroy() {
	if s == nil {
		return
	}

	if s.client != nil && s.handle != 0 {
		_, _ = s.client.call("go_yrx_scanner_destroy", uint64(s.handle))
		s.handle = 0
	}
	if s.client != nil && s.rulesHandle != 0 {
		_, _ = s.client.call("go_yrx_rules_destroy", uint64(s.rulesHandle))
		s.rulesHandle = 0
	}
	if s.client != nil {
		s.client.close()
	}
	s.client = nil
	s.rules = nil

	runtime.SetFinalizer(s, nil)
}
