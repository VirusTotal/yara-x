package yara_x

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/VirusTotal/yara-x/go-wasm/internal/module"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	wazeroexperimental "github.com/tetratelabs/wazero/experimental"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

const (
	yrxSuccess            = 0
	yrxSyntaxError        = 1
	yrxVariableError      = 2
	yrxScanError          = 3
	yrxScanTimeout        = 4
	yrxInvalidArgument    = 5
	yrxInvalidUTF8        = 6
	yrxInvalidState       = 7
	yrxSerializationError = 8
	yrxNoMetadata         = 9
	yrxNotSupported       = 10
)

const (
	guestABIVersion          = 6
	guestExportABIVersion    = "go_yrx_abi_version"
	guestExportVersion       = "go_yrx_version"
	guestExportBufferPtr     = "go_yrx_buffer_ptr"
	guestExportBufferLen     = "go_yrx_buffer_len"
	guestExportBufferDestroy = "go_yrx_buffer_destroy"
)

type packedCallResult struct {
	code    int32
	payload uint32
}

type guestWasmSource struct {
	path  string
	bytes []byte
	set   bool
}

type guestProgram struct {
	ctx             context.Context
	rt              wazero.Runtime
	host            *hostRuntime
	compiled        wazero.CompiledModule
	memoryAllocator wazeroexperimental.MemoryAllocator
	nextID          uint64
}

type guestClient struct {
	ctx     context.Context
	program *guestProgram
	guestID uint64
	guest   api.Module
	realloc api.Function
	exports map[string]api.Function
	// Calls within one guest instance stay serialized because a single object
	// is still not goroutine-safe. Parallelism comes from distinct instances.
	mu sync.Mutex
}

var (
	guestModuleNameSeq  uint64
	guestWasmBytes      []byte
	errGuestWasm        error
	guestWasmOnce       sync.Once
	guestWasmSourceMu   sync.Mutex
	guestWasmSourceCfg  guestWasmSource
	guestMemoryAllocCfg wazeroexperimental.MemoryAllocator
	guestMemoryAlloc    wazeroexperimental.MemoryAllocator
	guestWasmLocked     bool
	guestRuntimeConfig  wazero.RuntimeConfig
	guestRuntimeOnce    sync.Once
	sharedGuestProgram  *guestProgram
	errSharedGuest      error
	sharedGuestOnce     sync.Once
)

func configureGuestWasmSource(opts ...InitialiseOption) error {
	if len(opts) == 0 {
		return nil
	}

	var cfg initialiseConfig
	for _, opt := range opts {
		if opt == nil {
			return errors.New("nil InitialiseOption")
		}
		if err := opt.applyInitialise(&cfg); err != nil {
			return err
		}
	}

	guestWasmSourceMu.Lock()
	defer guestWasmSourceMu.Unlock()

	if guestWasmLocked {
		return errors.New("guest wasm source is already locked after initialization")
	}

	if cfg.hasSource {
		guestWasmSourceCfg = guestWasmSource{
			path:  cfg.source.path,
			bytes: slices.Clone(cfg.source.bytes),
			set:   true,
		}
	} else {
		guestWasmSourceCfg = guestWasmSource{}
	}
	guestMemoryAllocCfg = cfg.memoryAllocator
	return nil
}

func loadGuestWasm() ([]byte, error) {
	guestWasmOnce.Do(func() {
		guestWasmSourceMu.Lock()
		source := guestWasmSource{
			path:  guestWasmSourceCfg.path,
			bytes: slices.Clone(guestWasmSourceCfg.bytes),
		}
		guestMemoryAlloc = guestMemoryAllocCfg
		guestWasmLocked = true
		guestWasmSourceMu.Unlock()

		switch {
		case source.path != "":
			guestWasmBytes, errGuestWasm = os.ReadFile(source.path)
			if errGuestWasm != nil {
				errGuestWasm = fmt.Errorf("read guest wasm at %q: %w", source.path, errGuestWasm)
			}
			return
		case source.set:
			guestWasmBytes = source.bytes
			return
		}

		path := os.Getenv("YARAX_GUEST_WASM")

		if path != "" {
			guestWasmBytes, errGuestWasm = os.ReadFile(path)
			if errGuestWasm != nil {
				errGuestWasm = fmt.Errorf("read guest wasm at %q: %w", path, errGuestWasm)
			}
			return
		}

		guestWasmBytes, errGuestWasm = module.DecompressedWASM()
		if errGuestWasm != nil {
			errGuestWasm = fmt.Errorf(
				"load embedded guest wasm (or set YARAX_GUEST_WASM, or call Initialise with GuestWASMPath/GuestWASMReader when built with no_embed_wasm): %w",
				errGuestWasm,
			)
		}
	})

	if errGuestWasm != nil {
		return nil, errGuestWasm
	}
	return guestWasmBytes, nil
}

func runtimeConfig() wazero.RuntimeConfig {
	guestRuntimeOnce.Do(func() {
		cache := wazero.NewCompilationCache()
		guestRuntimeConfig = wazero.NewRuntimeConfig().WithCompilationCache(cache)
	})
	return guestRuntimeConfig
}

func ensureGuestProgram() (*guestProgram, error) {
	sharedGuestOnce.Do(func() {
		sharedGuestProgram, errSharedGuest = createGuestProgram()
	})
	if errSharedGuest != nil {
		return nil, errSharedGuest
	}
	return sharedGuestProgram, nil
}

func newGuestClient() (*guestClient, error) {
	program, err := ensureGuestProgram()
	if err != nil {
		return nil, err
	}
	return program.newClient()
}

func createGuestProgram() (*guestProgram, error) {
	guestWasm, err := loadGuestWasm()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	rt := wazero.NewRuntimeWithConfig(ctx, runtimeConfig())

	if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("instantiate WASI preview1: %w", err)
	}

	host := newHostRuntime(rt)
	if err := host.instantiateHostBridge(ctx); err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("instantiate host bridge: %w", err)
	}

	compiled, err := rt.CompileModule(ctx, guestWasm)
	if err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("compile guest module: %w", err)
	}

	return &guestProgram{
		ctx:             ctx,
		rt:              rt,
		host:            host,
		compiled:        compiled,
		memoryAllocator: guestMemoryAlloc,
	}, nil
}

func (p *guestProgram) newClient() (*guestClient, error) {
	guestID := atomic.AddUint64(&p.nextID, 1)
	ctx := p.ctx
	if p.memoryAllocator != nil {
		ctx = wazeroexperimental.WithMemoryAllocator(ctx, p.memoryAllocator)
	}

	moduleName := fmt.Sprintf("yarax_guest_%d", atomic.AddUint64(&guestModuleNameSeq, 1))
	cfg := wazero.NewModuleConfig().
		WithName(moduleName).
		WithFSConfig(wazero.NewFSConfig().WithDirMount("/", "/")).
		WithStderr(os.Stderr)

	guest, err := p.rt.InstantiateModule(ctx, p.compiled, cfg)
	if err != nil {
		return nil, fmt.Errorf("instantiate guest module: %w", err)
	}

	// Inventory-based export registration in the guest depends on constructors.
	// Explicitly invoke wasm constructors when available to ensure they run
	// under runtimes that don't execute them automatically on instantiation.
	if ctors := guest.ExportedFunction("__wasm_call_ctors"); ctors != nil {
		if _, err := ctors.Call(ctx); err != nil {
			_ = guest.Close(ctx)
			return nil, fmt.Errorf("invoke guest constructors: %w", err)
		}
	}

	realloc := guest.ExportedFunction("cabi_realloc")
	if realloc == nil {
		realloc = guest.ExportedFunction("cabi_realloc_wit_bindgen_0_46_0")
	}
	if realloc == nil {
		_ = guest.Close(ctx)
		return nil, errors.New("guest allocator export not found")
	}

	client := &guestClient{
		ctx:     ctx,
		program: p,
		guestID: guestID,
		guest:   guest,
		realloc: realloc,
		exports: map[string]api.Function{},
	}

	abiVersion, err := client.callU32(guestExportABIVersion)
	if err != nil {
		_ = guest.Close(ctx)
		return nil, fmt.Errorf("read guest ABI version: %w", err)
	}
	if abiVersion != guestABIVersion {
		_ = guest.Close(ctx)
		return nil, fmt.Errorf("unsupported guest ABI version %d (expected %d)", abiVersion, guestABIVersion)
	}

	p.host.registerGuest(guestID, guest, realloc)
	return client, nil
}

func (c *guestClient) close() {
	if c == nil || c.guest == nil {
		return
	}
	_ = c.program.host.destroySession(c.ctx, c.guestID)
	c.program.host.unregisterGuest(c.guestID)
	_ = c.guest.Close(c.ctx)
	c.guest = nil
	c.realloc = nil
	c.exports = nil
	c.guestID = 0
}

func (c *guestClient) setConsoleOutput(w io.Writer) {
	c.program.host.setGuestConsoleOutput(c.guestID, w)
}

func (c *guestClient) resetConsoleError() {
	c.program.host.resetGuestConsoleError(c.guestID)
}

func (c *guestClient) takeConsoleError() error {
	return c.program.host.takeGuestConsoleError(c.guestID)
}

func (c *guestClient) memory() api.Memory {
	return c.guest.Memory()
}

func (c *guestClient) export(name string) (api.Function, error) {
	if fn := c.exports[name]; fn != nil {
		return fn, nil
	}
	fn := c.guest.ExportedFunction(name)
	if fn == nil {
		return nil, fmt.Errorf("guest export %q not found", name)
	}
	c.exports[name] = fn
	return fn, nil
}

func (c *guestClient) call(name string, params ...uint64) ([]uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fn, err := c.export(name)
	if err != nil {
		return nil, err
	}

	return fn.Call(c.ctx, params...)
}

func (c *guestClient) callU32(name string, params ...uint64) (uint32, error) {
	out, err := c.call(name, params...)
	if err != nil {
		return 0, err
	}
	if len(out) != 1 {
		return 0, fmt.Errorf("guest export %q returned %d values, expected 1", name, len(out))
	}
	return u32FromUint64(out[0], fmt.Sprintf("guest export %q result", name))
}

func (c *guestClient) callResult(name string, params ...uint64) (packedCallResult, error) {
	out, err := c.call(name, params...)
	if err != nil {
		return packedCallResult{}, err
	}
	if len(out) != 1 {
		return packedCallResult{}, fmt.Errorf("guest export %q returned %d values, expected 1", name, len(out))
	}
	code, err := u32FromUint64(out[0]>>32, fmt.Sprintf("guest export %q status code", name))
	if err != nil {
		return packedCallResult{}, err
	}
	payload, err := u32FromUint64(out[0]&math.MaxUint32, fmt.Sprintf("guest export %q payload", name))
	if err != nil {
		return packedCallResult{}, err
	}
	return packedCallResult{
		code:    i32FromBits(code),
		payload: payload,
	}, nil
}

func (c *guestClient) alloc(size, align uint32) (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if align == 0 {
		align = 1
	}
	requestSize := size
	if requestSize == 0 {
		requestSize = 1
	}

	out, err := c.realloc.Call(c.ctx, 0, 0, uint64(align), uint64(requestSize))
	if err != nil {
		return 0, err
	}
	if len(out) != 1 {
		return 0, fmt.Errorf("allocator returned %d values, expected 1", len(out))
	}
	ptr, err := u32FromUint64(out[0], "guest allocator result")
	if err != nil {
		return 0, err
	}
	if ptr == 0 {
		return 0, errors.New("guest allocator returned null pointer")
	}
	return ptr, nil
}

func (c *guestClient) free(ptr, oldSize, align uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ptr == 0 {
		return
	}
	if align == 0 {
		align = 1
	}
	if oldSize == 0 {
		oldSize = 1
	}
	_, _ = c.realloc.Call(c.ctx, uint64(ptr), uint64(oldSize), uint64(align), 0)
}

func (c *guestClient) allocAndWrite(data []byte, align uint32) (uint32, uint32, error) {
	dataLen, err := u32FromLen(len(data), "guest write length")
	if err != nil {
		return 0, 0, err
	}
	ptr, err := c.alloc(dataLen, align)
	if err != nil {
		return 0, 0, err
	}
	c.mu.Lock()
	writeOK := len(data) == 0 || c.memory().Write(ptr, data)
	c.mu.Unlock()
	if !writeOK {
		c.free(ptr, dataLen, align)
		return 0, 0, fmt.Errorf("write %d bytes to guest memory at %d failed", len(data), ptr)
	}
	return ptr, dataLen, nil
}

func (c *guestClient) errorFromResult(result packedCallResult) error {
	if result.code == yrxSuccess {
		return nil
	}
	if result.code == yrxScanTimeout {
		return ErrTimeout
	}

	if result.payload == 0 {
		return fmt.Errorf("yara guest error code %d", result.code)
	}

	var out error
	err := c.withBufferView(result.payload, func(msg []byte) error {
		if result.code == yrxSyntaxError {
			var compileErr CompileError
			if err := json.Unmarshal(msg, &compileErr); err == nil && compileErr.Type != "" {
				out = &compileErr
				return nil
			}
		}
		if len(msg) == 0 {
			out = fmt.Errorf("yara guest error code %d", result.code)
			return nil
		}
		out = errors.New(string(msg))
		return nil
	})
	if err != nil {
		return err
	}
	return out
}

func (c *guestClient) readAndFreeBuffer(handle uint32) ([]byte, error) {
	var out []byte
	err := c.withBufferView(handle, func(data []byte) error {
		out = slices.Clone(data)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *guestClient) withBufferView(handle uint32, fn func([]byte) error) error {
	if handle == 0 {
		return errors.New("guest returned null buffer handle")
	}
	defer func() {
		_, _ = c.call(guestExportBufferDestroy, uint64(handle))
	}()

	ptr, err := c.callU32(guestExportBufferPtr, uint64(handle))
	if err != nil {
		return err
	}
	length, err := c.callU32(guestExportBufferLen, uint64(handle))
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if length == 0 {
		return fn(nil)
	}
	data, ok := c.memory().Read(ptr, length)
	if !ok {
		return fmt.Errorf("out-of-bounds read at %d with length %d", ptr, length)
	}
	return fn(data)
}

func (c *guestClient) callStatus(name string, params ...uint64) error {
	result, err := c.callResult(name, params...)
	if err != nil {
		return err
	}
	return c.errorFromResult(result)
}

func (c *guestClient) callHandle(name string, params ...uint64) (uint32, error) {
	result, err := c.callResult(name, params...)
	if err != nil {
		return 0, err
	}
	if result.code != yrxSuccess {
		return 0, c.errorFromResult(result)
	}
	if result.payload == 0 {
		return 0, fmt.Errorf("guest export %q returned null handle on success", name)
	}
	return result.payload, nil
}

func (c *guestClient) callInt32(name string, params ...uint64) (int32, error) {
	result, err := c.callResult(name, params...)
	if err != nil {
		return 0, err
	}
	if result.code != yrxSuccess {
		return 0, c.errorFromResult(result)
	}
	return i32FromBits(result.payload), nil
}

func (c *guestClient) writeString(s string) (uint32, uint32, error) {
	return c.allocAndWrite([]byte(s), 1)
}
