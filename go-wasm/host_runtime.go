package yara_x

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

const (
	yaraRuntimeHostModule = "yara:runtime/host"
	goConsoleHostModule   = "go:console/host"
	pageSize              = 65536
	hostCallTimeoutError  = "__yarax_timeout__"
	noTimeoutNanos        = ^uint64(0)
)

type valType uint32

const (
	valTypeI64 valType = iota
	valTypeI32
	valTypeF64Bits
	valTypeF32Bits
)

type globalState struct {
	typ     valType
	mutable bool
	value   uint64
}

type memoryState struct {
	initial uint32
	maximum *uint32
	data    []byte
}

type externKind uint32

const (
	externKindGlobal externKind = iota
	externKindMemory
)

const (
	callbackSyncBefore uint32 = 1 << 0
	callbackSyncAfter  uint32 = 1 << 1
)

type functionImport struct {
	module     string
	name       string
	callbackID uint64
	syncFlags  uint32
}

type externImport struct {
	module string
	name   string
	kind   externKind
	handle uint64
}

type instanceState struct {
	sessionID     uint64
	session       *hostSessionState
	rt            wazero.Runtime
	module        api.Module
	helperModules []api.Module
	externModules map[string]api.Module
	externs       []externImport
	exportMu      sync.Mutex
	exports       map[string]api.Function
	deadlineMu    sync.RWMutex
	deadline      time.Time
	hasDeadline   bool
}

func (i *instanceState) close(ctx context.Context) {
	if i.rt != nil {
		_ = i.rt.Close(ctx)
		i.rt = nil
		return
	}
	if i.module != nil {
		_ = i.module.Close(ctx)
		i.module = nil
	}
}

func (i *instanceState) beginCallDeadline(timeout time.Duration) func() {
	if timeout <= 0 {
		i.deadlineMu.Lock()
		i.deadline = time.Now()
		i.hasDeadline = true
		i.deadlineMu.Unlock()
		return func() {
			i.deadlineMu.Lock()
			i.hasDeadline = false
			i.deadline = time.Time{}
			i.deadlineMu.Unlock()
		}
	}

	i.deadlineMu.Lock()
	i.deadline = time.Now().Add(timeout)
	i.hasDeadline = true
	i.deadlineMu.Unlock()

	return func() {
		i.deadlineMu.Lock()
		i.hasDeadline = false
		i.deadline = time.Time{}
		i.deadlineMu.Unlock()
	}
}

func (i *instanceState) timedOut() bool {
	i.deadlineMu.RLock()
	defer i.deadlineMu.RUnlock()
	return i.hasDeadline && !time.Now().Before(i.deadline)
}

type hostSessionState struct {
	mu         sync.RWMutex
	nextHandle uint64
	globals    map[uint64]*globalState
	memories   map[uint64]*memoryState
	instances  map[uint64]*instanceState
}

type guestModuleState struct {
	module         api.Module
	realloc        api.Function
	callbackInvoke api.Function
	callbackPost   api.Function
	mu             sync.Mutex
	consoleMu      sync.Mutex
	console        io.Writer
	consoleErr     error
}

func newHostSessionState() *hostSessionState {
	return &hostSessionState{
		globals:   map[uint64]*globalState{},
		memories:  map[uint64]*memoryState{},
		instances: map[uint64]*instanceState{},
	}
}

func (s *hostSessionState) nextID() uint64 {
	s.nextHandle++
	return s.nextHandle
}

type hostRuntime struct {
	rt wazero.Runtime

	guestsMu   sync.RWMutex
	guests     map[uint64]*guestModuleState
	sessionsMu sync.RWMutex
	sessions   map[uint64]*hostSessionState
}

func newHostRuntime(rt wazero.Runtime) *hostRuntime {
	return &hostRuntime{
		rt:       rt,
		guests:   map[uint64]*guestModuleState{},
		sessions: map[uint64]*hostSessionState{},
	}
}

func (h *hostRuntime) registerGuest(
	guestID uint64,
	module api.Module,
	realloc api.Function,
) {
	h.guestsMu.Lock()
	h.guests[guestID] = &guestModuleState{
		module:         module,
		realloc:        realloc,
		callbackInvoke: module.ExportedFunction("yara:runtime/callbacks#invoke-callback"),
		callbackPost:   module.ExportedFunction("cabi_post_yara:runtime/callbacks#invoke-callback"),
	}
	h.guestsMu.Unlock()
}

func (h *hostRuntime) unregisterGuest(guestID uint64) {
	h.guestsMu.Lock()
	delete(h.guests, guestID)
	h.guestsMu.Unlock()
}

func (h *hostRuntime) guest(guestID uint64) (*guestModuleState, error) {
	h.guestsMu.RLock()
	guest := h.guests[guestID]
	h.guestsMu.RUnlock()
	if guest == nil {
		return nil, fmt.Errorf("unknown guest instance %d", guestID)
	}
	return guest, nil
}

func (h *hostRuntime) setGuestConsoleOutput(guestID uint64, w io.Writer) {
	guest, err := h.guest(guestID)
	if err != nil {
		return
	}
	guest.consoleMu.Lock()
	guest.console = w
	guest.consoleErr = nil
	guest.consoleMu.Unlock()
}

func (h *hostRuntime) resetGuestConsoleError(guestID uint64) {
	guest, err := h.guest(guestID)
	if err != nil {
		return
	}
	guest.consoleMu.Lock()
	guest.consoleErr = nil
	guest.consoleMu.Unlock()
}

func (h *hostRuntime) takeGuestConsoleError(guestID uint64) error {
	guest, err := h.guest(guestID)
	if err != nil {
		return nil
	}
	guest.consoleMu.Lock()
	defer guest.consoleMu.Unlock()
	err = guest.consoleErr
	guest.consoleErr = nil
	return err
}

func (h *hostRuntime) instantiateHostBridge(ctx context.Context) error {
	builder := h.rt.NewHostModuleBuilder(yaraRuntimeHostModule)

	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.validateModule),
		[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
		[]api.ValueType{},
	).Export("validate-module")

	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.globalNew),
		[]api.ValueType{api.ValueTypeI64, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI64, api.ValueTypeI32},
		[]api.ValueType{},
	).Export("global-new")

	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.globalGet),
		[]api.ValueType{api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI32, api.ValueTypeI32},
		[]api.ValueType{},
	).Export("global-get")

	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.globalSet),
		[]api.ValueType{api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI32, api.ValueTypeI64, api.ValueTypeI32},
		[]api.ValueType{},
	).Export("global-set")

	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.memoryNew),
		[]api.ValueType{api.ValueTypeI64, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
		[]api.ValueType{},
	).Export("memory-new")

	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.memoryRead),
		[]api.ValueType{api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI32},
		[]api.ValueType{},
	).Export("memory-read")

	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.memoryWrite),
		[]api.ValueType{api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
		[]api.ValueType{},
	).Export("memory-write")

	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.instantiate),
		[]api.ValueType{
			api.ValueTypeI64,
			api.ValueTypeI32,
			api.ValueTypeI32,
			api.ValueTypeI32,
			api.ValueTypeI32,
			api.ValueTypeI32,
			api.ValueTypeI32,
			api.ValueTypeI32,
		},
		[]api.ValueType{},
	).Export("instantiate")

	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.instanceDestroy),
		[]api.ValueType{api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI32},
		[]api.ValueType{},
	).Export("instance-destroy")

	builder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.callExport),
		[]api.ValueType{
			api.ValueTypeI64,
			api.ValueTypeI64,
			api.ValueTypeI32,
			api.ValueTypeI32,
			api.ValueTypeI32,
			api.ValueTypeI32,
			api.ValueTypeI32,
			api.ValueTypeI32,
			api.ValueTypeI64,
			api.ValueTypeI32,
		},
		[]api.ValueType{},
	).Export("call-export")

	if _, err := builder.Instantiate(ctx); err != nil {
		return err
	}

	consoleBuilder := h.rt.NewHostModuleBuilder(goConsoleHostModule)
	consoleBuilder.NewFunctionBuilder().WithGoModuleFunction(
		api.GoModuleFunc(h.consoleWriteMessage),
		[]api.ValueType{api.ValueTypeI64, api.ValueTypeI32, api.ValueTypeI32},
		[]api.ValueType{},
	).Export("write-message")

	_, err := consoleBuilder.Instantiate(ctx)
	return err
}

func (h *hostRuntime) session(sessionID uint64) (*hostSessionState, error) {
	if sessionID == 0 {
		return nil, errors.New("invalid zero session id")
	}

	h.sessionsMu.RLock()
	state := h.sessions[sessionID]
	h.sessionsMu.RUnlock()
	if state != nil {
		return state, nil
	}

	h.sessionsMu.Lock()
	defer h.sessionsMu.Unlock()

	if state = h.sessions[sessionID]; state != nil {
		return state, nil
	}

	state = newHostSessionState()
	h.sessions[sessionID] = state
	return state, nil
}

func (h *hostRuntime) destroySession(ctx context.Context, sessionID uint64) error {
	h.sessionsMu.Lock()
	state := h.sessions[sessionID]
	if state != nil {
		delete(h.sessions, sessionID)
	}
	h.sessionsMu.Unlock()
	if state == nil {
		return nil
	}
	return state.closeAllInstances(ctx)
}

func (h *hostRuntime) consoleWriteMessage(ctx context.Context, caller api.Module, stack []uint64) {
	guestID := stack[0]
	ptr, err := u32FromUint64(stack[1], "console message pointer")
	if err != nil {
		return
	}
	length, err := u32FromUint64(stack[2], "console message length")
	if err != nil {
		return
	}

	guest, err := h.guest(guestID)
	if err != nil {
		return
	}

	message, err := readBytes(caller.Memory(), ptr, length)
	if err != nil {
		guest.consoleMu.Lock()
		if guest.consoleErr == nil {
			guest.consoleErr = err
		}
		guest.consoleMu.Unlock()
		return
	}

	guest.consoleMu.Lock()
	defer guest.consoleMu.Unlock()

	if guest.console == nil || guest.consoleErr != nil {
		return
	}

	if _, err := guest.console.Write(message); err != nil {
		guest.consoleErr = err
		return
	}
	if _, err := guest.console.Write([]byte{'\n'}); err != nil {
		guest.consoleErr = err
		return
	}
	switch flusher := guest.console.(type) {
	case interface{ Flush() error }:
		if err := flusher.Flush(); err != nil {
			guest.consoleErr = err
		}
	case interface{ Flush() }:
		flusher.Flush()
	}
}

func (s *hostSessionState) closeAllInstances(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, inst := range s.instances {
		inst.close(ctx)
		delete(s.instances, id)
	}
	return nil
}

func (h *hostRuntime) validateModule(ctx context.Context, caller api.Module, stack []uint64) {
	mem := caller.Memory()
	retPtr, err := u32FromUint64(stack[2], "validate-module result pointer")
	if err != nil {
		return
	}
	modulePtr, err := u32FromUint64(stack[0], "validate-module module pointer")
	if err != nil {
		h.writeUnitResultErr(ctx, caller, retPtr, err.Error())
		return
	}
	moduleLen, err := u32FromUint64(stack[1], "validate-module module length")
	if err != nil {
		h.writeUnitResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	moduleBytes, err := readBytes(mem, modulePtr, moduleLen)
	if err != nil {
		h.writeUnitResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	compiled, err := h.rt.CompileModule(ctx, moduleBytes)
	if err != nil {
		h.writeUnitResultErr(ctx, caller, retPtr, err.Error())
		return
	}
	_ = compiled.Close(ctx)
	h.writeUnitResultOK(mem, retPtr)
}

func (h *hostRuntime) globalNew(ctx context.Context, caller api.Module, stack []uint64) {
	mem := caller.Memory()
	sessionID := stack[0]
	retPtr, err := u32FromUint64(stack[4], "global-new result pointer")
	if err != nil {
		return
	}
	rawType, err := u32FromUint64(stack[1], "global-new type")
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}
	typ := valType(rawType)
	mutable := stack[2] != 0
	value := stack[3]

	session, err := h.session(sessionID)
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	if typ > valTypeF32Bits {
		h.writeU64ResultErr(ctx, caller, retPtr, fmt.Sprintf("unsupported val-type %d", typ))
		return
	}

	session.mu.Lock()
	id := session.nextID()
	session.globals[id] = &globalState{
		typ:     typ,
		mutable: mutable,
		value:   value,
	}
	session.mu.Unlock()

	h.writeU64ResultOK(mem, retPtr, id)
}

func (h *hostRuntime) globalGet(ctx context.Context, caller api.Module, stack []uint64) {
	mem := caller.Memory()
	sessionID := stack[0]
	retPtr, err := u32FromUint64(stack[3], "global-get result pointer")
	if err != nil {
		return
	}
	id := stack[1]

	session, err := h.session(sessionID)
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	session.mu.RLock()
	global, ok := session.globals[id]
	var value uint64
	if ok {
		value = global.value
	}
	session.mu.RUnlock()
	if !ok {
		h.writeU64ResultErr(ctx, caller, retPtr, fmt.Sprintf("unknown global handle %d", id))
		return
	}

	h.writeU64ResultOK(mem, retPtr, value)
}

func (h *hostRuntime) globalSet(ctx context.Context, caller api.Module, stack []uint64) {
	mem := caller.Memory()
	sessionID := stack[0]
	retPtr, err := u32FromUint64(stack[4], "global-set result pointer")
	if err != nil {
		return
	}
	id := stack[1]
	value := stack[3]

	session, err := h.session(sessionID)
	if err != nil {
		h.writeUnitResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	session.mu.Lock()
	global, ok := session.globals[id]
	if !ok {
		session.mu.Unlock()
		h.writeUnitResultErr(ctx, caller, retPtr, fmt.Sprintf("unknown global handle %d", id))
		return
	}

	if !global.mutable {
		session.mu.Unlock()
		h.writeUnitResultErr(ctx, caller, retPtr, fmt.Sprintf("global %d is immutable", id))
		return
	}

	global.value = value
	session.mu.Unlock()
	h.writeUnitResultOK(mem, retPtr)
}

func (h *hostRuntime) memoryNew(ctx context.Context, caller api.Module, stack []uint64) {
	mem := caller.Memory()
	sessionID := stack[0]
	retPtr, err := u32FromUint64(stack[4], "memory-new result pointer")
	if err != nil {
		return
	}
	initialPages, err := u32FromUint64(stack[1], "memory-new initial pages")
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}
	maxTag, err := u32FromUint64(stack[2], "memory-new max tag")
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}
	maxRaw, err := u32FromUint64(stack[3], "memory-new max pages")
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	session, err := h.session(sessionID)
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	var maximum *uint32
	if maxTag != 0 {
		maxPages := maxRaw
		maximum = &maxPages
	}

	dataSize := int(initialPages) * pageSize
	session.mu.Lock()
	id := session.nextID()
	session.memories[id] = &memoryState{
		initial: initialPages,
		maximum: maximum,
		data:    make([]byte, dataSize),
	}
	session.mu.Unlock()

	h.writeU64ResultOK(mem, retPtr, id)
}

func (h *hostRuntime) memoryRead(ctx context.Context, caller api.Module, stack []uint64) {
	sessionID := stack[0]
	retPtr, err := u32FromUint64(stack[2], "memory-read result pointer")
	if err != nil {
		return
	}
	id := stack[1]

	session, err := h.session(sessionID)
	if err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	session.mu.RLock()
	memory, ok := session.memories[id]
	if !ok {
		session.mu.RUnlock()
		h.writeListResultErr(ctx, caller, retPtr, fmt.Sprintf("unknown memory handle %d", id))
		return
	}
	if err := h.writeBytesResultOK(ctx, caller, retPtr, memory.data); err != nil {
		session.mu.RUnlock()
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}
	session.mu.RUnlock()
}

func (h *hostRuntime) memoryWrite(ctx context.Context, caller api.Module, stack []uint64) {
	mem := caller.Memory()
	sessionID := stack[0]
	retPtr, err := u32FromUint64(stack[4], "memory-write result pointer")
	if err != nil {
		return
	}
	id := stack[1]
	dataPtr, err := u32FromUint64(stack[2], "memory-write data pointer")
	if err != nil {
		h.writeUnitResultErr(ctx, caller, retPtr, err.Error())
		return
	}
	dataLen, err := u32FromUint64(stack[3], "memory-write data length")
	if err != nil {
		h.writeUnitResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	session, err := h.session(sessionID)
	if err != nil {
		h.writeUnitResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	session.mu.RLock()
	_, ok := session.memories[id]
	session.mu.RUnlock()
	if !ok {
		h.writeUnitResultErr(ctx, caller, retPtr, fmt.Sprintf("unknown memory handle %d", id))
		return
	}

	var data []byte
	if dataLen > 0 {
		var readOK bool
		data, readOK = mem.Read(dataPtr, dataLen)
		if !readOK {
			h.writeUnitResultErr(ctx, caller, retPtr, fmt.Sprintf("out-of-bounds read at %d with length %d", dataPtr, dataLen))
			return
		}
	}

	session.mu.Lock()
	memory, ok := session.memories[id]
	if !ok {
		session.mu.Unlock()
		h.writeUnitResultErr(ctx, caller, retPtr, fmt.Sprintf("unknown memory handle %d", id))
		return
	}
	if cap(memory.data) < len(data) {
		memory.data = make([]byte, len(data))
	} else {
		memory.data = memory.data[:len(data)]
	}
	copy(memory.data, data)
	session.mu.Unlock()

	h.writeUnitResultOK(mem, retPtr)
}

func (h *hostRuntime) instantiate(ctx context.Context, caller api.Module, stack []uint64) {
	sessionID := stack[0]
	mem := caller.Memory()
	retPtr, err := u32FromUint64(stack[7], "instantiate result pointer")
	if err != nil {
		return
	}

	modulePtr, err := u32FromUint64(stack[1], "instantiate module pointer")
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}
	moduleLen, err := u32FromUint64(stack[2], "instantiate module length")
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}
	functionsPtr, err := u32FromUint64(stack[3], "instantiate function-import pointer")
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}
	functionsLen, err := u32FromUint64(stack[4], "instantiate function-import length")
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}
	externsPtr, err := u32FromUint64(stack[5], "instantiate extern-import pointer")
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}
	externsLen, err := u32FromUint64(stack[6], "instantiate extern-import length")
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	session, err := h.session(sessionID)
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	moduleBytes, err := readBytes(mem, modulePtr, moduleLen)
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	functionImports, err := parseFunctionImports(mem, functionsPtr, functionsLen)
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	externImports, err := parseExternImports(mem, externsPtr, externsLen)
	if err != nil {
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	instanceRT := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig())
	compiled, err := instanceRT.CompileModule(ctx, moduleBytes)
	if err != nil {
		_ = instanceRT.Close(ctx)
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	instance := &instanceState{
		sessionID:     sessionID,
		session:       session,
		rt:            instanceRT,
		helperModules: make([]api.Module, 0),
		externModules: make(map[string]api.Module),
		externs:       externImports,
		exports:       make(map[string]api.Function),
	}

	if err := h.instantiateFunctionModules(ctx, instanceRT, compiled, functionImports, instance); err != nil {
		_ = compiled.Close(ctx)
		instance.close(ctx)
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	if err := h.instantiateExternModules(ctx, instanceRT, externImports, instance); err != nil {
		_ = compiled.Close(ctx)
		instance.close(ctx)
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	if err := h.syncExternsToModules(instance); err != nil {
		_ = compiled.Close(ctx)
		instance.close(ctx)
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	session.mu.Lock()
	moduleName := fmt.Sprintf("yrx-rule-%d-%d", sessionID, session.nextID())
	session.mu.Unlock()
	module, err := instanceRT.InstantiateModule(
		ctx,
		compiled,
		wazero.NewModuleConfig().WithName(moduleName),
	)
	_ = compiled.Close(ctx)
	if err != nil {
		instance.close(ctx)
		h.writeU64ResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	instance.module = module
	session.mu.Lock()
	id := session.nextID()
	session.instances[id] = instance
	session.mu.Unlock()

	h.writeU64ResultOK(mem, retPtr, id)
}

func (h *hostRuntime) instanceDestroy(ctx context.Context, caller api.Module, stack []uint64) {
	mem := caller.Memory()
	sessionID := stack[0]
	instanceID := stack[1]
	retPtr, err := u32FromUint64(stack[2], "instance-destroy result pointer")
	if err != nil {
		return
	}

	session, err := h.session(sessionID)
	if err != nil {
		h.writeUnitResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	session.mu.Lock()
	instance, ok := session.instances[instanceID]
	if !ok {
		session.mu.Unlock()
		h.writeUnitResultErr(ctx, caller, retPtr, fmt.Sprintf("unknown instance handle %d", instanceID))
		return
	}

	instance.close(ctx)
	delete(session.instances, instanceID)
	session.mu.Unlock()
	h.writeUnitResultOK(mem, retPtr)
}

func (h *hostRuntime) callExport(ctx context.Context, caller api.Module, stack []uint64) {
	sessionID := stack[0]
	mem := caller.Memory()
	retPtr, err := u32FromUint64(stack[9], "call-export result pointer")
	if err != nil {
		return
	}

	instanceID := stack[1]
	namePtr, err := u32FromUint64(stack[2], "call-export name pointer")
	if err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}
	nameLen, err := u32FromUint64(stack[3], "call-export name length")
	if err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}
	paramsPtr, err := u32FromUint64(stack[4], "call-export params pointer")
	if err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}
	paramsLen, err := u32FromUint64(stack[5], "call-export params length")
	if err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}
	resultsPtr, err := u32FromUint64(stack[6], "call-export results pointer")
	if err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}
	resultsLen, err := u32FromUint64(stack[7], "call-export results length")
	if err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}
	timeoutNanos := stack[8]

	session, err := h.session(sessionID)
	if err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	session.mu.RLock()
	instance, ok := session.instances[instanceID]
	session.mu.RUnlock()
	if !ok {
		h.writeListResultErr(ctx, caller, retPtr, fmt.Sprintf("unknown instance handle %d", instanceID))
		return
	}

	exportName, err := readString(mem, namePtr, nameLen)
	if err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	paramsByteLen, err := checkedMul(paramsLen, 8)
	if err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	paramBytes, err := readBytes(mem, paramsPtr, paramsByteLen)
	if err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	params := make([]uint64, paramsLen)
	for i := range params {
		offset := i * 8
		params[i] = binary.LittleEndian.Uint64(paramBytes[offset : offset+8])
	}

	_, err = readBytes(mem, resultsPtr, resultsLen*4)
	if err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	if err := h.syncExternsToModules(instance); err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	instance.exportMu.Lock()
	fn := instance.exports[exportName]
	if fn == nil {
		fn = instance.module.ExportedFunction(exportName)
		if fn != nil {
			instance.exports[exportName] = fn
		}
	}
	instance.exportMu.Unlock()
	if fn == nil {
		h.writeListResultErr(ctx, caller, retPtr, fmt.Sprintf("missing export %q", exportName))
		return
	}

	clearDeadline := func() {}
	if timeoutNanos != noTimeoutNanos {
		timeout, convErr := durationFromNanos(timeoutNanos, "call-export timeout")
		if convErr != nil {
			h.writeListResultErr(ctx, caller, retPtr, convErr.Error())
			return
		}
		clearDeadline = instance.beginCallDeadline(timeout)
	}
	defer clearDeadline()

	out, err := fn.Call(ctx, params...)
	if err != nil {
		if strings.Contains(err.Error(), hostCallTimeoutError) {
			h.writeListResultErr(ctx, caller, retPtr, hostCallTimeoutError)
			return
		}
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	if err := h.syncExternsFromModules(instance); err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}

	outLen, err := u32FromLen(len(out), "call-export result count")
	if err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
		return
	}
	if outLen != resultsLen {
		h.writeListResultErr(
			ctx,
			caller,
			retPtr,
			fmt.Sprintf("unexpected result length: got %d want %d", len(out), resultsLen),
		)
		return
	}

	if err := h.writeU64ListResultOK(ctx, caller, retPtr, out); err != nil {
		h.writeListResultErr(ctx, caller, retPtr, err.Error())
	}
}

func (h *hostRuntime) instantiateFunctionModules(
	ctx context.Context,
	rt wazero.Runtime,
	compiled wazero.CompiledModule,
	callbacks []functionImport,
	instance *instanceState,
) error {
	callbackIDByName := make(map[string]uint64, len(callbacks))
	callbackSyncFlagsByName := make(map[string]uint32, len(callbacks))
	for _, c := range callbacks {
		callbackIDByName[importKey(c.module, c.name)] = c.callbackID
		callbackSyncFlagsByName[importKey(c.module, c.name)] = c.syncFlags
	}

	type exportDef struct {
		name       string
		callbackID uint64
		syncFlags  uint32
		params     []api.ValueType
		results    []api.ValueType
	}

	moduleExports := map[string][]exportDef{}
	seen := map[string]struct{}{}

	for _, def := range compiled.ImportedFunctions() {
		moduleName, importName, isImport := def.Import()
		if !isImport {
			continue
		}

		key := importKey(moduleName, importName)
		if _, done := seen[key]; done {
			continue
		}
		seen[key] = struct{}{}

		callbackID, ok := callbackIDByName[key]
		if !ok {
			return fmt.Errorf("missing callback mapping for import %s.%s", moduleName, importName)
		}

		moduleExports[moduleName] = append(moduleExports[moduleName], exportDef{
			name:       importName,
			callbackID: callbackID,
			syncFlags:  callbackSyncFlagsByName[key],
			params:     def.ParamTypes(),
			results:    def.ResultTypes(),
		})
	}

	moduleNames := make([]string, 0, len(moduleExports))
	for name := range moduleExports {
		moduleNames = append(moduleNames, name)
	}
	sort.Strings(moduleNames)

	for _, moduleName := range moduleNames {
		builder := rt.NewHostModuleBuilder(moduleName)
		exports := moduleExports[moduleName]
		sort.Slice(exports, func(i, j int) bool { return exports[i].name < exports[j].name })

		for _, export := range exports {
			callbackID := export.callbackID
			syncFlags := export.syncFlags
			paramTypes := export.params
			resultTypes := export.results

			builder.NewFunctionBuilder().WithGoModuleFunction(
				api.GoModuleFunc(func(ctx context.Context, _ api.Module, stack []uint64) {
					if err := h.invokeImportCallback(ctx, instance, callbackID, syncFlags, paramTypes, resultTypes, stack); err != nil {
						panic(err)
					}
				}),
				paramTypes,
				resultTypes,
			).Export(export.name)
		}

		mod, err := builder.Instantiate(ctx)
		if err != nil {
			return fmt.Errorf("instantiate callback module %q: %w", moduleName, err)
		}
		instance.helperModules = append(instance.helperModules, mod)
	}

	return nil
}

type externModuleSpec struct {
	name   string
	memory *externMemorySpec
	global []externGlobalSpec
}

type externMemorySpec struct {
	name  string
	state *memoryState
}

type externGlobalSpec struct {
	name  string
	state *globalState
}

func (h *hostRuntime) instantiateExternModules(
	ctx context.Context,
	rt wazero.Runtime,
	externs []externImport,
	instance *instanceState,
) error {
	specByModule := map[string]*externModuleSpec{}

	for _, ext := range externs {
		spec, ok := specByModule[ext.module]
		if !ok {
			spec = &externModuleSpec{name: ext.module}
			specByModule[ext.module] = spec
		}

		switch ext.kind {
		case externKindGlobal:
			instance.session.mu.RLock()
			state, ok := instance.session.globals[ext.handle]
			instance.session.mu.RUnlock()
			if !ok {
				return fmt.Errorf("unknown global handle %d", ext.handle)
			}
			spec.global = append(spec.global, externGlobalSpec{name: ext.name, state: state})
		case externKindMemory:
			instance.session.mu.RLock()
			state, ok := instance.session.memories[ext.handle]
			instance.session.mu.RUnlock()
			if !ok {
				return fmt.Errorf("unknown memory handle %d", ext.handle)
			}
			if spec.memory != nil {
				return fmt.Errorf("multiple memories for module %q", ext.module)
			}
			spec.memory = &externMemorySpec{name: ext.name, state: state}
		default:
			return fmt.Errorf("unsupported extern kind %d", ext.kind)
		}
	}

	moduleNames := make([]string, 0, len(specByModule))
	for name := range specByModule {
		moduleNames = append(moduleNames, name)
	}
	sort.Strings(moduleNames)

	for _, moduleName := range moduleNames {
		spec := specByModule[moduleName]
		wasm, err := buildExternModule(spec)
		if err != nil {
			return fmt.Errorf("build extern module %q: %w", moduleName, err)
		}

		compiled, err := rt.CompileModule(ctx, wasm)
		if err != nil {
			return fmt.Errorf("compile extern module %q: %w", moduleName, err)
		}

		mod, err := rt.InstantiateModule(
			ctx,
			compiled,
			wazero.NewModuleConfig().WithName(moduleName),
		)
		_ = compiled.Close(ctx)
		if err != nil {
			return fmt.Errorf("instantiate extern module %q: %w", moduleName, err)
		}

		instance.helperModules = append(instance.helperModules, mod)
		instance.externModules[moduleName] = mod
	}

	return nil
}

func (h *hostRuntime) invokeImportCallback(
	ctx context.Context,
	instance *instanceState,
	callbackID uint64,
	syncFlags uint32,
	paramTypes []api.ValueType,
	resultTypes []api.ValueType,
	stack []uint64,
) error {
	if instance.timedOut() {
		return errors.New(hostCallTimeoutError)
	}

	if syncFlags&callbackSyncBefore != 0 {
		if err := h.syncExternsFromModules(instance); err != nil {
			return err
		}
	}

	if instance.timedOut() {
		return errors.New(hostCallTimeoutError)
	}

	paramCount := len(paramTypes)
	args := make([]uint64, paramCount)
	copy(args, stack[:paramCount])

	out, err := h.callGuestCallback(ctx, instance.sessionID, callbackID, args)
	if err != nil {
		return err
	}

	if instance.timedOut() {
		return errors.New(hostCallTimeoutError)
	}

	if syncFlags&callbackSyncAfter != 0 {
		if err := h.syncExternsToModules(instance); err != nil {
			return err
		}
	}

	if len(out) != len(resultTypes) {
		return fmt.Errorf(
			"callback %d returned %d values, expected %d",
			callbackID,
			len(out),
			len(resultTypes),
		)
	}

	copy(stack, out)
	return nil
}

func (h *hostRuntime) callGuestCallback(
	ctx context.Context,
	sessionID uint64,
	callbackID uint64,
	args []uint64,
) (vals []uint64, err error) {
	guest, err := h.guest(sessionID)
	if err != nil {
		return nil, err
	}

	guest.mu.Lock()
	defer guest.mu.Unlock()

	if guest.callbackInvoke == nil {
		return nil, errors.New("guest callback export is missing")
	}

	mem := guest.module.Memory()
	argCount, err := u32FromLen(len(args), "callback argument count")
	if err != nil {
		return nil, err
	}
	argsLenBytes, err := checkedMul(argCount, 8)
	if err != nil {
		return nil, err
	}
	argsPtr, err := allocWithRealloc(ctx, guest.realloc, argsLenBytes, 8)
	if err != nil {
		return nil, err
	}
	defer func() {
		if freeErr := freeWithRealloc(ctx, guest.realloc, argsPtr, argsLenBytes, 8); freeErr != nil && err == nil {
			err = fmt.Errorf("free callback args: %w", freeErr)
		}
	}()

	for i, arg := range args {
		index, convErr := u32FromLen(i, "callback argument index")
		if convErr != nil {
			return nil, convErr
		}
		offset := argsPtr + index*8
		if !mem.WriteUint64Le(offset, arg) {
			return nil, fmt.Errorf("failed to write callback arg at %d", offset)
		}
	}

	rawRet, err := guest.callbackInvoke.Call(
		ctx,
		sessionID,
		callbackID,
		uint64(argsPtr),
		uint64(argCount),
	)
	if err != nil {
		return nil, err
	}
	if len(rawRet) != 1 {
		return nil, fmt.Errorf("unexpected callback return arity %d", len(rawRet))
	}

	retArea, err := u32FromUint64(rawRet[0], "callback return area")
	if err != nil {
		return nil, err
	}
	if guest.callbackPost != nil {
		defer func() {
			if _, postErr := guest.callbackPost.Call(ctx, uint64(retArea)); postErr != nil && err == nil {
				err = fmt.Errorf("post-return callback cleanup failed: %w", postErr)
			}
		}()
	}

	tag, ok := mem.ReadByte(retArea)
	if !ok {
		return nil, fmt.Errorf("failed to read callback tag at %d", retArea)
	}

	if tag == 0 {
		ptr, ok := mem.ReadUint32Le(retArea + 4)
		if !ok {
			return nil, errors.New("failed to read callback result pointer")
		}
		length, ok := mem.ReadUint32Le(retArea + 8)
		if !ok {
			return nil, errors.New("failed to read callback result length")
		}

		rawLen, mulErr := checkedMul(length, 8)
		if mulErr != nil {
			return nil, mulErr
		}

		buf, ok := mem.Read(ptr, rawLen)
		if !ok {
			return nil, fmt.Errorf("out-of-bounds read at %d with length %d", ptr, rawLen)
		}

		out := make([]uint64, length)
		for i := range out {
			base := i * 8
			out[i] = binary.LittleEndian.Uint64(buf[base : base+8])
		}
		return out, nil
	}

	errPtr, ok := mem.ReadUint32Le(retArea + 4)
	if !ok {
		return nil, errors.New("failed to read callback error pointer")
	}
	errLen, ok := mem.ReadUint32Le(retArea + 8)
	if !ok {
		return nil, errors.New("failed to read callback error length")
	}
	msg, readErr := readString(mem, errPtr, errLen)
	if readErr != nil {
		return nil, readErr
	}
	if msg == "" {
		msg = "callback returned an empty error"
	}
	return nil, errors.New(msg)
}

func (h *hostRuntime) syncExternsToModules(instance *instanceState) error {
	for _, ext := range instance.externs {
		mod, ok := instance.externModules[ext.module]
		if !ok {
			return fmt.Errorf("extern module %q not found", ext.module)
		}

		switch ext.kind {
		case externKindGlobal:
			instance.session.mu.RLock()
			state, ok := instance.session.globals[ext.handle]
			instance.session.mu.RUnlock()
			if !ok {
				return fmt.Errorf("unknown global handle %d", ext.handle)
			}

			g := mod.ExportedGlobal(ext.name)
			if g == nil {
				return fmt.Errorf("missing global export %q in module %q", ext.name, ext.module)
			}

			if mg, ok := g.(api.MutableGlobal); ok {
				mg.Set(state.value)
			}

		case externKindMemory:
			memory := mod.Memory()
			if memory == nil {
				return fmt.Errorf("module %q has no memory export", ext.module)
			}

			instance.session.mu.RLock()
			state, ok := instance.session.memories[ext.handle]
			if !ok {
				instance.session.mu.RUnlock()
				return fmt.Errorf("unknown memory handle %d", ext.handle)
			}

			if len(state.data) > int(memory.Size()) {
				instance.session.mu.RUnlock()
				return fmt.Errorf(
					"memory handle %d is larger than module memory (%d > %d)",
					ext.handle,
					len(state.data),
					memory.Size(),
				)
			}

			if len(state.data) > 0 && !memory.Write(0, state.data) {
				instance.session.mu.RUnlock()
				return fmt.Errorf("failed to write module memory for handle %d", ext.handle)
			}
			instance.session.mu.RUnlock()
		}
	}

	return nil
}

func (h *hostRuntime) syncExternsFromModules(instance *instanceState) error {
	for _, ext := range instance.externs {
		mod, ok := instance.externModules[ext.module]
		if !ok {
			return fmt.Errorf("extern module %q not found", ext.module)
		}

		switch ext.kind {
		case externKindGlobal:
			instance.session.mu.RLock()
			state, ok := instance.session.globals[ext.handle]
			instance.session.mu.RUnlock()
			if !ok {
				return fmt.Errorf("unknown global handle %d", ext.handle)
			}

			g := mod.ExportedGlobal(ext.name)
			if g == nil {
				return fmt.Errorf("missing global export %q in module %q", ext.name, ext.module)
			}

			instance.session.mu.Lock()
			state.value = g.Get()
			instance.session.mu.Unlock()

		case externKindMemory:
			memory := mod.Memory()
			if memory == nil {
				return fmt.Errorf("module %q has no memory export", ext.module)
			}

			size := memory.Size()
			buf, ok := memory.Read(0, size)
			if !ok {
				return fmt.Errorf("failed to read memory from module %q", ext.module)
			}

			instance.session.mu.Lock()
			state, ok := instance.session.memories[ext.handle]
			if !ok {
				instance.session.mu.Unlock()
				return fmt.Errorf("unknown memory handle %d", ext.handle)
			}
			if cap(state.data) < len(buf) {
				state.data = make([]byte, len(buf))
			} else {
				state.data = state.data[:len(buf)]
			}
			copy(state.data, buf)
			instance.session.mu.Unlock()
		}
	}

	return nil
}

func parseFunctionImports(mem api.Memory, ptr, length uint32) ([]functionImport, error) {
	const recordSize = uint32(48)
	imports := make([]functionImport, 0, length)

	for i := uint32(0); i < length; i++ {
		recordPtr := ptr + i*recordSize
		record, ok := mem.Read(recordPtr, recordSize)
		if !ok {
			return nil, fmt.Errorf("out-of-bounds function import record %d", i)
		}

		modulePtr := binary.LittleEndian.Uint32(record[0:4])
		moduleLen := binary.LittleEndian.Uint32(record[4:8])
		namePtr := binary.LittleEndian.Uint32(record[8:12])
		nameLen := binary.LittleEndian.Uint32(record[12:16])
		callbackID := binary.LittleEndian.Uint64(record[32:40])
		syncFlags := binary.LittleEndian.Uint32(record[40:44])

		module, err := readString(mem, modulePtr, moduleLen)
		if err != nil {
			return nil, fmt.Errorf("function import %d module: %w", i, err)
		}
		name, err := readString(mem, namePtr, nameLen)
		if err != nil {
			return nil, fmt.Errorf("function import %d name: %w", i, err)
		}

		imports = append(imports, functionImport{
			module:     module,
			name:       name,
			callbackID: callbackID,
			syncFlags:  syncFlags,
		})
	}

	return imports, nil
}

func parseExternImports(mem api.Memory, ptr, length uint32) ([]externImport, error) {
	const recordSize = uint32(32)
	imports := make([]externImport, 0, length)

	for i := uint32(0); i < length; i++ {
		recordPtr := ptr + i*recordSize
		record, ok := mem.Read(recordPtr, recordSize)
		if !ok {
			return nil, fmt.Errorf("out-of-bounds extern import record %d", i)
		}

		modulePtr := binary.LittleEndian.Uint32(record[0:4])
		moduleLen := binary.LittleEndian.Uint32(record[4:8])
		namePtr := binary.LittleEndian.Uint32(record[8:12])
		nameLen := binary.LittleEndian.Uint32(record[12:16])
		tag := record[16]
		handle := binary.LittleEndian.Uint64(record[24:32])

		module, err := readString(mem, modulePtr, moduleLen)
		if err != nil {
			return nil, fmt.Errorf("extern import %d module: %w", i, err)
		}
		name, err := readString(mem, namePtr, nameLen)
		if err != nil {
			return nil, fmt.Errorf("extern import %d name: %w", i, err)
		}

		var kind externKind
		switch tag {
		case 0:
			kind = externKindGlobal
		case 1:
			kind = externKindMemory
		default:
			return nil, fmt.Errorf("extern import %d has unknown kind tag %d", i, uint32(tag))
		}

		imports = append(imports, externImport{
			module: module,
			name:   name,
			kind:   kind,
			handle: handle,
		})
	}

	return imports, nil
}

func buildExternModule(spec *externModuleSpec) ([]byte, error) {
	exports := 0
	if spec.memory != nil {
		exports++
	}
	exports += len(spec.global)
	if exports == 0 {
		return nil, fmt.Errorf("extern module %q has no exports", spec.name)
	}

	wasm := make([]byte, 0, 512)
	wasm = append(wasm, 0x00, 0x61, 0x73, 0x6d)
	wasm = append(wasm, 0x01, 0x00, 0x00, 0x00)

	if spec.memory != nil {
		payload := make([]byte, 0, 16)
		payload = appendU32(payload, 1)
		if spec.memory.state.maximum == nil {
			payload = append(payload, 0x00)
			payload = appendU32(payload, spec.memory.state.initial)
		} else {
			payload = append(payload, 0x01)
			payload = appendU32(payload, spec.memory.state.initial)
			payload = appendU32(payload, *spec.memory.state.maximum)
		}
		var err error
		wasm, err = appendSection(wasm, 5, payload)
		if err != nil {
			return nil, err
		}
	}

	if len(spec.global) > 0 {
		payload := make([]byte, 0, len(spec.global)*16)
		globalCount, err := u32FromLen(len(spec.global), "extern module global count")
		if err != nil {
			return nil, err
		}
		payload = appendU32(payload, globalCount)
		for _, g := range spec.global {
			payload = append(payload, valTypeToWasmByte(g.state.typ))
			if g.state.mutable {
				payload = append(payload, 0x01)
			} else {
				payload = append(payload, 0x00)
			}
			initExpr, err := buildInitExpr(g.state.typ, g.state.value)
			if err != nil {
				return nil, err
			}
			payload = append(payload, initExpr...)
		}
		wasm, err = appendSection(wasm, 6, payload)
		if err != nil {
			return nil, err
		}
	}

	exportPayload := make([]byte, 0, 256)
	exportCount, err := u32FromLen(exports, "extern module export count")
	if err != nil {
		return nil, err
	}
	exportPayload = appendU32(exportPayload, exportCount)

	if spec.memory != nil {
		exportPayload, err = appendName(exportPayload, spec.memory.name)
		if err != nil {
			return nil, err
		}
		exportPayload = append(exportPayload, 0x02)
		exportPayload = appendU32(exportPayload, 0)
	}

	for i, g := range spec.global {
		exportPayload, err = appendName(exportPayload, g.name)
		if err != nil {
			return nil, err
		}
		exportPayload = append(exportPayload, 0x03)
		index, convErr := u32FromLen(i, "extern module global index")
		if convErr != nil {
			return nil, convErr
		}
		exportPayload = appendU32(exportPayload, index)
	}

	wasm, err = appendSection(wasm, 7, exportPayload)
	if err != nil {
		return nil, err
	}
	return wasm, nil
}

func appendSection(dst []byte, id byte, payload []byte) ([]byte, error) {
	payloadLen, err := u32FromLen(len(payload), "WASM section payload length")
	if err != nil {
		return nil, err
	}
	dst = append(dst, id)
	dst = appendU32(dst, payloadLen)
	dst = append(dst, payload...)
	return dst, nil
}

func appendName(dst []byte, name string) ([]byte, error) {
	nameLen, err := u32FromLen(len(name), "WASM name length")
	if err != nil {
		return nil, err
	}
	dst = appendU32(dst, nameLen)
	dst = append(dst, []byte(name)...)
	return dst, nil
}

func appendU32(dst []byte, v uint32) []byte {
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			dst = append(dst, b|0x80)
		} else {
			dst = append(dst, b)
			return dst
		}
	}
}

func appendI32(dst []byte, v int32) []byte {
	val := int64(v)
	for {
		b := byte(val & 0x7f)
		val >>= 7
		signBit := (b & 0x40) != 0
		done := (val == 0 && !signBit) || (val == -1 && signBit)
		if done {
			dst = append(dst, b)
			return dst
		}
		dst = append(dst, b|0x80)
	}
}

func appendI64(dst []byte, v int64) []byte {
	val := v
	for {
		b := byte(val & 0x7f)
		val >>= 7
		signBit := (b & 0x40) != 0
		done := (val == 0 && !signBit) || (val == -1 && signBit)
		if done {
			dst = append(dst, b)
			return dst
		}
		dst = append(dst, b|0x80)
	}
}

func valTypeToWasmByte(t valType) byte {
	switch t {
	case valTypeI64:
		return 0x7e
	case valTypeI32:
		return 0x7f
	case valTypeF64Bits:
		return 0x7c
	case valTypeF32Bits:
		return 0x7d
	default:
		return 0x7f
	}
}

func buildInitExpr(t valType, raw uint64) ([]byte, error) {
	expr := make([]byte, 0, 16)
	switch t {
	case valTypeI32:
		bits, err := u32FromUint64(raw, "i32 init expression")
		if err != nil {
			return nil, err
		}
		expr = append(expr, 0x41)
		expr = appendI32(expr, i32FromBits(bits))
	case valTypeI64:
		expr = append(expr, 0x42)
		expr = appendI64(expr, i64FromBits(raw))
	case valTypeF32Bits:
		bits, err := u32FromUint64(raw, "f32 init expression bits")
		if err != nil {
			return nil, err
		}
		expr = append(expr, 0x43)
		var data [4]byte
		binary.LittleEndian.PutUint32(data[:], bits)
		expr = append(expr, data[:]...)
	case valTypeF64Bits:
		expr = append(expr, 0x44)
		var data [8]byte
		binary.LittleEndian.PutUint64(data[:], raw)
		expr = append(expr, data[:]...)
	default:
		return nil, fmt.Errorf("unsupported val-type %d", t)
	}
	expr = append(expr, 0x0b)
	return expr, nil
}

func checkedMul(a, b uint32) (uint32, error) {
	product := uint64(a) * uint64(b)
	if product > math.MaxUint32 {
		return 0, fmt.Errorf("overflow while computing %d * %d", a, b)
	}
	return uint32(product), nil
}

func importKey(module, name string) string {
	return module + "\x00" + name
}

func readBytes(mem api.Memory, ptr, length uint32) ([]byte, error) {
	if length == 0 {
		return []byte{}, nil
	}
	data, ok := mem.Read(ptr, length)
	if !ok {
		return nil, fmt.Errorf("out-of-bounds read at %d with length %d", ptr, length)
	}
	copied := make([]byte, len(data))
	copy(copied, data)
	return copied, nil
}

func readString(mem api.Memory, ptr, length uint32) (string, error) {
	data, err := readBytes(mem, ptr, length)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func normalizeGuestAlign(align uint32) uint32 {
	if align == 0 {
		return 1
	}
	return align
}

func normalizeGuestAllocSize(size uint32) uint32 {
	if size == 0 {
		return 1
	}
	return size
}

func moduleRealloc(module api.Module) (api.Function, error) {
	realloc := module.ExportedFunction("cabi_realloc")
	if realloc == nil {
		realloc = module.ExportedFunction("cabi_realloc_wit_bindgen_0_46_0")
	}
	if realloc == nil {
		return nil, errors.New("guest allocator export not found")
	}

	return realloc, nil
}

func allocWithRealloc(
	ctx context.Context,
	realloc api.Function,
	size,
	align uint32,
) (uint32, error) {
	results, err := realloc.Call(
		ctx,
		0,
		0,
		uint64(normalizeGuestAlign(align)),
		uint64(normalizeGuestAllocSize(size)),
	)
	if err != nil {
		return 0, err
	}
	if len(results) != 1 {
		return 0, fmt.Errorf("unexpected realloc result arity %d", len(results))
	}

	ptr, err := u32FromUint64(results[0], "realloc pointer result")
	if err != nil {
		return 0, err
	}
	if ptr == 0 {
		return 0, errors.New("guest allocator returned null pointer")
	}

	return ptr, nil
}

func freeWithRealloc(
	ctx context.Context,
	realloc api.Function,
	ptr,
	oldSize,
	align uint32,
) error {
	if ptr == 0 {
		return nil
	}

	results, err := realloc.Call(
		ctx,
		uint64(ptr),
		uint64(normalizeGuestAllocSize(oldSize)),
		uint64(normalizeGuestAlign(align)),
		0,
	)
	if err != nil {
		return err
	}
	if len(results) != 1 {
		return fmt.Errorf("unexpected realloc result arity %d", len(results))
	}

	return nil
}

func moduleAllocAndWrite(
	ctx context.Context,
	module api.Module,
	data []byte,
	align uint32,
) (uint32, uint32, error) {
	realloc, err := moduleRealloc(module)
	if err != nil {
		return 0, 0, err
	}
	dataLen, err := u32FromLen(len(data), "module allocation length")
	if err != nil {
		return 0, 0, err
	}
	ptr, err := allocWithRealloc(ctx, realloc, dataLen, align)
	if err != nil {
		return 0, 0, err
	}

	if len(data) > 0 && !module.Memory().Write(ptr, data) {
		return 0, 0, fmt.Errorf("failed to write %d bytes to guest memory at %d", len(data), ptr)
	}

	return ptr, dataLen, nil
}

func (h *hostRuntime) writeUnitResultOK(mem api.Memory, retPtr uint32) {
	_ = mem.WriteUint32Le(retPtr, 0)
}

func (h *hostRuntime) writeUnitResultErr(ctx context.Context, caller api.Module, retPtr uint32, message string) {
	ptr, length, err := moduleAllocAndWrite(ctx, caller, []byte(message), 1)
	if err != nil {
		ptr, length = 0, 0
	}
	mem := caller.Memory()
	_ = mem.WriteUint32Le(retPtr, 1)
	_ = mem.WriteUint32Le(retPtr+4, ptr)
	_ = mem.WriteUint32Le(retPtr+8, length)
}

func (h *hostRuntime) writeU64ResultOK(mem api.Memory, retPtr uint32, value uint64) {
	_ = mem.WriteUint32Le(retPtr, 0)
	_ = mem.WriteUint64Le(retPtr+8, value)
}

func (h *hostRuntime) writeU64ResultErr(ctx context.Context, caller api.Module, retPtr uint32, message string) {
	ptr, length, err := moduleAllocAndWrite(ctx, caller, []byte(message), 1)
	if err != nil {
		ptr, length = 0, 0
	}
	mem := caller.Memory()
	_ = mem.WriteUint32Le(retPtr, 1)
	_ = mem.WriteUint32Le(retPtr+8, ptr)
	_ = mem.WriteUint32Le(retPtr+12, length)
}

func (h *hostRuntime) writeBytesResultOK(ctx context.Context, caller api.Module, retPtr uint32, data []byte) error {
	ptr, length, err := moduleAllocAndWrite(ctx, caller, data, 1)
	if err != nil {
		return err
	}
	mem := caller.Memory()
	_ = mem.WriteUint32Le(retPtr, 0)
	_ = mem.WriteUint32Le(retPtr+4, ptr)
	_ = mem.WriteUint32Le(retPtr+8, length)
	return nil
}

func (h *hostRuntime) writeU64ListResultOK(ctx context.Context, caller api.Module, retPtr uint32, values []uint64) error {
	valueCount, err := u32FromLen(len(values), "uint64 result count")
	if err != nil {
		return err
	}
	rawLen, err := checkedMul(valueCount, 8)
	if err != nil {
		return err
	}
	realloc, err := moduleRealloc(caller)
	if err != nil {
		return err
	}
	ptr, err := allocWithRealloc(ctx, realloc, rawLen, 8)
	if err != nil {
		return err
	}
	mem := caller.Memory()
	for i, value := range values {
		index, convErr := u32FromLen(i, "uint64 result index")
		if convErr != nil {
			return convErr
		}
		offset := ptr + index*8
		if !mem.WriteUint64Le(offset, value) {
			return fmt.Errorf("failed to write %d uint64 values to guest memory at %d", len(values), ptr)
		}
	}
	_ = mem.WriteUint32Le(retPtr, 0)
	_ = mem.WriteUint32Le(retPtr+4, ptr)
	_ = mem.WriteUint32Le(retPtr+8, valueCount)
	return nil
}

func (h *hostRuntime) writeListResultErr(ctx context.Context, caller api.Module, retPtr uint32, message string) {
	ptr, length, err := moduleAllocAndWrite(ctx, caller, []byte(message), 1)
	if err != nil {
		ptr, length = 0, 0
	}
	mem := caller.Memory()
	_ = mem.WriteUint32Le(retPtr, 1)
	_ = mem.WriteUint32Le(retPtr+4, ptr)
	_ = mem.WriteUint32Le(retPtr+8, length)
}
