package yara_x

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/experimental/wazerotest"
)

func writeGuestTestBytes(t *testing.T, client *guestClient, data []byte) (uint32, uint32) {
	t.Helper()

	ptr, length, err := client.allocAndWrite(data, 1)
	require.NoError(t, err)
	t.Cleanup(func() {
		client.free(ptr, length, 1)
	})
	return ptr, length
}

func writeGuestTestString(t *testing.T, client *guestClient, value string) (uint32, uint32) {
	t.Helper()
	return writeGuestTestBytes(t, client, []byte(value))
}

func allocGuestResultArea(t *testing.T, client *guestClient, size uint32) uint32 {
	t.Helper()

	ptr, err := client.alloc(size, 8)
	require.NoError(t, err)
	t.Cleanup(func() {
		client.free(ptr, size, 8)
	})
	return ptr
}

func newTestHostRuntime(t *testing.T) (*hostRuntime, context.Context, wazero.Runtime) {
	t.Helper()

	ctx := context.Background()
	rt := wazero.NewRuntimeWithConfig(ctx, runtimeConfig())
	t.Cleanup(func() {
		require.NoError(t, rt.Close(ctx))
	})

	return newHostRuntime(rt), ctx, rt
}

func registerTestSession(t *testing.T, h *hostRuntime, sessionID uint64, session *hostSessionState) {
	t.Helper()

	h.sessionsMu.Lock()
	h.sessions[sessionID] = session
	h.sessionsMu.Unlock()

	t.Cleanup(func() {
		require.NoError(t, h.destroySession(context.Background(), sessionID))
	})
}

func readUnitResultMessageForTest(t *testing.T, mem api.Memory, retPtr uint32) (bool, string) {
	t.Helper()

	tag, ok := mem.ReadUint32Le(retPtr)
	require.True(t, ok)
	if tag == 0 {
		return true, ""
	}
	ptr, ok := mem.ReadUint32Le(retPtr + 4)
	require.True(t, ok)
	length, ok := mem.ReadUint32Le(retPtr + 8)
	require.True(t, ok)
	msg, err := readString(mem, ptr, length)
	require.NoError(t, err)
	return false, msg
}

func readU64ResultMessageForTest(t *testing.T, mem api.Memory, retPtr uint32) (uint64, string, bool) {
	t.Helper()

	tag, ok := mem.ReadUint32Le(retPtr)
	require.True(t, ok)
	if tag == 0 {
		value, ok := mem.ReadUint64Le(retPtr + 8)
		require.True(t, ok)
		return value, "", true
	}
	ptr, ok := mem.ReadUint32Le(retPtr + 8)
	require.True(t, ok)
	length, ok := mem.ReadUint32Le(retPtr + 12)
	require.True(t, ok)
	msg, err := readString(mem, ptr, length)
	require.NoError(t, err)
	return 0, msg, false
}

func readListResultForTest(t *testing.T, mem api.Memory, retPtr uint32) ([]byte, bool, string) {
	t.Helper()

	tag, ok := mem.ReadUint32Le(retPtr)
	require.True(t, ok)
	ptr, ok := mem.ReadUint32Le(retPtr + 4)
	require.True(t, ok)
	length, ok := mem.ReadUint32Le(retPtr + 8)
	require.True(t, ok)
	if tag != 0 {
		msg, err := readString(mem, ptr, length)
		require.NoError(t, err)
		return nil, false, msg
	}
	data, err := readBytes(mem, ptr, length)
	require.NoError(t, err)
	return data, true, ""
}

func readU64ListResultForTest(t *testing.T, mem api.Memory, retPtr uint32) ([]uint64, bool, string) {
	t.Helper()

	tag, ok := mem.ReadUint32Le(retPtr)
	require.True(t, ok)
	ptr, ok := mem.ReadUint32Le(retPtr + 4)
	require.True(t, ok)
	length, ok := mem.ReadUint32Le(retPtr + 8)
	require.True(t, ok)
	if tag != 0 {
		msg, err := readString(mem, ptr, length)
		require.NoError(t, err)
		return nil, false, msg
	}
	rawLen, err := checkedMul(length, 8)
	require.NoError(t, err)
	data, err := readBytes(mem, ptr, rawLen)
	require.NoError(t, err)
	return decodeU64ListForTest(t, data), true, ""
}

func encodeU64ListForTest(values ...uint64) []byte {
	buf := make([]byte, len(values)*8)
	for i, value := range values {
		binary.LittleEndian.PutUint64(buf[i*8:], value)
	}
	return buf
}

func decodeU64ListForTest(t *testing.T, data []byte) []uint64 {
	t.Helper()

	require.Zero(t, len(data)%8)
	out := make([]uint64, len(data)/8)
	for i := range out {
		out[i] = binary.LittleEndian.Uint64(data[i*8:])
	}
	return out
}

type fakeCallbackGuest struct {
	module    *wazerotest.Module
	memory    *wazerotest.Memory
	nextPtr   uint32
	postCalls int
}

type errorFunction struct {
	*wazerotest.Function
	err error
}

func newErrorFunction(name string, err error) *errorFunction {
	return &errorFunction{
		Function: &wazerotest.Function{
			ParamTypes:       []api.ValueType{},
			ResultTypes:      []api.ValueType{},
			ExportNames:      []string{name},
			GoModuleFunction: api.GoModuleFunc(func(context.Context, api.Module, []uint64) {}),
		},
		err: err,
	}
}

func (f *errorFunction) Call(context.Context, ...uint64) ([]uint64, error) {
	return nil, f.err
}

func (f *errorFunction) CallWithStack(context.Context, []uint64) error {
	return f.err
}

func newFakeCallbackGuest(
	callback func(sessionID, callbackID uint64, args []uint64) ([]uint64, error),
) *fakeCallbackGuest {
	guest := &fakeCallbackGuest{
		memory:  wazerotest.NewFixedMemory(64 * 1024),
		nextPtr: 1024,
	}

	alloc := func(size, align uint32) uint32 {
		if align == 0 {
			align = 1
		}
		if size == 0 {
			size = 1
		}
		mask := align - 1
		ptr := (guest.nextPtr + mask) &^ mask
		guest.nextPtr = ptr + size
		return ptr
	}

	realloc := &wazerotest.Function{
		ParamTypes:  []api.ValueType{api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32, api.ValueTypeI32},
		ResultTypes: []api.ValueType{api.ValueTypeI32},
		ExportNames: []string{"cabi_realloc"},
		GoModuleFunction: api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			size, _ := u32FromUint64(stack[3], "fake guest realloc size")
			align, _ := u32FromUint64(stack[2], "fake guest realloc align")
			if size == 0 {
				stack[0] = 0
				return
			}
			stack[0] = uint64(alloc(size, align))
		}),
	}

	invoke := &wazerotest.Function{
		ParamTypes:  []api.ValueType{api.ValueTypeI64, api.ValueTypeI64, api.ValueTypeI32, api.ValueTypeI64},
		ResultTypes: []api.ValueType{api.ValueTypeI32},
		ExportNames: []string{"yara:runtime/callbacks#invoke-callback"},
		GoModuleFunction: api.GoModuleFunc(func(_ context.Context, _ api.Module, stack []uint64) {
			sessionID := stack[0]
			callbackID := stack[1]
			argsPtr, _ := u32FromUint64(stack[2], "fake callback args ptr")
			argsLen, _ := u32FromUint64(stack[3], "fake callback args len")

			args := make([]uint64, argsLen)
			for i := range args {
				index, _ := u32FromLen(i, "fake callback arg index")
				value, ok := guest.memory.ReadUint64Le(argsPtr + index*8)
				if !ok {
					panic("failed to read fake callback arg")
				}
				args[i] = value
			}

			values, err := callback(sessionID, callbackID, args)
			retArea := alloc(12, 4)
			if err != nil {
				msg := []byte(err.Error())
				msgPtr := alloc(uint32(len(msg)), 1)
				_ = guest.memory.Write(msgPtr, msg)
				_ = guest.memory.WriteByte(retArea, 1)
				_ = guest.memory.WriteUint32Le(retArea+4, msgPtr)
				_ = guest.memory.WriteUint32Le(retArea+8, uint32(len(msg)))
				stack[0] = uint64(retArea)
				return
			}

			valuesPtr := alloc(uint32(len(values))*8, 8)
			for i, value := range values {
				index, _ := u32FromLen(i, "fake callback result index")
				_ = guest.memory.WriteUint64Le(valuesPtr+index*8, value)
			}
			_ = guest.memory.WriteByte(retArea, 0)
			_ = guest.memory.WriteUint32Le(retArea+4, valuesPtr)
			_ = guest.memory.WriteUint32Le(retArea+8, uint32(len(values)))
			stack[0] = uint64(retArea)
		}),
	}

	post := &wazerotest.Function{
		ParamTypes:  []api.ValueType{api.ValueTypeI32},
		ResultTypes: []api.ValueType{},
		ExportNames: []string{"cabi_post_yara:runtime/callbacks#invoke-callback"},
		GoModuleFunction: api.GoModuleFunc(func(_ context.Context, _ api.Module, _ []uint64) {
			guest.postCalls++
		}),
	}

	guest.module = wazerotest.NewModule(guest.memory, realloc, invoke, post)
	guest.module.ModuleName = "fake-guest"
	return guest
}

func registerTestGuest(t *testing.T, h *hostRuntime, guestID uint64, guest *fakeCallbackGuest) {
	t.Helper()

	realloc := guest.module.ExportedFunction("cabi_realloc")
	require.NotNil(t, realloc)
	h.registerGuest(guestID, guest.module, realloc)
	t.Cleanup(func() {
		h.unregisterGuest(guestID)
	})
}

func TestParseFunctionImportsIncludesSyncFlags(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	modulePtr, moduleLen := writeGuestTestString(t, client, "env")
	namePtr, nameLen := writeGuestTestString(t, client, "lookup")
	modulePtr2, moduleLen2 := writeGuestTestString(t, client, "math")
	namePtr2, nameLen2 := writeGuestTestString(t, client, "abs")

	record := make([]byte, 48*2)
	binary.LittleEndian.PutUint32(record[0:4], modulePtr)
	binary.LittleEndian.PutUint32(record[4:8], moduleLen)
	binary.LittleEndian.PutUint32(record[8:12], namePtr)
	binary.LittleEndian.PutUint32(record[12:16], nameLen)
	binary.LittleEndian.PutUint64(record[32:40], 17)
	binary.LittleEndian.PutUint32(record[40:44], callbackSyncBefore)

	offset := 48
	binary.LittleEndian.PutUint32(record[offset+0:offset+4], modulePtr2)
	binary.LittleEndian.PutUint32(record[offset+4:offset+8], moduleLen2)
	binary.LittleEndian.PutUint32(record[offset+8:offset+12], namePtr2)
	binary.LittleEndian.PutUint32(record[offset+12:offset+16], nameLen2)
	binary.LittleEndian.PutUint64(record[offset+32:offset+40], 29)
	binary.LittleEndian.PutUint32(record[offset+40:offset+44], callbackSyncBefore|callbackSyncAfter)

	recordPtr, _ := writeGuestTestBytes(t, client, record)

	imports, err := parseFunctionImports(client.memory(), recordPtr, 2)
	require.NoError(t, err)
	assert.Equal(t, []functionImport{
		{module: "env", name: "lookup", callbackID: 17, syncFlags: callbackSyncBefore},
		{module: "math", name: "abs", callbackID: 29, syncFlags: callbackSyncBefore | callbackSyncAfter},
	}, imports)
}

func TestParseFunctionImportsRejectsOutOfBoundsRecord(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	memSize := client.memory().Size()
	require.Greater(t, memSize, uint32(24))

	_, err = parseFunctionImports(client.memory(), memSize-24, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "out-of-bounds function import record 0")
}

func TestParseExternImportsParsesKindsAndRejectsUnknownTag(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	modulePtr, moduleLen := writeGuestTestString(t, client, "env")
	namePtr, nameLen := writeGuestTestString(t, client, "counter")
	modulePtr2, moduleLen2 := writeGuestTestString(t, client, "env")
	namePtr2, nameLen2 := writeGuestTestString(t, client, "memory")

	record := make([]byte, 32*2)
	binary.LittleEndian.PutUint32(record[0:4], modulePtr)
	binary.LittleEndian.PutUint32(record[4:8], moduleLen)
	binary.LittleEndian.PutUint32(record[8:12], namePtr)
	binary.LittleEndian.PutUint32(record[12:16], nameLen)
	record[16] = 0
	binary.LittleEndian.PutUint64(record[24:32], 41)

	offset := 32
	binary.LittleEndian.PutUint32(record[offset+0:offset+4], modulePtr2)
	binary.LittleEndian.PutUint32(record[offset+4:offset+8], moduleLen2)
	binary.LittleEndian.PutUint32(record[offset+8:offset+12], namePtr2)
	binary.LittleEndian.PutUint32(record[offset+12:offset+16], nameLen2)
	record[offset+16] = 1
	binary.LittleEndian.PutUint64(record[offset+24:offset+32], 42)

	recordPtr, _ := writeGuestTestBytes(t, client, record)

	imports, err := parseExternImports(client.memory(), recordPtr, 2)
	require.NoError(t, err)
	assert.Equal(t, []externImport{
		{module: "env", name: "counter", kind: externKindGlobal, handle: 41},
		{module: "env", name: "memory", kind: externKindMemory, handle: 42},
	}, imports)

	record[offset+16] = 9
	invalidPtr, _ := writeGuestTestBytes(t, client, record)

	_, err = parseExternImports(client.memory(), invalidPtr, 2)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "extern import 1 has unknown kind tag 9")
}

func TestReadBytesReturnsDetachedCopy(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	ptr, length := writeGuestTestBytes(t, client, []byte("abc"))

	data, err := readBytes(client.memory(), ptr, length)
	require.NoError(t, err)

	require.True(t, client.memory().Write(ptr, []byte("xyz")))
	assert.Equal(t, []byte("abc"), data)
}

func TestGuestClientCloseUnregistersGuest(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)

	guestID := client.guestID
	_, err = client.program.host.guest(guestID)
	require.NoError(t, err)

	client.close()
	client.close()

	_, err = client.program.host.guest(guestID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown guest instance")
	assert.Zero(t, client.guestID)
	assert.Nil(t, client.guest)
	assert.Nil(t, client.realloc)
	assert.Nil(t, client.exports)
}

func TestHostRuntimeGlobalLifecycle(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	sessionID := uint64(7001)
	registerTestSession(t, h, sessionID, newHostSessionState())

	retPtr := allocGuestResultArea(t, client, 16)

	h.globalNew(client.ctx, client.guest, []uint64{sessionID, uint64(valTypeI64), 1, 7, uint64(retPtr)})
	globalID, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)

	h.globalGet(client.ctx, client.guest, []uint64{sessionID, globalID, 0, uint64(retPtr)})
	value, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)
	assert.Equal(t, uint64(7), value)

	h.globalSet(client.ctx, client.guest, []uint64{sessionID, globalID, 0, 11, uint64(retPtr)})
	okResult, msg := readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, okResult, msg)

	h.globalGet(client.ctx, client.guest, []uint64{sessionID, globalID, 0, uint64(retPtr)})
	value, msg, ok = readU64ResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)
	assert.Equal(t, uint64(11), value)

	h.globalNew(client.ctx, client.guest, []uint64{sessionID, uint64(valTypeI64), 0, 5, uint64(retPtr)})
	immutableID, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)

	h.globalSet(client.ctx, client.guest, []uint64{sessionID, immutableID, 0, 9, uint64(retPtr)})
	okResult, msg = readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.False(t, okResult)
	assert.Contains(t, msg, "immutable")
}

func TestHostRuntimeMemoryWriteAndReadDetachFromCallerMemory(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	sessionID := uint64(7002)
	session := newHostSessionState()
	registerTestSession(t, h, sessionID, session)

	retPtr := allocGuestResultArea(t, client, 16)

	h.memoryNew(client.ctx, client.guest, []uint64{sessionID, 1, 1, 1, uint64(retPtr)})
	memoryID, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)

	dataPtr, dataLen := writeGuestTestBytes(t, client, []byte("abc"))
	h.memoryWrite(client.ctx, client.guest, []uint64{sessionID, memoryID, uint64(dataPtr), uint64(dataLen), uint64(retPtr)})
	okResult, msg := readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, okResult, msg)

	require.True(t, client.memory().Write(dataPtr, []byte("xyz")))
	assert.Equal(t, []byte("abc"), session.memories[memoryID].data)

	h.memoryRead(client.ctx, client.guest, []uint64{sessionID, memoryID, uint64(retPtr)})
	data, ok, msg := readListResultForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)
	assert.Equal(t, []byte("abc"), data)

	session.memories[memoryID].data[0] = 'q'
	assert.Equal(t, []byte("abc"), data)
}

func TestInstantiateExternModulesAndSyncRoundTrip(t *testing.T) {
	h, ctx, rt := newTestHostRuntime(t)

	maxPages := uint32(1)
	session := newHostSessionState()
	session.globals[1] = &globalState{
		typ:     valTypeI64,
		mutable: true,
		value:   7,
	}
	session.memories[2] = &memoryState{
		initial: 1,
		maximum: &maxPages,
		data:    []byte("abc"),
	}

	instance := &instanceState{
		session:       session,
		externs:       []externImport{{module: "env", name: "counter", kind: externKindGlobal, handle: 1}, {module: "env", name: "memory", kind: externKindMemory, handle: 2}},
		externModules: map[string]api.Module{},
	}

	require.NoError(t, h.instantiateExternModules(ctx, rt, instance.externs, instance))

	mod := instance.externModules["env"]
	require.NotNil(t, mod)
	require.NoError(t, h.syncExternsToModules(instance))

	global := mod.ExportedGlobal("counter")
	require.NotNil(t, global)
	assert.Equal(t, uint64(7), global.Get())

	memory := mod.Memory()
	require.NotNil(t, memory)
	got, ok := memory.Read(0, 3)
	require.True(t, ok)
	assert.Equal(t, []byte("abc"), got)

	mutableGlobal, ok := global.(api.MutableGlobal)
	require.True(t, ok)
	mutableGlobal.Set(11)
	require.True(t, memory.Write(0, []byte("xyz")))

	require.NoError(t, h.syncExternsFromModules(instance))

	assert.Equal(t, uint64(11), session.globals[1].value)
	require.Len(t, session.memories[2].data, int(memory.Size()))
	assert.Equal(t, []byte("xyz"), session.memories[2].data[:3])

	require.True(t, memory.Write(0, []byte("qqq")))
	assert.Equal(t, []byte("xyz"), session.memories[2].data[:3])
}

func TestDestroySessionClosesInstancesAndIsIdempotent(t *testing.T) {
	h, ctx, _ := newTestHostRuntime(t)

	sessionID := uint64(9001)
	session := newHostSessionState()
	instanceRT := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig())
	instance := &instanceState{rt: instanceRT}
	session.instances[5] = instance

	h.sessionsMu.Lock()
	h.sessions[sessionID] = session
	h.sessionsMu.Unlock()

	require.NoError(t, h.destroySession(ctx, sessionID))
	require.NoError(t, h.destroySession(ctx, sessionID))

	h.sessionsMu.RLock()
	_, ok := h.sessions[sessionID]
	h.sessionsMu.RUnlock()
	assert.False(t, ok)
	assert.Nil(t, instance.rt)
	assert.Empty(t, session.instances)
}

func TestInstanceDestroyRemovesInstanceAndReportsUnknownHandle(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	sessionID := uint64(9002)
	session := newHostSessionState()
	registerTestSession(t, h, sessionID, session)

	instanceID := uint64(7)
	instance := &instanceState{
		sessionID:     sessionID,
		session:       session,
		module:        wazerotest.NewModule(nil),
		externModules: map[string]api.Module{},
		exports:       map[string]api.Function{},
	}
	session.instances[instanceID] = instance

	retPtr := allocGuestResultArea(t, client, 12)
	h.instanceDestroy(client.ctx, client.guest, []uint64{sessionID, instanceID, uint64(retPtr)})
	ok, msg := readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)
	assert.Nil(t, instance.module)
	_, exists := session.instances[instanceID]
	assert.False(t, exists)

	h.instanceDestroy(client.ctx, client.guest, []uint64{sessionID, instanceID, uint64(retPtr)})
	ok, msg = readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.False(t, ok)
	assert.Contains(t, msg, "unknown instance handle")
}

func TestValidateModuleAcceptsValidWASMAndRejectsInvalidBytes(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	retPtr := allocGuestResultArea(t, client, 12)

	wasm, err := buildExternModule(&externModuleSpec{
		name: "env",
		global: []externGlobalSpec{{
			name:  "counter",
			state: &globalState{typ: valTypeI64, mutable: true, value: 1},
		}},
	})
	require.NoError(t, err)

	modulePtr, moduleLen := writeGuestTestBytes(t, client, wasm)
	h.validateModule(client.ctx, client.guest, []uint64{uint64(modulePtr), uint64(moduleLen), uint64(retPtr)})
	ok, msg := readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)

	invalidPtr, invalidLen := writeGuestTestBytes(t, client, []byte{0x00, 0x61, 0x73})
	h.validateModule(client.ctx, client.guest, []uint64{uint64(invalidPtr), uint64(invalidLen), uint64(retPtr)})
	ok, msg = readUnitResultMessageForTest(t, client.memory(), retPtr)
	require.False(t, ok)
	assert.NotEmpty(t, msg)
}

func TestWriteU64ResultErrEncodesMessage(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	retPtr := allocGuestResultArea(t, client, 16)
	h.writeU64ResultErr(client.ctx, client.guest, retPtr, "boom")

	_, msg, ok := readU64ResultMessageForTest(t, client.memory(), retPtr)
	require.False(t, ok)
	assert.Equal(t, "boom", msg)
}

func TestCallExportReturnsResultsAndCachesExport(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	sessionID := uint64(9101)
	instanceID := uint64(3)
	session := newHostSessionState()
	registerTestSession(t, h, sessionID, session)

	sum := wazerotest.NewFunction(func(_ context.Context, _ api.Module, left, right uint64) uint64 {
		return left + right
	})
	sum.ExportNames = []string{"sum"}

	instance := &instanceState{
		sessionID:     sessionID,
		session:       session,
		module:        wazerotest.NewModule(nil, sum),
		externModules: map[string]api.Module{},
		exports:       map[string]api.Function{},
	}
	session.instances[instanceID] = instance

	namePtr, nameLen := writeGuestTestString(t, client, "sum")
	paramsPtr, _ := writeGuestTestBytes(t, client, encodeU64ListForTest(20, 22))
	resultsPtr, _ := writeGuestTestBytes(t, client, make([]byte, 4))
	retPtr := allocGuestResultArea(t, client, 12)

	h.callExport(client.ctx, client.guest, []uint64{
		sessionID,
		instanceID,
		uint64(namePtr),
		uint64(nameLen),
		uint64(paramsPtr),
		2,
		uint64(resultsPtr),
		1,
		noTimeoutNanos,
		uint64(retPtr),
	})

	values, ok, msg := readU64ListResultForTest(t, client.memory(), retPtr)
	require.True(t, ok, msg)
	assert.Equal(t, []uint64{42}, values)
	assert.NotNil(t, instance.exports["sum"])
}

func TestCallExportReportsMissingExport(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	sessionID := uint64(9102)
	instanceID := uint64(4)
	session := newHostSessionState()
	registerTestSession(t, h, sessionID, session)

	instance := &instanceState{
		sessionID:     sessionID,
		session:       session,
		module:        wazerotest.NewModule(nil),
		externModules: map[string]api.Module{},
		exports:       map[string]api.Function{},
	}
	session.instances[instanceID] = instance

	namePtr, nameLen := writeGuestTestString(t, client, "missing")
	resultsPtr, _ := writeGuestTestBytes(t, client, make([]byte, 0))
	retPtr := allocGuestResultArea(t, client, 12)

	h.callExport(client.ctx, client.guest, []uint64{
		sessionID,
		instanceID,
		uint64(namePtr),
		uint64(nameLen),
		0,
		0,
		uint64(resultsPtr),
		0,
		noTimeoutNanos,
		uint64(retPtr),
	})

	_, ok, msg := readListResultForTest(t, client.memory(), retPtr)
	require.False(t, ok)
	assert.Contains(t, msg, `missing export "missing"`)
}

func TestCallExportRejectsUnexpectedResultLength(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	sessionID := uint64(9103)
	instanceID := uint64(5)
	session := newHostSessionState()
	registerTestSession(t, h, sessionID, session)

	pair := wazerotest.NewFunction(func(_ context.Context, _ api.Module, value uint64) (uint64, uint64) {
		return value, value + 1
	})
	pair.ExportNames = []string{"pair"}

	instance := &instanceState{
		sessionID:     sessionID,
		session:       session,
		module:        wazerotest.NewModule(nil, pair),
		externModules: map[string]api.Module{},
		exports:       map[string]api.Function{},
	}
	session.instances[instanceID] = instance

	namePtr, nameLen := writeGuestTestString(t, client, "pair")
	paramsPtr, _ := writeGuestTestBytes(t, client, encodeU64ListForTest(7))
	resultsPtr, _ := writeGuestTestBytes(t, client, make([]byte, 4))
	retPtr := allocGuestResultArea(t, client, 12)

	h.callExport(client.ctx, client.guest, []uint64{
		sessionID,
		instanceID,
		uint64(namePtr),
		uint64(nameLen),
		uint64(paramsPtr),
		1,
		uint64(resultsPtr),
		1,
		noTimeoutNanos,
		uint64(retPtr),
	})

	_, ok, msg := readListResultForTest(t, client.memory(), retPtr)
	require.False(t, ok)
	assert.Contains(t, msg, "unexpected result length: got 2 want 1")
}

func TestCallExportPropagatesTimeoutAndOtherErrors(t *testing.T) {
	client, err := newGuestClient()
	require.NoError(t, err)
	t.Cleanup(client.close)

	h := client.program.host
	sessionID := uint64(9104)
	instanceID := uint64(6)
	session := newHostSessionState()
	registerTestSession(t, h, sessionID, session)

	instance := &instanceState{
		sessionID:     sessionID,
		session:       session,
		module:        wazerotest.NewModule(nil),
		externModules: map[string]api.Module{},
		exports: map[string]api.Function{
			"timeout": newErrorFunction("timeout", errors.New("wrapped "+hostCallTimeoutError+" value")),
			"boom":    newErrorFunction("boom", errors.New("boom")),
		},
	}
	session.instances[instanceID] = instance

	retPtr := allocGuestResultArea(t, client, 12)
	resultsPtr, _ := writeGuestTestBytes(t, client, make([]byte, 0))

	for _, tc := range []struct {
		name    string
		wantMsg string
	}{
		{name: "timeout", wantMsg: hostCallTimeoutError},
		{name: "boom", wantMsg: "boom"},
	} {
		namePtr, nameLen := writeGuestTestString(t, client, tc.name)
		h.callExport(client.ctx, client.guest, []uint64{
			sessionID,
			instanceID,
			uint64(namePtr),
			uint64(nameLen),
			0,
			0,
			uint64(resultsPtr),
			0,
			noTimeoutNanos,
			uint64(retPtr),
		})

		_, ok, msg := readListResultForTest(t, client.memory(), retPtr)
		require.False(t, ok)
		assert.Equal(t, tc.wantMsg, msg)
	}
}

func TestCallGuestCallbackSuccessAndError(t *testing.T) {
	h, ctx, _ := newTestHostRuntime(t)

	var seenSessionID uint64
	var seenCallbackID uint64
	var seenArgs []uint64

	guest := newFakeCallbackGuest(func(sessionID, callbackID uint64, args []uint64) ([]uint64, error) {
		seenSessionID = sessionID
		seenCallbackID = callbackID
		seenArgs = append([]uint64(nil), args...)
		if callbackID == 9 {
			return nil, errors.New("boom")
		}
		return []uint64{11, 22}, nil
	})
	registerTestGuest(t, h, 41, guest)

	values, err := h.callGuestCallback(ctx, 41, 7, []uint64{3, 5})
	require.NoError(t, err)
	assert.Equal(t, []uint64{11, 22}, values)
	assert.Equal(t, uint64(41), seenSessionID)
	assert.Equal(t, uint64(7), seenCallbackID)
	assert.Equal(t, []uint64{3, 5}, seenArgs)
	assert.Equal(t, 1, guest.postCalls)

	values, err = h.callGuestCallback(ctx, 41, 9, []uint64{1})
	require.Error(t, err)
	assert.Nil(t, values)
	assert.EqualError(t, err, "boom")
	assert.Equal(t, 2, guest.postCalls)
}

func TestInvokeImportCallbackSelectiveSync(t *testing.T) {
	t.Run("sync before refreshes session state from extern modules", func(t *testing.T) {
		h, ctx, rt := newTestHostRuntime(t)
		guest := newFakeCallbackGuest(func(sessionID, callbackID uint64, args []uint64) ([]uint64, error) {
			return nil, nil
		})
		registerTestGuest(t, h, 77, guest)

		maxPages := uint32(1)
		session := newHostSessionState()
		session.globals[1] = &globalState{typ: valTypeI64, mutable: true, value: 3}
		session.memories[2] = &memoryState{initial: 1, maximum: &maxPages, data: []byte("old")}

		instance := &instanceState{
			sessionID:     77,
			session:       session,
			externs:       []externImport{{module: "env", name: "counter", kind: externKindGlobal, handle: 1}, {module: "env", name: "memory", kind: externKindMemory, handle: 2}},
			externModules: map[string]api.Module{},
		}

		require.NoError(t, h.instantiateExternModules(ctx, rt, instance.externs, instance))
		mod := instance.externModules["env"]
		require.NotNil(t, mod)

		global := mod.ExportedGlobal("counter")
		mutableGlobal, ok := global.(api.MutableGlobal)
		require.True(t, ok)
		mutableGlobal.Set(33)
		require.True(t, mod.Memory().Write(0, []byte("new")))

		stack := []uint64{}
		require.NoError(t, h.invokeImportCallback(ctx, instance, 1, callbackSyncBefore, nil, nil, stack))
		assert.Equal(t, uint64(33), session.globals[1].value)
		assert.Equal(t, []byte("new"), session.memories[2].data[:3])
	})

	t.Run("sync after pushes session state into extern modules", func(t *testing.T) {
		h, ctx, rt := newTestHostRuntime(t)
		guest := newFakeCallbackGuest(func(sessionID, callbackID uint64, args []uint64) ([]uint64, error) {
			return nil, nil
		})
		registerTestGuest(t, h, 77, guest)

		maxPages := uint32(1)
		session := newHostSessionState()
		session.globals[1] = &globalState{typ: valTypeI64, mutable: true, value: 44}
		session.memories[2] = &memoryState{initial: 1, maximum: &maxPages, data: []byte("abc")}

		instance := &instanceState{
			sessionID:     77,
			session:       session,
			externs:       []externImport{{module: "env", name: "counter", kind: externKindGlobal, handle: 1}, {module: "env", name: "memory", kind: externKindMemory, handle: 2}},
			externModules: map[string]api.Module{},
		}

		require.NoError(t, h.instantiateExternModules(ctx, rt, instance.externs, instance))
		mod := instance.externModules["env"]
		require.NotNil(t, mod)

		stack := []uint64{}
		require.NoError(t, h.invokeImportCallback(ctx, instance, 2, callbackSyncAfter, nil, nil, stack))
		assert.Equal(t, uint64(44), mod.ExportedGlobal("counter").Get())
		data, ok := mod.Memory().Read(0, 3)
		require.True(t, ok)
		assert.Equal(t, []byte("abc"), data)
	})
}

func TestInvokeImportCallbackTimeoutAndResultValidation(t *testing.T) {
	h, ctx, _ := newTestHostRuntime(t)

	callCount := 0
	guest := newFakeCallbackGuest(func(sessionID, callbackID uint64, args []uint64) ([]uint64, error) {
		callCount++
		return []uint64{99}, nil
	})
	registerTestGuest(t, h, 88, guest)

	instance := &instanceState{
		sessionID: 88,
		session:   newHostSessionState(),
	}

	clearDeadline := instance.beginCallDeadline(0)
	err := h.invokeImportCallback(ctx, instance, 1, 0, nil, nil, nil)
	clearDeadline()
	require.Error(t, err)
	assert.EqualError(t, err, hostCallTimeoutError)
	assert.Zero(t, callCount)

	stack := []uint64{0}
	err = h.invokeImportCallback(ctx, instance, 2, 0, nil, []api.ValueType{}, stack)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "returned 1 values, expected 0")
	assert.Equal(t, 1, callCount)
}
