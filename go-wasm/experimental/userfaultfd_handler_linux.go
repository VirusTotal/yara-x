//go:build linux

package experimental

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"

	uffd "github.com/niallnsec/linux-uffd-go"
	"golang.org/x/sys/unix"
)

const userfaultfdPollTimeoutMillis = 100

type userfaultfdHandler struct {
	uffd      uffd.UFFD
	start     uintptr
	length    uintptr
	size      int64
	done      chan error
	cancel    context.CancelFunc
	closeOnce sync.Once
	trace     *userfaultfdTrace
}

func newUserfaultfdHandler(addr unsafe.Pointer, length uintptr, src io.ReaderAt, size int64) (*userfaultfdHandler, error) {
	if addr == nil || length == 0 {
		logUFFDTracef("newUserfaultfdHandler noop addr=%#x length=%d size=%d src=%T", uintptr(addr), length, size, src)
		return &userfaultfdHandler{}, nil
	}
	logUFFDTracef("newUserfaultfdHandler addr=%#x length=%d size=%d src=%T", uintptr(addr), length, size, src)

	uffd, err := registerUserfaultfdRange(uintptr(addr), length)
	if err != nil {
		logUFFDTracef("newUserfaultfdHandler register failed addr=%#x length=%d err=%v", uintptr(addr), length, err)
		return nil, err
	}
	logUFFDTracef("newUserfaultfdHandler registered uffd=%d addr=%#x length=%d", uffd, uintptr(addr), length)

	h := &userfaultfdHandler{
		uffd:   uffd,
		start:  uintptr(addr),
		length: length,
		size:   size,
		done:   make(chan error, 1),
		trace:  newUserfaultfdTraceFromEnv(),
	}
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel = cancel
	go func() {
		logUFFDTracef("userfaultfdHandler goroutine starting uffd=%d addr=%#x length=%d", h.uffd, h.start, length)
		h.done <- h.serve(ctx, src)
		close(h.done)
	}()
	return h, nil
}

func (h *userfaultfdHandler) Close() error {
	if h == nil || h.uffd == 0 {
		return nil
	}
	logUFFDTracef("userfaultfdHandler.Close uffd=%d addr=%#x size=%d", h.uffd, h.start, h.size)

	var closeErr error
	h.closeOnce.Do(func() {
		if h.cancel != nil {
			h.cancel()
		}
		if err, ok := <-h.done; ok {
			closeErr = err
		}
		if h.trace != nil {
			h.trace.logSummary(h.size)
		}
		_ = unix.Close(int(h.uffd))
		h.uffd = 0
	})
	return closeErr
}

func registerUserfaultfdRange(start, length uintptr) (uffd.UFFD, error) {
	logUFFDTracef("registerUserfaultfdRange start=%#x length=%d", start, length)
	if err := uffd.CheckSupport(); err != nil {
		return 0, err
	}
	uffdFD, err := uffd.Open(uffd.UFFD_OPEN_DEFAULT | uffd.UFFD_USER_MODE_ONLY)
	if err != nil && errors.Is(err, syscall.EINVAL) {
		uffdFD, err = uffd.Open(uffd.UFFD_OPEN_DEFAULT)
	}
	if err != nil {
		return 0, err
	}
	if err := uffdFD.Init(0); err != nil {
		_ = uffdFD.Close()
		return 0, err
	}
	if err := uffdFD.Register(start, length, uffd.UFFDIO_REGISTER_MODE_MISSING); err != nil {
		_ = uffdFD.Close()
		return 0, err
	}
	return uffdFD, nil
}

func (h *userfaultfdHandler) serve(ctx context.Context, src io.ReaderAt) error {
	logUFFDTracef("userfaultfdHandler.serve start uffd=%d addr=%#x size=%d src=%T", h.uffd, h.start, h.size, src)
	pageSize := os.Getpagesize()
	pageMask := uintptr(pageSize - 1)
	chunkMask := uintptr(experimentalHugePageSize - 1)
	chunkBuf, err := uffd.AllocateMoveBuffer(experimentalHugePageSize)
	if err != nil {
		return fmt.Errorf("allocate userfaultfd staging chunk: %w", err)
	}
	defer func() { _ = chunkBuf.Close() }()
	chunkBytes := chunkBuf.Bytes()

	handler := uffd.NewHandler(h.uffd, &uffd.HandlerOptions{
		PollTimeout: userfaultfdPollTimeoutMillis * time.Millisecond,
	})

	return handler.Serve(ctx, func(fault uffd.Fault, resolver uffd.Resolver) error {
		pageStart := fault.Address &^ pageMask
		chunkStart := pageStart &^ chunkMask
		if chunkStart < h.start {
			chunkStart = h.start
		}
		offset := int64(chunkStart - h.start)
		if h.trace == nil && offset == 0 {
			logUFFDTracef("userfaultfdHandler.serve first fault chunk_start=%#x page_start=%#x offset=%d", chunkStart, pageStart, offset)
		}
		if h.trace != nil {
			h.trace.record(offset, h.size)
		}

		chunkLen := experimentalHugePageSize
		if relativeChunkStart := chunkStart - h.start; relativeChunkStart < h.length {
			if remainingMapping := h.length - relativeChunkStart; remainingMapping < uintptr(chunkLen) {
				chunkLen = int(remainingMapping)
			}
		}
		if chunkLen <= 0 || chunkLen > len(chunkBytes) {
			return fmt.Errorf("invalid chunk length %d for fault at %d", chunkLen, pageStart)
		}

		clear(chunkBytes[:chunkLen])
		if offset < h.size {
			readBuf := chunkBytes[:chunkLen]
			if remaining := h.size - offset; remaining < int64(len(readBuf)) {
				readBuf = readBuf[:int(remaining)]
			}
			n, err := src.ReadAt(readBuf, offset)
			if err != nil && !(errors.Is(err, io.EOF) && n > 0) {
				return fmt.Errorf("fault page read at %d: %w", offset, err)
			}
		}

		moved, err := resolver.PopulateMove(chunkStart, chunkBytes[:chunkLen])
		if err != nil {
			return fmt.Errorf("populate userfaultfd chunk at %d: %w", chunkStart, err)
		}
		if h.trace != nil {
			h.trace.recordMove(moved, int64(chunkLen))
		}
		return nil
	})
}

func isUserfaultfdCloseError(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, unix.EBADF) || errors.Is(err, unix.EINVAL) || errors.Is(err, os.ErrClosed)
}
