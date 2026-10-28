// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Copyright (C) 2026 Sulayman Seid Ymam

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"math/bits"
	"net"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sulaiman3352/integrity-framework/daemon/pkg/pb"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
)

const (
	socketDir     = "/run/walia-guard"
	socketPath    = "/run/walia-guard/integrity.sock"
	channelBuffer = 1000

	// Ring-buffer sizing. The event ring buffer is a SINGLE BPF_MAP_TYPE_RINGBUF
	// shared by all CPUs (not per-CPU), so the more cores that can run the probe
	// concurrently, the more producers race the single consumer between reads.
	// We therefore budget ringbufPerCPUBytes of buffer per CPU, with a floor of
	// ringbufMinBytes on low-core machines. See ringbufBytes.
	ringbufPerCPUBytes = 64 * 1024  // 64 KB per CPU
	ringbufMinBytes    = 256 * 1024 // floor
)

// eventsDropped counts events lost because the Go channel was full.
// Read atomically by GetStatus; incremented in the main reader loop.
var eventsDropped atomic.Uint64

// ringReads counts total events successfully read from the BPF ring buffer.
var ringReads atomic.Uint64

// decodeErrors counts events that failed binary decoding.
var decodeErrors atomic.Uint64

func clean_output(b []byte) string {
	var n int = bytes.IndexByte(b, 0)
	if n == -1 {
		n = len(b)
	}
	return string(b[:n])
}

// bootOffset is the nanosecond offset between CLOCK_REALTIME and CLOCK_MONOTONIC,
// measured once at startup and frozen for the lifetime of the daemon.
//
// Adding bootOffset to a CLOCK_MONOTONIC timestamp (such as bpf_ktime_get_ns())
// yields the corresponding wall-clock time. Freezing at startup ensures NTP
// corrections after boot don't reorder events — critical for forensic audit trails.
var bootOffset = computeBootOffset()

// computeBootOffset samples both realtime and monotonic clocks back-to-back
// and returns realtime - monotonic as a nanosecond offset.
func computeBootOffset() int64 {
	var realtime, monotonic unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_REALTIME, &realtime); err != nil {
		log.Fatalf("failed to get realtime clock: %v", err)
	}
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonic); err != nil {
		log.Fatalf("failed to get monotonic clock: %v", err)
	}
	// note: two separate syscalls Between them a tiny slice of time passes and the fix is
	// (sandwich: read monotonic, read realtime, read monotonic again, use the average of the two monotonic reads) but it is a little bit over-engineering
	return realtime.Nano() - monotonic.Nano()
}

// ringbufBytes returns the size for the shared event ring buffer given the
// number of CPUs the kernel can schedule the probe on, scaling at
// ringbufPerCPUBytes per CPU with a floor of ringbufMinBytes.
//
// The kernel requires a ring-buffer size that is a power of two and a multiple
// of the page size, so the budget is rounded UP to the next power of two
// (which, being >= the 4 KB floor, is always page-aligned). Examples at
// 64 KB/CPU: 4 cores -> 256 KB, 8 -> 512 KB, 16 -> 1 MB.
func ringbufBytes(nCPU int) uint32 {
	size := max(ringbufMinBytes, nCPU*ringbufPerCPUBytes)
	// bits.Len(size-1) is the exponent of the smallest power of two >= size;
	// for an exact power of two it returns size unchanged.
	return uint32(1) << bits.Len(uint(size-1))
}

func main() {
	// Remove The Memlock Limit
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove Memlock limit: %v", err)
	}

	// Load the eBPF spec, then size the shared event ring buffer from the CPU
	// count BEFORE loading it into the kernel (max_entries is fixed at load time).
	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("failed to load eBPF spec: %v", err)
	}
	nCPU, err := ebpf.PossibleCPU()
	if err != nil || nCPU < 1 {
		// Fall back to the floor rather than failing to start over a sizing hint.
		nCPU = 1
	}
	rbSize := ringbufBytes(nCPU)
	spec.Maps["events"].MaxEntries = rbSize
	log.Printf("event ring buffer sized to %d KB (%d possible CPUs)", rbSize/1024, nCPU)

	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Attach fentry to the real x86_64 syscall entry functions.
	//
	// fentry is a BPF link (bpf_link_create): it is system-wide and fires on
	// every CPU. The legacy perf-event tracepoint attach (link.Tracepoint)
	// pins its event to CPU 0 in cilium/ebpf v0.21.0, silently losing events
	// from all other CPUs — that is why the old probe missed most commands.
	lkExecve, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.HandleExecve,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		log.Fatalf("failed to attach fentry execve: %v", err)
	}
	defer lkExecve.Close()

	// fentry on execveat — covers fexecve() and memfd-based execution, which
	// never go through execve and would otherwise be invisible to the daemon.
	lkExecveat, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.HandleExecveat,
		AttachType: ebpf.AttachTraceFEntry,
	})
	if err != nil {
		log.Fatalf("failed to attach fentry execveat: %v", err)
	}
	defer lkExecveat.Close()

	// Open a Reader on The Ring Buffer
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("failed to read the events: %v", err)
	}
	defer rd.Close()

	// create & read the socket
	if err := os.MkdirAll(socketDir, 0700); err != nil {
		log.Fatalf("failed to create socket directory %v: %v", socketDir, err)
	}
	if err := os.Remove(socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.Fatalf("failed to remove stale socket: %v", err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("failed to listen on socket %v: %v", socketPath, err)
	}

	if err := os.Chmod(socketPath, 0600); err != nil {
		log.Fatalf("failed to set socket permissions: %v", err)
	}
	defer os.Remove(socketPath)

	grpcServer := grpc.NewServer()
	srv := &server{eventCh: make(chan *pb.ExecEvent, channelBuffer), dropCount: objs.DropCount, shutdown: make(chan struct{})}
	pb.RegisterIntegrityServiceServer(grpcServer, srv)

	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			log.Fatalf("gRPC server failed: %v", err)
		}
	}()

	log.Printf("daemon started: socket %s, channel buffer %d", socketPath, channelBuffer)

	// Signal handling — clean shutdown on Ctrl+C / SIGTERM
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("received signal %v, shutting down...", sig)
		rd.Close()
	}()

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) { // Clean-Shutdown
				log.Println("Thank you for using Walia Guard🤗, See you soon!👋")
				close(srv.shutdown)
				grpcServer.GracefulStop()
				return
			}
			log.Printf("error reading: %v", err)
			continue
		}
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			decodeErrors.Add(1)
			log.Printf("error decoding: %v", err)
			continue
		}
		ringReads.Add(1)

		pbEvent := &pb.ExecEvent{
			TimestampNs: event.Timestamp,
			Pid:         event.Pid,
			Uid:         event.Uid,
			Source:      pb.ExecSource(event.Source),
			Comm:        clean_output(event.Comm[:]),
			Filename:    clean_output(event.Filename[:]),
			WallClockNs: event.Timestamp + uint64(bootOffset),
			TrustReason: "observed",
		}
		select {
		case srv.eventCh <- pbEvent:
			// delivered
		default:
			eventsDropped.Add(1)
		}
	}
}
