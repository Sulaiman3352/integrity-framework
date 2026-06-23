package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sulaiman3352/integrity-framework/daemon/pkg/pb"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
)

const (
	socketDir  = "/run/walia-guard"
	socketPath = "/run/walia-guard/integrity.sock"
)

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
	unix.ClockGettime(unix.CLOCK_REALTIME, &realtime)
	unix.ClockGettime(unix.CLOCK_MONOTONIC, &monotonic)
	return realtime.Nano() - monotonic.Nano()
}

// eventToWallTime converts a bpf_ktime_get_ns() timestamp (CLOCK_MONOTONIC,
// nanoseconds since boot) to a time.Time in the wall-clock epoch.
func eventToWallTime(bpfTimestamp uint64) time.Time {
	return time.Unix(0, int64(bpfTimestamp)+bootOffset)
}

func main() {
	// Remove The Memlock Limit
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove Memlock limit: %v", err)
	}

	// Load The eBPF Objects Into The Kernel
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Attach The Probe To The Tracepoint(hook)
	tp, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)
	if err != nil {
		log.Fatalf("failed to load Probe to tracepoint: %v", err)
	}
	defer tp.Close()

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

	grpcServer := grpc.NewServer()
	pb.RegisterIntegrityServiceServer(grpcServer, &server{})

	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			log.Fatalf("gRPC server failed: %v", err)
		}
	}()

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) { // Clean-Shutdown
				log.Println("Thank you for using Walia Guard🤗, See you soon!👋")
				return
			}
			log.Printf("error reading: %v", err)
			continue
		}
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("error decoding: %v", err)
			continue
		}

		eventTime := eventToWallTime(event.Timestamp)
		fmt.Printf("[%s] PID=%d UID=%d COMM=%s FILENAME=%s\n",
			// eventTime.UTC().Format(time.RFC3339Nano),
			eventTime.Format(time.StampMicro),
			event.Pid, event.Uid,
			clean_output(event.Comm[:]),
			clean_output(event.Filename[:]))
	}
}
