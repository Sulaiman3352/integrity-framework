package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/sulaiman3352/integrity-framework/daemon/pkg/pb"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

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

// eventToWallTime converts a bpf_ktime_get_ns() timestamp (CLOCK_MONOTONIC,
// nanoseconds since boot) to a time.Time in the wall-clock epoch.
func eventToWallTime(bpfTimestamp uint64) time.Time {
	return time.Unix(0, int64(bpfTimestamp)+bootOffset)
}

// function to create a new client
func newClient() (pb.IntegrityServiceClient, *grpc.ClientConn) {
	conn, err := grpc.NewClient("unix:///run/walia-guard/integrity.sock", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to call the socket: %v", err)
	}
	return pb.NewIntegrityServiceClient(conn), conn
}

func statusCmd() {
	client, conn := newClient()
	defer conn.Close()

	stat, err := client.GetStatus(context.Background(), &pb.StatusRequest{})
	if err != nil {
		log.Fatalf("Failed to get status: %v", err)
	}
	fmt.Printf("Running: %v\nMode: %v\nUptime: %vs\nTPM: %v\nTPM Status: %v\nEvents: %v total, %v blocked", stat.Running, stat.Mode, stat.UptimeS, stat.TpmPresent, stat.TpmState, stat.EventsTotal, stat.EventsBlocked)

}

// Big note here for the future!!!
// Have the daemon convert to wall-clock before sending, and add a proper wall-clock timestamp field to the proto

func watchCmd() {
	client, conn := newClient()
	defer conn.Close()

	stream, err := client.StreamEvents(context.Background(), &pb.StreamRequest{})
	if err != nil {
		log.Fatalf("Failed to catch the stream: %v", err)
	}

	for {
		event, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			fmt.Printf("That is all for now")
			break
		} else if err != nil {
			log.Fatalf("something went wrong: %v", err)
		} else if err == nil {
			eventTime := eventToWallTime(event.TimestampNs)
			fmt.Printf("[%s] PID=%d UID=%d COMM=%s FILENAME=%s\n",
				eventTime.Format(time.StampMicro),
				event.Pid, event.Uid,
				event.Comm,
				event.Filename)
		}
	}
}

func main() {
	if len(os.Args) > 2 {
		log.Fatalf("too many arguments")
	} else if len(os.Args) < 2 {
		log.Fatalf("you need to write an argument")
	}

	if os.Args[1] != "status" && os.Args[1] != "watch" {
		log.Fatalf("unrecognized argument")
	}

	switch {
	case os.Args[1] == "status":
		statusCmd()
	case os.Args[1] == "watch":
		watchCmd()
	}
}
