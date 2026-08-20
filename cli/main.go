// SPDX-License-Identifier: AGPL-3.0-or-later
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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

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
	fmt.Printf("Running: %v\nMode: %v\nUptime: %vs\nTPM: %v\nTPM Status: %v\nEvents: %v total, %v blocked, %v dropped", stat.Running, stat.Mode, stat.UptimeS, stat.TpmPresent, stat.TpmState, stat.EventsTotal, stat.EventsBlocked, stat.EventsDropped)

}

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
			eventTime := time.Unix(0, int64(event.WallClockNs))
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
