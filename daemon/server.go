// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"

	"github.com/cilium/ebpf"
	"github.com/sulaiman3352/integrity-framework/daemon/pkg/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type server struct {
	pb.UnimplementedIntegrityServiceServer

	eventCh   chan *pb.ExecEvent
	dropCount *ebpf.Map // BPF drop_count map, read in GetStatus
	shutdown  chan struct{}   //close when the daemon shutdown
}

func (s *server) GetStatus(ctx context.Context, req *pb.StatusRequest) (*pb.StatusResponse, error) {
	var bpfDrops uint64
	if s.dropCount != nil {
		var key uint32
		var val uint64
		if err := s.dropCount.Lookup(&key, &val); err == nil {
			bpfDrops = val
		}
	}

	return &pb.StatusResponse{
		Running:          true,
		UptimeS:          0,
		TpmPresent:       false,
		TpmState:         "none",
		EventsTotal:      0,
		EventsBlocked:    0,
		EventsDropped:    eventsDropped.Load(),
		EventsDroppedBpf: bpfDrops,
		RingReads:        ringReads.Load(),
		DecodeErrors:     decodeErrors.Load(),
		Mode:             "observing",
	}, nil
}

func (s *server) StreamEvents(req *pb.StreamRequest, stream grpc.ServerStreamingServer[pb.ExecEvent]) error {
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case <-s.shutdown:          
			return status.Error(codes.Unavailable, "walia-guard daemon is shutting down")
		case event := <-s.eventCh:
			if err := stream.Send(event); err != nil {
				return err
			}
		}
	}
}
