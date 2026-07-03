// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"

	"github.com/sulaiman3352/integrity-framework/daemon/pkg/pb"
	"google.golang.org/grpc"
)

type server struct {
	pb.UnimplementedIntegrityServiceServer

	// this is channel needed for grpc socket implementation
	eventCh chan *pb.ExecEvent
}

func (s *server) GetStatus(ctx context.Context, req *pb.StatusRequest) (*pb.StatusResponse, error) {

	return &pb.StatusResponse{
		Running:       true,
		UptimeS:       0,
		TpmPresent:    false,
		TpmState:      "none",
		EventsTotal:   0,
		EventsBlocked: 0,
		Mode:          "observing",
	}, nil
}

func (s *server) StreamEvents(req *pb.StreamRequest, stream grpc.ServerStreamingServer[pb.ExecEvent]) error {
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case event := <-s.eventCh:
			if err := stream.Send(event); err != nil {
				return err
			}
		}
	}
}
