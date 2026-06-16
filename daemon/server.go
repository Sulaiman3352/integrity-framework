// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"

	"github.com/sulaiman3352/integrity-framework/daemon/pkg/pb"
)

type server struct {
	pb.UnimplementedIntegrityServiceServer
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
