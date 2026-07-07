package main

import (
	"os"
	"fmt"
	"log"
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"github.com/sulaiman3352/integrity-framework/daemon/pkg/pb"
)

func statusCmd(){
	conn, err := grpc.NewClient("unix:///run/walia-guard/integrity.sock", grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil{
		log.Fatalf("Failed to call the socket: %v",err)
	}
	defer conn.Close()

	client := pb.NewIntegrityServiceClient(conn)
	stat, err := client.GetStatus(context.Background(), &pb.StatusRequest{})
	if err != nil{
                log.Fatalf("Failed to get status: %v",err)
        }
	fmt.Printf("Running: %v\nMode: %v\nUptime: %v\nTPM: %v\nTPM Status: %v\nEvents: %v total, %v blocked",stat.Running, stat.Mode, stat.UptimeS, stat.TpmPresent, stat.TpmState, stat.EventsTotal, stat.EventsBlocked)


}

func watchCmd(){

}


func main(){
	if len(os.Args) > 2{
		log.Fatalf("too many arguments")	
	} else if len(os.Args) < 2{
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
