package main

import (
	"log"

	"github.com/cilium/ebpf/rlimit"
)

func main() {

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("something failed: %v", err)
	}

	var objs bpfObjects

	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load eBPF objects: %v", err)
	}
	defer objs.Close()
}
