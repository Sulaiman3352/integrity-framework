package main

import (
	"log"
	"encoding/binary"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

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

	//
	for {
		record, err := rd.Read()
		if err != nil {
			log.Fatalf("The reader got closed")
		}
		var event bpfEvent

	}
}
