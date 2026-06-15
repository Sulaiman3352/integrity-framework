VMLINUX := kern/vmlinux.h
MODULE  := github.com/sulaiman3352/integrity-framework

$(VMLINUX): 
	@echo "Generating $(VMLINUX) from this machine's kernel BTF..."
	bpftool -d btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

.PHONY: proto ebpf vmlinux vmlinux-force build all clean

proto:                  # regenerate gRPC code from the .proto
	protoc \
		--go_out=. \
		--go_opt=module=$(MODULE) \
		--go-grpc_out=. \
		--go-grpc_opt=module=$(MODULE) \
		api/proto/integrity.proto

vmlinux: $(VMLINUX)

vmlinux-force:	# Force regenerate after a kernel change
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

ebpf:	$(VMLINUX)              # regenerate eBPF bindings
	cd daemon && go generate ./...

build:                # build the daemon
	cd daemon && go build -o integrity-daemon .

all: proto ebpf build

clean: 
	rm -f daemon/integrity-daemon