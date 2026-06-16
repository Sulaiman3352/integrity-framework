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


help:
	@echo "Targets:"
	@echo "  make / make all  	- generate (eBPF + proto) and build"
	@echo "  make ebpf        	- regenerate only eBPF bindings"
	@echo "  make proto       	- regenerate only proto/gRPC code"
	@echo "  make build       	- build the daemon (uses committed generated code)"
	@echo "  make clean       	- remove built binaries"
	@echo "  make vmlinux		- genrate file vmlinux.h in case it does not exist"
	@echo "  make vmlinux-Force	- regenrate vmlinux.h file even if it exists"