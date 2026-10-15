// SPDX-License-Identifier: GPL-2.0-or-later
//
// execve.bpf.c — minimal eBPF probe (Phase 1, Step 1).
// Copyright (C) 2026 Sulayman Seid Ymam

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

#define EXEC_SOURCE_EXECVE 1
#define EXEC_SOURCE_EXECVEAT 2

struct event {
    __u64 timestamp;    
    __u32 pid;
    __u32 uid;
    __u8  source;
    __u8  comm[TASK_COMM_LEN];
    __u8  filename[MAX_FILENAME_LEN]; // I chosed here u8 over char because it is an explicitly unsigned single byte from the kernel's own type family
};
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);   // "what kind of map?" → a ring buffer
    __uint(max_entries, 256 * 1024);      // placeholder (256 KB): the daemon overrides
                                          // this at load time, scaling it by CPU count
                                          // (see ringbufBytes in daemon/main.go). This
                                          // value only applies if the object is loaded
                                          // without the daemon (e.g. raw bpftool).
} events SEC(".maps");                    // name it "events", put it in the maps section

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);     // drop counter (single u64)
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} drop_count SEC(".maps");

struct event *unused_event __attribute__((unused)); // the perpose of this is to force the compiler to acknowledge struct event as a used type → it gets preserved in the BTF → bpf2go finds it → generates the Go struct automatically.

static __always_inline int submit_exec_event(const char *filename, __u8 source)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        // ring buffer full — count the drop, never block in the kernel
        __u32 key = 0;
        __u64 *count = bpf_map_lookup_elem(&drop_count, &key);
        if (count)
            __sync_fetch_and_add(count, 1);
        return 0;
    }

    e->timestamp = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->source = source;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Zero the filename buffer FIRST, so stale ring-buffer data can't show through.
    __builtin_memset(&e->filename, 0, sizeof(e->filename));

    // bpf_probe_read_user_str returns the number of bytes copied INCLUDING the
    // trailing NUL, or a negative value on failure.
    long ret = bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

    if (ret < 0) {
        // Read failed — mark it clearly instead of leaving an empty field.
        __builtin_memcpy(&e->filename, "<unreadable>", 13);
    } else if (ret <= 1) {
        __builtin_memcpy(&e->filename, "<fd>", 5);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// Attaches to the x86_64 syscall entry functions via fentry (BPF trampoline link).
//
// Why fentry instead of tracepoint/syscalls/sys_enter_execve: the perf-event
// based tracepoint attach in cilium/ebpf v0.21.0 (link.Tracepoint) opens its
// perf event with cpu=0, so the program only fires for syscalls that happen to
// run on CPU 0 — every exec on the other CPUs was silently lost. An fentry
// link is created with bpf_link_create: it is system-wide and fires on every CPU.
//
// BPF_PROG unpacks the fentry context, which is the argument list of the
// traced function. On x86_64 every syscall handler takes exactly one argument,
// a `struct pt_regs *` holding the userspace registers of the caller. That
// pointer is kernel memory, so its fields must be read with
// bpf_probe_read_kernel — which is what the _CORE_SYSCALL macros do.
//
//   execve(filename, argv, envp)     → filename is PARM1 (rdi)
//   execveat(dirfd, filename, ...)   → filename is PARM2 (rsi), dirfd is PARM1
SEC("fentry/__x64_sys_execve")
int BPF_PROG(handle_execve, struct pt_regs *regs)
{
    return submit_exec_event((const char *)PT_REGS_PARM1_CORE_SYSCALL(regs), EXEC_SOURCE_EXECVE);
}

SEC("fentry/__x64_sys_execveat")
int BPF_PROG(handle_execveat, struct pt_regs *regs)
{
    return submit_exec_event((const char *)PT_REGS_PARM2_CORE_SYSCALL(regs), EXEC_SOURCE_EXECVEAT);
}

char LICENSE[] SEC("license") = "GPL";