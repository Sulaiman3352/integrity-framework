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

struct event {
    __u32 pid;
    __u32 uid;
    __u8  comm[TASK_COMM_LEN];
    __u8  filename[MAX_FILENAME_LEN]; // I chosed here u8 over char because it is an explicitly unsigned single byte from the kernel's own type family
};
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);   // "what kind of map?" → a ring buffer
    __uint(max_entries, 256 * 1024);      // "how big?"          → 256 KB
} events SEC(".maps");                    // name it "events", put it in the maps section
struct event *unused_event __attribute__((unused)); // the perpose of this is to force the compiler to acknowledge struct event as a used type → it gets preserved in the BTF → bpf2go finds it → generates the Go struct automatically.

SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Zero the filename buffer FIRST, so stale ring-buffer data can't show through.
    __builtin_memset(&e->filename, 0, sizeof(e->filename));

    // Read the filename; check the result.
    const char *filename = (const char *)ctx->args[0];
    long ret = bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);
    if (ret < 0) {
        // Read failed — mark it clearly instead of leaving garbage.
        e->filename[0] = '?';
        e->filename[1] = '\0';
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";