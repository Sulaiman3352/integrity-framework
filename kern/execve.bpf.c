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
