# CPU-Pinning Bug in cilium/ebpf v0.21.0 and the fentry Fix

> **Author:** Sulayman Seid Ymam
> **Date:** August 2026
> **Commit:** `7c06e98`
> **Environment:** Fedora 43 · kernel 7.0.6 · 8-core Ryzen 3500U · cilium/ebpf v0.21.0

---

> **Update — 28 October 2026:** the project now builds against **cilium/ebpf v0.22.0** on
> **kernel 7.2.9**. Nothing in the analysis below changes — `link.Tracepoint` is still
> avoided and fentry is still the attach mechanism. The version bump was forced by an
> unrelated problem: kernel 7.2.x ships a 32-byte BTF header, and v0.21.0 rejects it with
> `load vmlinux: parsing .BTF header: header contains non-zero trailer`, so the daemon
> could not load its programs at all. Versions below are kept as the record of the original
> investigation.

---

## 1. The Problem

After implementing the eBPF execve/execveat probe with a ring buffer pipeline, the daemon
appeared to work — it printed events to the console. But on closer inspection, **most
executions on the system were invisible**. Running `ls`, `cat`, `vim`, or any command from a
terminal produced either no output or sporadic output, while the system was clearly executing
dozens of programs per second.

The daemon was only capturing events from **one CPU core**. On an 8-core machine, roughly
7/8 of all executions were silently lost.

## 2. Investigation

### 2.1 Initial Hypotheses

Several explanations were considered:

- **Ring buffer too small** — ruled out: the buffer was 256 KB and the drop counter showed
  zero drops.
- **Go channel full** — ruled out: `eventsDropped` atomic counter was zero.
- **eBPF verifier silently rejecting the program** — ruled out: `bpftool prog show` confirmed
  the program was loaded and attached.
- **Perf event pinned to a single CPU** — the remaining hypothesis.

### 2.2 A/B Taskset Test

The decisive test used `taskset` to force commands onto specific CPUs:

```bash
# Terminal 1: start daemon, watch output
sudo ./integrity-daemon

# Terminal 2: run commands pinned to CPU 3
taskset -c 3 touch /tmp/test1
taskset -c 3 ls /tmp

# Terminal 3: run commands pinned to CPU 0
taskset -c 0 touch /tmp/test2
taskset -c 0 ls /tmp
```

**Results:**

| Command pinned to | Events captured |
|-------------------|-----------------|
| CPU 0             | All events visible |
| CPU 3             | Events missing |

This confirmed the perf event was pinned to CPU 0 only.

### 2.3 bpftool Inspection

```bash
bpftool prog show
```

The program was listed as attached to `tracepoint/syscalls/sys_enter_execve`, type
`tracepoint`. The tracepoint attachment appeared correct at the API level — but the
underlying perf event was only open on CPU 0.

## 3. Root Cause

The bug is in **cilium/ebpf v0.21.0**'s `link.Tracepoint()` implementation.

When `link.Tracepoint("syscalls", "sys_enter_execve", ...)` is called, the library
internally calls `openTracepointPerfEvent(tid, perfAllThreads)`. That function opens a perf
event **pinned to CPU 0**:

```go
// cilium/ebpf v0.21.0 — internal/perf/reader.go (simplified)
func openTracepointPerfEvent(tid int, ...) {
    // ...
    pe, err := perf.NewMonitor(perf.Config{
        CPU: 0,  // <-- hardcoded to CPU 0
        // ...
    })
}
```

The `cpu=0` means the perf event only fires when `sys_enter_execve` occurs on CPU 0. On a
multi-core system, the other CPUs execute syscalls independently — their events never reach
the perf event, and therefore never reach the ring buffer.

**Why this happens:** tracepoints are per-CPU in Linux. To capture a tracepoint on all CPUs,
you need to open a perf event on each CPU. cilium/ebpf v0.21.0's `link.Tracepoint()` opens
only one perf event (on CPU 0), so only CPU 0 events are captured. This is a library-level
bug, not a kernel bug — the kernel supports per-CPU tracepoint attachment; the library just
doesn't do it.

**Silent failure:** The BPF program loads, attaches, and passes the verifier. No error is
returned. The ring buffer receives events — just not from most CPUs. There is no diagnostic
signal that events are being lost.

## 4. The Fix: fentry via BPF Trampoline

### 4.1 Why fentry

fentry (function entry tracing) uses the kernel's **BPF trampoline** mechanism rather than
perf events. A trampoline link is created with `bpf_link_create()` and is **system-wide** —
it fires on every CPU when the target function is called.

Key differences from tracepoint:

| | tracepoint (perf event) | fentry (BPF trampoline) |
|---|---|---|
| Per-CPU | Yes — need one perf event per CPU | No — single link, all CPUs |
| Kernel requirement | Any kernel with perf | 5.5+ (BPF trampoline) |
| ctx type | `struct trace_event_raw_sys_enter` | Function argument list |
| cilium/ebpf v0.21.0 | `link.Tracepoint` (buggy CPU=0) | `link.AttachTracing` (works) |

### 4.2 Go Side: `link.AttachTracing`

In `daemon/main.go`:

```go
// OLD (broken — CPU 0 only):
tpExecve, err := link.Tracepoint("syscalls", "sys_enter_execve", objs.HandleExecve, nil)

// NEW (works — all CPUs):
lkExecve, err := link.AttachTracing(link.TracingOptions{
    Program:    objs.HandleExecve,
    AttachType: ebpf.AttachTraceFEntry,
})
```

The `AttachType: ebpf.AttachTraceFEntry` tells `cilium/ebpf` to use
`BPF_PROG_TYPE_TRACING` with `bpf_link_create`, which creates a system-wide trampoline
link.

### 4.3 BPF Side: `SEC("fentry/...")` + `BPF_PROG`

In `kern/execve.bpf.c`:

```c
// OLD — tracepoint context:
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    return submit_exec_event((const char *)ctx->args[0]);
}

// NEW — fentry context:
SEC("fentry/__x64_sys_execve")
int BPF_PROG(handle_execve, struct pt_regs *regs)
{
    return submit_exec_event((const char *)PT_REGS_PARM1_CORE_SYSCALL(regs));
}
```

Two changes here:
1. **`SEC("fentry/__x64_sys_execve")`** — tells the BPF linker to attach to the kernel
   function `__x64_sys_execve` via fentry.
2. **`BPF_PROG` macro** — unpacks the fentry context into typed function arguments. On
   x86_64, every syscall handler takes a single `struct pt_regs *` argument. The macro
   gives us `regs` directly.

## 5. The BPF Verifier Issue

### 5.1 First Attempt: `PT_REGS_PARM1(ctx)`

The initial fentry code used:

```c
SEC("fentry/__x64_sys_execve")
int handle_execve(void *ctx)
{
    return submit_exec_event((const char *)PT_REGS_PARM1(ctx));
}
```

This failed with:

```
R1 type=ctx expected=ptr_
0: (85) call bpf_probe_read_user_str#-6672
R1 type=ctx expected=ptr_, off=112
invalid bpf_context access off=112 size=8
```

### 5.2 Why It Failed

In fentry programs, `ctx` is **not** a `struct pt_regs *`. It is the raw **function
argument array** — a `void *` pointing to the kernel stack where the function's arguments
are laid out. On x86_64 `__x64_sys_execve(struct pt_regs *regs)`, the single argument
(`regs`) is at offset 0 of the argument array.

`PT_REGS_PARM1` is designed for **kprobe** context where `ctx` actually is `struct pt_regs *`.
Using it on fentry context reads at the wrong offset (112 bytes into the argument array),
which the verifier rejects as an invalid context access.

### 5.3 The Fix: `BPF_PROG` + `PT_REGS_PARM1_CORE_SYSCALL`

```c
SEC("fentry/__x64_sys_execve")
int BPF_PROG(handle_execve, struct pt_regs *regs)
{
    return submit_exec_event((const char *)PT_REGS_PARM1_CORE_SYSCALL(regs));
}
```

**`BPF_PROG`** is the correct macro for fentry/fexit programs. It:
- Unpacks the fentry context into the typed function arguments declared after the program
  name (`struct pt_regs *regs`)
- The `regs` variable now correctly points to the `struct pt_regs *` argument of
  `__x64_sys_execve`

**`PT_REGS_PARM1_CORE_SYSCALL`** then reads `regs->di` (the first syscall argument on
x86_64) using `bpf_probe_read_kernel` (CORE-safe). For `execveat`, `PT_REGS_PARM2_CORE_SYSCALL`
reads `regs->si` (the second argument, which is the filename pointer).

### 5.4 Key Insight

The `_CORE_SYSCALL` macros are specifically designed for reading syscall parameters from
`pt_regs` in a CO-RE-safe way. They use `bpf_core_field_exists` to handle struct layout
differences across kernel versions. The distinction is:

| Macro | Context | Use case |
|-------|---------|----------|
| `PT_REGS_PARM1` | kprobe (ctx IS pt_regs) | kprobes, kretprobes |
| `PT_REGS_PARM1_CORE_SYSCALL` | fentry (ctx is arg array, regs is pt_regs) | fentry on syscall handlers |

## 6. Verification

After deploying the fix, the A/B taskset test was repeated:

```bash
# Commands pinned to CPU 3:
taskset -c 3 touch /tmp/test1
taskset -c 3 cp /bin/ls /tmp/ls_copy
taskset -c 3 ls /tmp

# Commands pinned to CPU 7:
taskset -c 7 touch /tmp/test2
taskset -c 7 cat /etc/hostname
```

**Results:**

| CPU | Commands run | Events captured |
|-----|-------------|-----------------|
| CPU 3 | 3 | 3/3 |
| CPU 7 | 3 | 3/3 |
| CPU 0 | (background) | also captured |

All events from CPUs 3 and 7 appeared in the daemon output. Zero drops, zero decode errors.

`bpftool link show` confirmed the new attachment type:

```
... prog_id 123  prog_type tracing  attach_type trace_fentry  target_btf_id 77774
```

The `prog_type tracing` and `attach_type trace_fentry` confirm a BPF trampoline link —
system-wide, all CPUs.

## 7. Additional Changes in the Same Commit

The fix commit (`7c06e98`) also addressed several related issues:

### 7.1 BPF-side Drop Counter

Added a `BPF_MAP_TYPE_ARRAY` map (`drop_count`) that atomically increments when the ring
buffer is full. Read from userspace via `GetStatus` to report BPF-side drops separately from
Go-channel drops.

### 7.2 Debug Counters

Added `ringReads` and `decodeErrors` atomic counters to `StatusResponse` for observability
during development. These help distinguish "events never arrived" from "events arrived but
couldn't be decoded."

### 7.3 Ring Buffer Size

Increased from 256 KB to 512 KB. While the CPU-pinning bug was the primary cause of missed
events, the larger buffer provides more headroom for bursty workloads (e.g., package manager
operations that spawn hundreds of processes).

### 7.4 Shutdown Channel

Added a `shutdown chan struct{}` to the server. When the daemon receives SIGINT/SIGTERM, it
closes the ring buffer reader (causing `rd.Read()` to return `ringbuf.ErrClosed`), then
closes the shutdown channel, then calls `grpcServer.GracefulStop()`. This prevents
`GracefulStop()` from hanging indefinitely when a watch client is connected.

### 7.5 CLI Graceful Shutdown Handling

The CLI now checks for `codes.Unavailable` (returned by the daemon on shutdown) before
checking for `io.EOF`, and exits cleanly with a message instead of a fatal error.

## 8. Lessons Learned

1. **cilium/ebpf v0.21.0's `link.Tracepoint` is broken for multi-CPU tracing.** If your
   eBPF program needs to capture events from all CPUs (i.e., almost always), use
   `link.AttachTracing` with fentry instead.

2. **Silent failures are the worst failures.** The tracepoint attachment returned no error.
   The ring buffer received events. The daemon appeared to work. The only symptom was
   "fewer events than expected" — which is easily mistaken for "the system isn't busy."
   Always test on multi-core with `taskset`.

3. **fentry context is not kprobe context.** The `ctx` parameter in fentry programs is the
   function argument array, not `struct pt_regs *`. Use `BPF_PROG` to unpack arguments
   correctly. `PT_REGS_PARM1(ctx)` on fentry will silently read the wrong memory.

4. **`_CORE_SYSCALL` macros exist for a reason.** They use `bpf_probe_read_kernel` to
   access `pt_regs` fields safely across kernel versions. Direct struct field access
   (`regs->di`) may fail CO-RE relocation.

5. **`bpftool link show` is the ground truth.** After attaching, verify the attachment type
   and target. `prog_type tracing` + `attach_type trace_fentry` confirms a trampoline link.
   `perf_event` confirms the old (potentially per-CPU-broken) path.

## 9. Files Changed

| File | Change |
|------|--------|
| `kern/execve.bpf.c:72-98` | fentry SEC macros, BPF_PROG, PT_REGS_*_CORE_SYSCALL |
| `daemon/main.go:87-111` | `link.AttachTracing` replacing `link.Tracepoint` |
| `daemon/main.go:139` | shutdown channel in server struct |
| `daemon/main.go:163-167` | close shutdown channel before GracefulStop |
| `daemon/server.go:19` | shutdown channel field |
| `daemon/server.go:52-53` | StreamEvents select on shutdown |
| `cli/main.go:49-56` | codes.Unavailable handling |
| `api/proto/integrity.proto` | StatusResponse fields 9-11 |
