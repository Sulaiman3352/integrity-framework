# `kern/` — Kernel eBPF Probes

This directory contains the **kernel-space components** of the Integrity Framework: the eBPF
programs (written in C, compiled to eBPF bytecode) that attach to kernel syscalls and the BPF
LSM hook to observe and enforce execution policy.

These programs run **inside the Linux kernel** after passing the kernel's eBPF verifier. They
communicate with the userspace daemon (`../daemon/`) over an arms-length boundary — eBPF maps
and a ring buffer — and never share an address space or binary with userspace code.

---

## ⚠️ Licensing — Read Before Modifying

> **The code in this directory is licensed differently from the rest of the repository.**
>
> The repository as a whole is licensed under **AGPL-3.0** (see the top-level `LICENSE`). The
> files in this `kern/` directory are licensed under the **GNU General Public License v2.0 or
> later (GPL-2.0-or-later)** and additionally carry the in-code `SEC("license") = "GPL"`
> declaration required by the kernel.
>
> AGPL-3.0 and GPL are part of the same license family and are explicitly designed to be
> compatible, so both licenses coexisting in this single repository is intentional and not a
> conflict.

### Why a GPL declaration is required here (the technical reason)

Every eBPF program declares a license to the kernel via a special section:

```c
char LICENSE[] SEC("license") = "GPL";
```

The kernel's eBPF verifier reads this string **at program load time**. Many kernel helper
functions are marked **GPL-only** — the verifier will refuse to load an eBPF program that
calls them unless the program declares a **GPL-compatible** license. The probes in this
directory rely on such helpers (for example, helpers used to read process and file context,
and to interact with maps and the ring buffer). Therefore the `SEC("license")` declaration
**must** be GPL-compatible, or the probes will fail to load.

This is a **runtime gate enforced by the kernel**, not merely a copyright preference. It is the
kernel saying: *"you may only call my GPL-only helpers if you are also GPL."*

### What is and isn't fixed (the honest nuance)

- **Fixed (technical):** the in-code `SEC("license")` string must be **GPL-compatible** to use
  GPL-only kernel helpers. This is not optional if those helpers are used.
- **Has some flexibility (legal):** "GPL-compatible" is a *category*, not a single license. It
  includes GPL-2.0 and GPL-3.0, and also some permissive licenses (e.g. BSD, MIT). A common
  idiom in the eBPF ecosystem is to **dual-license probe source as "GPL OR BSD"** — the file
  carries a permissive copyright license while still presenting a GPL-compatible declaration to
  the kernel.
- **The precise copyright license chosen for these files is a decision with legal
  implications** (it interacts with what can and cannot be kept proprietary elsewhere) and is
  **pending legal review** — see the project's `licensing_strategy.md`. This project currently
  defaults these files to **GPL-2.0-or-later** as the simplest, safest choice that satisfies the
  kernel requirement, subject to that review.

### Does this "infect" the rest of the repository?

No — and the architecture is deliberately designed so this question stays clean:

- The kernel probes here and the userspace daemon in `../daemon/` are **separate programs** that
  communicate over a **defined arms-length boundary** (eBPF maps / ring buffer). They are not
  linked into a single binary.
- The rest of the open repository is already strong copyleft (**AGPL-3.0**), so there is nothing
  here that anyone is trying to keep proprietary. There is no "infection" concern *within* the
  open repo.
- The place GPL/AGPL "linking" actually matters is the **separate proprietary repository**
  (`integrity-enterprise`). That code must never link GPL/AGPL code into one binary — and it
  does not: it communicates with the open daemon **only over the public gRPC API** (an
  arms-length boundary). That API seam is, by design, both an engineering interface and a
  **licensing firewall**.

> **One-line summary:** these files are **GPL** (to satisfy the kernel's GPL-only helper
> requirement); they sit happily in this AGPL repository because AGPL and GPL are compatible;
> and the proprietary product stays clean because it only ever talks to userspace over the
> gRPC API, never by linking this code.

---

## Per-File License Header

Every C source file in this directory should carry an SPDX identifier at the top, in addition
to the in-code kernel license declaration. Example header:

```c
// SPDX-License-Identifier: GPL-2.0-or-later
//
// <filename>.bpf.c — <short description>
//
// Part of the Integrity Framework kernel data plane.
// Copyright (C) 2026 Sulayman Seid Ymam
//
// This file is licensed GPL-2.0-or-later. NOTE: this differs from the
// repository's top-level AGPL-3.0 license. See kern/README.md for the
// rationale (eBPF GPL-only helper requirement). AGPL-3.0 and GPL are
// compatible and intentionally coexist in this repository.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/* ... program code ... */

char LICENSE[] SEC("license") = "GPL";
```

Two distinct things appear here and must **both** be present:
1. **`SPDX-License-Identifier: GPL-2.0-or-later`** — the *copyright* license of the source file
   (for humans, tooling, and GitHub's license detection).
2. **`char LICENSE[] SEC("license") = "GPL";`** — the *kernel runtime* declaration the eBPF
   verifier checks at load time. Without this, GPL-only helpers are unavailable.

---

## Contents of This Directory

| File | Phase | Purpose |
|------|-------|---------|
| `execve_probe.bpf.c` | 1 | Hooks `sys_enter_execve` / `sys_enter_execveat`; emits execution events. |
| `file_probe.bpf.c` | 2 | Hooks `openat`(write), `write`, `close`, `rename`/`renameat2`, `chmod`/`fchmodat`; feeds provenance tracking. |
| `lsm_enforce.bpf.c` | 2 | BPF LSM hook; enforces allow/block verdicts from the daemon. |
| `common.bpf.h` | — | Shared map definitions and event structs used across probes. |
| `vmlinux.h` | — | Generated BTF kernel type definitions (CO-RE). Regenerate with `bpftool`; do not hand-edit. |

> Files may be added as the project progresses through its phases. Any new `.bpf.c` file must
> carry the SPDX header shown above and the in-code `SEC("license")` declaration.

---

## Building

The eBPF objects are compiled with Clang to BPF bytecode and loaded by the Go daemon via the
`cilium/ebpf` library (see `../daemon/ebpf/loader.go`). Build is orchestrated from the
top-level `Makefile`. Required tooling: `clang`, `llvm`, `libbpf-devel`, `bpftool`, and kernel
headers.

To regenerate `vmlinux.h` for your kernel:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > kern/vmlinux.h
```

---

## Cross-References

- **Why the kernel side must be C/eBPF at all:** `design_decisions_log.md`, §3.1.
- **The kernel↔userspace architecture (the arms-length boundary):** `design_decisions_log.md`, §4.
- **The overall licensing strategy and the open/proprietary split:** `licensing_strategy.md`.
- **The repository structure and per-component licenses:** `project_structure_and_licensing.md`.

---

*The GPL declaration requirement for eBPF GPL-only helpers is a technical certainty. The
precise copyright license applied to these files (GPL-2.0-or-later by default, vs. a GPL-OR-BSD
dual-license idiom) is subject to the legal review described in `licensing_strategy.md`. This
README documents the current default and the reasoning; it is not legal advice.*
