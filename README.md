## License

<ProjectName> is **free and open source software**, licensed under the
**GNU Affero General Public License v3.0 (AGPL-3.0)** — see [`LICENSE`](./LICENSE).
You are free to use, run, study, modify, and redistribute it under the terms of that license.

Two sub-directories carry their own licenses for technical reasons:

- [`kern/`](./kern/) — the eBPF kernel programs — is licensed **GPL** (required for eBPF code
  that runs in the Linux kernel). See [`kern/README.md`](./kern/README.md).
- [`api/proto/`](./api/proto/) — the gRPC API definitions — is licensed **Apache-2.0**, so that
  anyone can freely build clients against the API. See [`api/proto/README.md`](./api/proto/README.md).
- 

## Building from Source

> **Platform:** Linux only (the daemon uses eBPF and runs in the kernel). Tested on
> Fedora 43, kernel 7.0.6, x86-64. Should work on any modern Linux with a recent kernel
> (5.8+ for ring buffer support) and BTF enabled.

### 1. Prerequisites

You need a Go toolchain, the LLVM/Clang compiler (eBPF programs are compiled with Clang),
and the eBPF/BTF tooling.

**Fedora / RHEL:**

```bash
sudo dnf install golang clang llvm libbpf-devel bpftool kernel-devel
```

**Debian / Ubuntu:**

```bash
sudo apt install golang clang llvm libbpf-dev linux-tools-common linux-tools-$(uname -r)
```

**Arch:**

```bash
sudo pacman -S go clang llvm libbpf bpf
```

Your kernel must have **BTF enabled** (it almost certainly is on any modern distro). Verify:

```bash
ls /sys/kernel/btf/vmlinux        # this file must exist
```

If it exists, you're good. (It is enabled by `CONFIG_DEBUG_INFO_BTF=y` in the kernel config.)

### 2. Generate `vmlinux.h` (kernel type definitions)

The eBPF probe needs `kern/vmlinux.h` — a header containing your kernel's type definitions,
generated from the kernel's own BTF. This file is **machine-specific and not committed** to
the repository (it is in `.gitignore`), so you generate it once locally:

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > kern/vmlinux.h
```

This reads your running kernel's BTF and writes the C type declarations the probe compiles
against. Regenerate it only if you change kernels.

> If `bpftool` is missing, install it (see prerequisites). The generated file is large
> (100,000+ lines) — that's normal; it describes every type in your kernel.

### 3. Generate the eBPF objects and Go bindings (`go generate`)

This step compiles the eBPF C source (`kern/execve.bpf.c`) into BPF bytecode **and**
auto-generates the matching Go bindings (the `bpfObjects`, `bpfEvent` struct, etc.) using
`bpf2go`. The directive lives in `daemon/gen.go`.

```bash
cd daemon
go generate ./...
```

This produces (in `daemon/`): `bpf_x86_bpfel.go` / `.o` (little-endian) and the big-endian
counterparts. You may see harmless warnings from the generated `vmlinux.h` (e.g.
"declaration does not declare anything") — these come from the kernel header dump, not from
the probe, and can be ignored.

> **Note:** `go generate` does not run automatically during a normal build — you must run it
> explicitly whenever you change the eBPF C source (`*.bpf.c`).

### 4. Build the daemon

From the `daemon/` directory:

```bash
go build -o integrity-daemon .
```

This compiles the Go daemon (which embeds the BPF bytecode generated in step 3) into a single
`integrity-daemon` binary.

### 5. Run it

Loading eBPF programs into the kernel and attaching to tracepoints requires elevated
privileges, so run the daemon with `sudo`:

```bash
sudo ./integrity-daemon
```

The daemon attaches to the `execve` syscall and prints every program execution on the system.
To see it working, open a **second terminal** and run any command (`ls`, `cat`, etc.) — the
daemon's terminal will show the corresponding events:

```
PID=12345 UID=1000 COMM=bash FILENAME=/usr/bin/ls
PID=12346 UID=1000 COMM=bash FILENAME=/usr/bin/cat
```

Press `Ctrl-C` to stop the daemon (it shuts down cleanly).

### Quick reference (after prerequisites are installed)

```bash
# one-time, per machine / per kernel:
bpftool btf dump file /sys/kernel/btf/vmlinux format c > kern/vmlinux.h

# whenever the eBPF C source changes:
cd daemon && go generate ./...

# build and run:
go build -o integrity-daemon . && sudo ./integrity-daemon
```

### Troubleshooting

| Symptom                                            | Likely cause / fix                                                                  |
| -------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `bpftool: command not found`                       | Install it (see prerequisites).                                                     |
| `/sys/kernel/btf/vmlinux: No such file`            | Kernel lacks BTF; uncommon on modern distros.                                       |
| `go generate` fails: clang errors                  | `clang` / `libbpf-devel` not installed, or `kern/vmlinux.h` not generated (step 2). |
| `undefined: bpfEvent` when building                | The `gen.go` directive needs `-type event`; re-run `go generate`.                   |
| Build OK, but `operation not permitted` at runtime | Run with `sudo` (eBPF load/attach needs privileges).                                |

## Contributions are welcome. Before submitting a contribution, please read:

- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — how to set up, build, test, and submit changes.
- [`CLA.md`](./CLA.md) — the **Contributor License Agreement**, which all contributors are
  asked to agree to before their contributions can be merged. Please read it in full so you
  understand the terms before contributing.
  If you have questions about contributing, open an issue or reach out at <contact>.
