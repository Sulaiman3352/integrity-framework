# Contributing

Thanks for your interest in contributing! This project welcomes contributions — bug reports,
fixes, features, documentation, and tests. This guide explains how to get set up, the
conventions to follow, and the one-time agreement step for code contributions.

---

## Before you start: the Contributor License Agreement

Code contributions require agreeing to the project's [Contributor License Agreement](./CLA.md)
(CLA). You don't need to sign or send anything in advance — when you open your first pull
request, an automated assistant will check whether you've agreed and, if not, post a link
asking you to confirm. It's a one-time, ~30-second step, and you won't be asked again for future
contributions.

Please read [`CLA.md`](./CLA.md) so you understand the terms before contributing.

---

## Getting set up

This is a Linux project built in **C** (the in-kernel eBPF probe) and **Go** (the userspace
daemon). See the **Building from Source** section of the [README](./README.md) for full
prerequisites and build steps. In brief, you'll need: a Go toolchain, Clang/LLVM, `libbpf`
development headers, `bpftool`, and a modern Linux kernel with BTF enabled.

The typical local workflow:

```bash
# one-time per machine: generate kernel type definitions
bpftool btf dump file /sys/kernel/btf/vmlinux format c > kern/vmlinux.h

# whenever the eBPF C source changes: regenerate bytecode + Go bindings
cd daemon && go generate ./...

# build and run (eBPF requires privileges)
go build -o integrity-daemon . && sudo ./integrity-daemon
```

---

## Project layout and licensing

Most of the repository is licensed under **AGPL-3.0** (see [`LICENSE`](./LICENSE)), but two
directories carry their own licenses for technical reasons. Please keep this in mind when
adding files:

- **`kern/`** — the eBPF kernel programs — is **GPL** (eBPF programs that run in the kernel must
  declare a GPL-compatible license). New `.bpf.c` files here must carry the appropriate SPDX
  header. See [`kern/README.md`](./kern/README.md).
- **`api/proto/`** — the gRPC API definitions — is **Apache-2.0**, so that clients of any kind
  can be built against the API freely. New `.proto` files here carry the Apache-2.0 SPDX header.
  See [`api/proto/README.md`](./api/proto/README.md).
- **Everything else** (`daemon/`, `cli/`, etc.) — **AGPL-3.0**.

When you add a new source file, include the matching SPDX license header for its directory.

---

## Code style

### Go

- **Format with `gofmt`** before committing. Run `gofmt -w .` (or configure your editor to run
  it on save). CI and reviewers expect `gofmt`-clean code — this is non-negotiable in Go and
  keeps the codebase consistent.
- Prefer clear, explicit error handling (`if err != nil { ... }`). Don't ignore errors silently.
- Keep functions focused and readable; favor clarity over cleverness.
- Run `go vet ./...` to catch common mistakes before submitting.

### C (eBPF)

- eBPF programs run in the kernel under the verifier — keep them simple and bounded.
- Use kernel integer types (`__u8`, `__u32`, `__u64`) for data stored in shared structures.
- Never block in the kernel; handle the "buffer full" / failure paths gracefully (e.g. drop
  rather than wait).
- If you change any `*.bpf.c`, **regenerate** with `go generate ./...` and commit the result if
  the project commits generated bindings (check existing practice in the repo).
- Be careful with memory from the kernel — initialize/zero buffers you don't fully populate, and
  read userspace memory only via the safe helpers.

### General

- Keep the kernel↔userspace data structures in sync — the C event struct and the generated Go
  struct must match field-for-field.
- Match the surrounding code's conventions.

---

## Submitting changes

1. **Open an issue first** for anything non-trivial — it's worth discussing the approach before
   you invest time, so your work aligns with the project's direction.
2. **Fork** the repository and create a branch for your change.
3. Make your change, keeping commits focused and with clear messages.
4. **Build and test locally** — make sure the daemon builds and runs, and that your change
   behaves as intended.
5. Run `gofmt -w .` and `go vet ./...`.
6. **Open a pull request** with a clear description of what the change does and why. Reference
   any related issue.
7. The CLA assistant will ask you to agree to the [CLA](./CLA.md) if you haven't already.
8. A maintainer will review. Please be responsive to feedback — review is a normal, collaborative
   part of the process.

---

## Reporting bugs and security issues

- **Bugs:** open an issue with steps to reproduce, what you expected, what happened, your distro
  and kernel version (`uname -r`), and any relevant log output.
- **Security vulnerabilities:** please do **not** open a public issue. See [`SECURITY.md`](./SECURITY.md)
  for how to report security concerns privately.

---

## Conduct

Please be respectful and constructive in all project spaces. We want this to be a welcoming
place to collaborate. See [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) if present.

---

*Thank you for helping improve this project. Every contribution — code, docs, tests, or a
well-written bug report — is genuinely appreciated.*
