# `api/proto/` — The API Contract (Apache-2.0)

This directory contains the **Protocol Buffer definitions** that form the public API contract
of the Integrity Framework: the schema describing how clients (CLI, GUI, and third-party
tools) communicate with the daemon over gRPC.

---

## ⚠️ Licensing — This Directory Is Apache-2.0, Not AGPL

> **The files in this directory are licensed under the Apache License 2.0 (Apache-2.0),
> which is DIFFERENT from the repository's top-level AGPL-3.0 license.**
> 
> See `api/proto/LICENSE` for the full Apache-2.0 text that governs this directory. The
> repository-wide `LICENSE` (AGPL-3.0) governs everything *except* the directories that carry
> their own license file and headers (this one, and `kern/` which is GPL).

### Why this directory is permissive (the reasoning)

This `.proto` file is an **interface contract**, not an implementation. The framework's value
lives in the *daemon's implementation* (AGPL-3.0), **not** in the schema that describes how to
call it. Licensing the interface permissively therefore costs nothing and brings real benefits:

1. **Anyone can build a client — open OR closed source.** Generated gRPC stubs inherit the
   license of the `.proto` they come from. A permissive `.proto` means every client author —
   hobbyist, startup, or company — can build against this API with no legal friction. This
   maximizes adoption of the ecosystem.
2. **No legal-department friction.** A permissive API never triggers the "will this obligate
   our code?" review that blocks integrations before they begin.
3. **The patent grant.** Apache-2.0 (unlike MIT/BSD) includes an explicit patent grant,
   assuring implementers that the project will not later assert patents against
   implementations of this protocol — important for an API meant to be widely adopted.

### Scope: this API describes the daemon's public interface

> **This API is the stable public contract for talking to the open daemon.**

The schema here defines how clients interact with the daemon — status, event streaming,
whitelist management, and statistics. Any component, in any language, communicates with the
daemon **solely through this API**. Keeping the interface permissive while the daemon
implementation remains AGPL-3.0 is what lets the contract be freely adopted while the
implementation stays under copyleft.

---

## Per-File Header

Every `.proto` file in this directory carries an SPDX identifier at the top declaring
Apache-2.0. Example:

```protobuf
// SPDX-License-Identifier: Apache-2.0
//
// integrity.proto — public gRPC API contract for the Integrity Framework.
//
// NOTE: This file is licensed Apache-2.0, which DIFFERS from the
// repository's top-level AGPL-3.0 license. See api/proto/LICENSE and
// api/proto/README.md for the rationale (this is the public API contract;
// it is intentionally permissive so any client may be built against it).
//
// Copyright (C) 2026 Sulayman Seid Ymam

syntax = "proto3";

package integrity.v1;

// ... message and service definitions ...
```

The SPDX header is what lets tooling (and GitHub's license detection) correctly identify these
files as Apache-2.0 despite the repository default being AGPL-3.0.

---

## API Versioning Policy (Read Before Changing the Schema)

Because this `.proto` is a **public, permissively-licensed contract**, third parties will build
clients against it. That makes the schema something the project has *published and that others
depend on* — so breaking it has a real external cost.

**Rules for evolving the schema:**

1. **Version in the package name.** The package is `integrity.v1`. A future incompatible
   redesign would become `integrity.v2`, served alongside `v1` during a deprecation window —
   never an in-place breaking change to `v1`.
2. **Add, don't remove or repurpose.** Protocol Buffers' field-numbering makes adding new
   fields backward-compatible. Never reuse or renumber an existing field tag; never change a
   field's type. Mark obsolete fields `reserved` rather than deleting them.
3. **Treat breaking changes as expensive.** A breaking change to a published API breaks
   third-party clients. Prefer additive evolution; reserve breaking changes for a deliberate,
   announced major-version bump.
4. **Document changes.** Note schema changes in this directory's changelog / the project
   release notes so client authors can track them.

This versioning discipline protects the ecosystem the permissive license is designed to invite.

---

## Contents of This Directory

| File              | Purpose                                                                                                          |
| ----------------- | ---------------------------------------------------------------------------------------------------------------- |
| `LICENSE`         | Apache-2.0 full text governing this directory.                                                                   |
| `integrity.proto` | The gRPC API: `ExecEvent`, `Verdict`, `IntegrityService` (status, event streaming, whitelist management, stats). |
| `README.md`       | This file.                                                                                                       |

> Additional `.proto` files may be added as the API grows. Each must carry the Apache-2.0 SPDX
> header shown above.

---

## How Generated Stubs Are Licensed

Generated gRPC client/server stubs (e.g. `daemon/pkg/pb/`, the GUI's Python client, third-party
clients) are generated **from this Apache-2.0 schema**, so the generated code is **Apache-2.0**.
This is intentional and is what allows clients of any kind to be built freely. Note that the *daemon's own implementation* that uses those stubs remains AGPL-3.0 — the stubs are permissive,
but the logic wrapping them in the daemon is copyleft.

---

## Cross-References

- **The kernel directory's separate (GPL) license, for comparison:** `kern/README.md`.

---

*The decision to license this directory Apache-2.0 (vs. AGPL or MIT/BSD) is recorded as a
deliberate choice to maximize ecosystem adoption. This README documents the
decision and reasoning; it is not legal advice.*
