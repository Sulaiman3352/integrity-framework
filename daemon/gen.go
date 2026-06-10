// SPDX-License-Identifier: AGPL-3.0-or-later
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target native bpf ../kern/execve.bpf.c
