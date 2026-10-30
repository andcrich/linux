<!-- SPDX-License-Identifier: GPL-2.0-only -->
<!-- Copyright 2026 Isovalent, Inc. -->
# Anonymous-address probes prototype

This is experimental, AI-assisted code, developed with Codex from a request
to investigate BPF probes in anonymous HotSpot JIT memory. It is not an
upstream proposal or a stable ABI. No human DCO certification is implied.

The kernel uses the existing uprobes instruction engine with a per-address
`mm_struct` key. `BPF_F_UPROBE_MULTI_APROBE` selects virtual addresses in the
multi-uprobe API. A TGID and ptrace authorization are required. Entry probes
on private anonymous executable memory, including RWX, are supported.
Return/session probes and shared mappings are rejected. Mapping identity
does not establish JIT compilation identity. The caller must coordinate
all instruction mutation while probes are armed.

The native fixture checks instruction semantics, multiple consumers, fork,
exec/exit, mapping reuse, mremap, protection changes, permission enforcement,
failed multi-address registration, concurrent detach and ordinary uprobes.
The HotSpot fixture checks an actual C2 method in anonymous RWX memory:
10,000 calls, exactly 10,000 BPF hits, correct results and restored bytes.
That coordinated fixture does not exercise live recompilation or unloading.

The recorded baseline passed all 17 checks under nested KVM on x86-64,
using Linux base d89e1d186ec9271bf78e62771779e9fc03bf0fc3 and Ubuntu
OpenJDK 25.0.4.1+1-1. The fixture agent supplies metadata and test barriers;
the breakpoint itself is in compiled Java code, not in the native agent.

On an Ubuntu x86-64 machine with nested virtualization and `/dev/kvm`:

```sh
sudo apt-get install build-essential flex bison bc libelf-dev libssl-dev \
  cpio qemu-system-x86 busybox-static pax-utils openjdk-25-jdk-headless
mkdir -p ../build
cp tools/testing/selftests/aprobes/kernel.config ../build/.config
make O=../build olddefconfig
make O=../build -j8 bzImage
KERNEL_BUILD="$PWD/../build" bash tools/testing/selftests/aprobes/run-guest.sh
```

The runner requires KVM, builds an initramfs and boots the patched guest
without changing the host kernel. It uses sudo for QEMU and the console
device node. Inspect `guest.log`; a pass requires all checks and no kernel
BUG/WARNING/Oops/KASAN messages. Build/configuration and JDK paths are
prototype conveniences, not a portable kselftest integration.

Known gaps include automatic mutation coordination, fault injection, full
concurrency review, resource accounting and scalable per-mm indexing.
Retained BPF links keep metadata references after target exit; they do not
hold the target mappings alive. The branch is for review and experimentation.
