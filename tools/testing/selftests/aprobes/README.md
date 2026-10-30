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
A second BPF lifecycle test exercises recompilation, invalidation and unloading with both G1 and ZGC.

The recorded baseline passed all 17 checks under nested KVM on x86-64,
using Linux base d89e1d186ec9271bf78e62771779e9fc03bf0fc3 and Ubuntu
OpenJDK 25.0.4.1+1-1. The fixture agent supplies metadata and test barriers;
the breakpoint itself is in compiled Java code, not in the native agent.

On an Ubuntu x86-64 machine with nested virtualization and `/dev/kvm`:

```sh
sudo apt-get install build-essential flex bison bc libelf-dev libssl-dev \
  cpio qemu-system-x86 busybox-static pax-utils openjdk-25-jdk-headless \
  clang libbpf-dev dwarves
mkdir -p ../build
cp tools/testing/selftests/aprobes/kernel.config ../build/.config
make O=../build olddefconfig
make O=../build -j"$(nproc)" bzImage
KERNEL_BUILD="$PWD/../build" bash tools/testing/selftests/aprobes/run-guest.sh
```

The runner requires KVM, builds an initramfs and boots the patched guest
without changing the host kernel. It uses sudo for QEMU and the console
device node. Inspect `guest.log`; a pass requires all checks and no kernel
BUG/WARNING/Oops/KASAN messages. Build/configuration and JDK paths are
prototype conveniences, not a portable kselftest integration.

Known gaps include arbitrary instruction-patch coverage, fault injection,
full concurrency review, resource accounting and scalable per-mm indexing.
Retained BPF links keep metadata references after target exit; they do not
hold the target mappings alive. The branch is for review and experimentation.

## BPF lifecycle control

`BPF_F_UPROBE_MULTI_APROBE_FACTORY` enables a native multi-uprobe link to
own up to 256 dynamic anonymous-address probes. The parent requires an
explicit TGID, ptrace authorization and a sleepable entry-only BPF program.
It retains a fixed mm identity across task lifetime; it does not follow exec.
The sleepable kfuncs `bpf_aprobe_attach(address, cookie)` and
`bpf_aprobe_detach(address, length)` operate on that parent's child probes in
the current mm. A child invokes the parent's BPF program with its own cookie.
Calling the control kfuncs from a child hit is rejected, preventing recursive
control of the currently executing anonymous probe.

Removal restores bytes and retires the address descriptor before returning
to the JVM. Consumers and saved instruction versions are reclaimed later.
There is no RCU grace-period wait inside the controlling BPF callback,
including registration-error cleanup. A new generation receives a new
instruction snapshot rather than modifying the snapshot of an in-flight trap.
Closing the parent unregisters the native hooks and all remaining children.

`hotspot.bpf.c` watches these native HotSpot entry points:

| Entry hook | BPF action |
| --- | --- |
| `Method::set_code` | Select a method and attach before normal publication |
| `InstanceKlass::add_osr_nmethod` | Select and attach before OSR publication |
| `nmethod::make_not_entrant` | Remove before invalidation/entry rewriting |
| `nmethod::unlink` | Retire tracing state at unlink |
| `CodeCache::free` | Remove any remaining probe before allocation reuse |

The selector reads the nmethod's Method, ConstMethod, ConstantPool and
class/name Symbols. It currently matches `AprobeLifecycle$Payload::target`
across all class loaders, not a particular loader identity. Native hooks
observe the selected JVM's publication/retirement operations, while dynamic
aprobes are installed only for matching methods. This is a test program,
not a Tetragon policy or all-classes mode. Removing the selector alone does
not solve the current resource/scalability limits.

BPF tracks live nmethod pointers and history keyed by compile ID, carried in
attach cookies. This distinguishes reused code addresses across compilations;
the kernel has no Java-specific generation identity. Compile-ID wraparound is
not handled in this prototype. Exact metadata offsets come from the installed
JDK's exported VMStructs/VMTypes, and native file offsets from its ELF symbols
and load segments. The startup agent only gates test start, with no JVMTI
compiled-method tracking or userspace attach/detach loop.

## Lifecycle validation

Linux build #6, BTF enabled, nested KVM, unmodified Ubuntu OpenJDK
25.0.4.1+1-1. Both collector runs completed with:

- 24 class loaders collected and correct Add/Mul results throughout;
- 72 compilations: 24 C1 and 48 C2, with 575208 traced entry hits;
- 72 invalidations, 72 unlinks, 72 frees and 72 probe removals;
- empty live-generation map, zero errors, read failures or stale-generation hits;
- actual nmethod address reuse: 9 generations in G1 and 12 in ZGC;
- callback-side failed registration returning EINVAL without deadlock.

The workload changes virtual dispatch from Add to Mul to trigger speculative
invalidation/recompilation, then drops each loader and explicitly collects.
It does not exercise OSR publication despite installing the OSR hook, and does
not establish complete coverage for inline/direct patch sites, all collectors,
JVMCI, arbitrary JDK versions or Java return probes. Tracing starts at compiled
method publication; interpreted invocations before compilation are not counted.

A BPF hook cannot force HotSpot to abort a mutation if disarming fails. The
program records control/read errors and the test rejects them; production
failure handling still requires a protocol with the runtime. This branch
therefore demonstrates the mechanism and tested paths, not universal safe
instrumentation of mutable JIT instructions. Existing file uprobes and all
17 native/stable-C2 baseline checks also passed on this kernel.

Raw checkpatch reports two path-based RCU_TASKS_TRACE warnings in BPF tracing
code (`kernel/trace/bpf_trace.c`); trace-RCU reclamation is intentional for
sleepable uprobes. The core patch has zero other errors/warnings when that
message class is excluded. This does not substitute for a full concurrency
review or upstream acceptance.
