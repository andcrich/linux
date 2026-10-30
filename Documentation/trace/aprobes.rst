.. SPDX-License-Identifier: GPL-2.0-only

Anonymous address probes
========================

Anonymous address probes place entry breakpoints at virtual addresses in a
specified address space. They reuse the architecture's uprobe instruction
analysis, breakpoint handling, and displaced instruction execution. They do
not provide return probes or identify the code stored at an address.

Registration and ownership
--------------------------

``aprobe_register(mm, address, consumer)`` registers one consumer. The caller
must hold a live ``mm_users`` reference during registration. Removal uses
``uprobe_unregister_nosync()`` followed by ``uprobe_unregister_sync()`` before
freeing the consumer. Registration may sleep and synchronize callbacks on
failure; it cannot be called from an active uprobe callback.

The mapping must be private, anonymous, executable, and populated. File-backed,
shared, and hugetlb mappings are rejected. The instruction buffer must fit
within one page. Writable executable mappings are accepted, but the caller
must prevent instruction modification while a registration remains active.
A write through another interface is not automatically a code-generation
notification.

Sites are indexed by address within the target ``mm_struct``. Independent
consumers at the same site share the saved instruction and breakpoint.
Removing one consumer does not remove another consumer's breakpoint. The last
consumer removes the breakpoint. The saved instruction remains protected
through the existing uprobe lifetime and callback synchronization rules.

The address space holds at most 4096 allocated sites, including allocations
awaiting deferred reclamation. An additional site fails with ``-E2BIG``;
adding a consumer to an existing site does not consume another slot. Probe
objects and anonymous-probe BPF link allocations are memory-accounted.

Mapping changes
---------------

The registration is tied to the original mapping and address. Unmapping or
zapping a range retires affected registrations after the PTEs are removed.
Changing a range to writable or non-executable restores its instructions and
retires the registrations before changing the protections. Moving a mapping
with ``mremap()`` does the same before moving PTEs. These operations affect all
consumers at a site. They do not transfer a registration to replacement code.
A later registration reads a new instruction snapshot. Closing an older link
does not change a newer registration at a reused address.

``UFFDIO_MOVE`` returns ``-EBUSY`` if either range contains an active site.
Registration and removal acquire VMA write protection so that this check
cannot race installation while the move holds the VMA locks.

A fork restores instructions in the child's copied address space before the
child runs; it does not inherit address probes. Tasks sharing the same
``mm_struct`` encounter the same breakpoint and require correct instruction
execution even if a consumer's task filter excludes them. Address-space
teardown retires sites; an open link can retain metadata until it is closed.

BPF attachment
--------------

``BPF_LINK_CREATE`` with attach type ``BPF_TRACE_UPROBE_MULTI`` accepts
``BPF_F_UPROBE_MULTI_APROBE``. The ``offsets`` array contains absolute virtual
addresses, ``pid`` must identify a target thread group, and ``path`` and
``path_fd`` must be absent. The caller must pass the target's ptrace attach
permission check as well as the normal BPF permission checks.

Each link accepts at most 64 addresses. Cookies retain their existing
multi-uprobe meaning. Return, session, and reference-counter options are not
supported. The link retains its target address space and uses the existing
thread-group filter for callback delivery. Executing a different program or
exiting does not make the link follow a replacement address space or PID.

Tests
-----

``tools/testing/selftests/bpf/test_aprobes`` exercises the interface with small
native instruction sequences and a BPF counter program. Run it as root on an
x86-64 kernel with ``CONFIG_UPROBES`` and BPF enabled. The page-movement test
also needs ``CONFIG_USERFAULTFD`` and ``UFFD_FEATURE_MOVE``. Unsupported
architectures or unavailable features are reported as skips.
