#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright 2026 Isovalent, Inc.
set -euo pipefail
test_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$test_dir"
kernel_src=${KERNEL_SRC:-$(git rev-parse --show-toplevel)}
kernel_build=${KERNEL_BUILD:-$kernel_src/../build}
test -c /dev/kvm
gcc -O2 -g -Wall -Wextra -Werror -static -pthread aprobes-test.c -o aprobes-test
mkdir -p initramfs/{bin,dev,proc,sys,tmp}
cp /usr/bin/busybox-static initramfs/bin/busybox
ln -sf busybox initramfs/bin/sh
cp aprobes-test initramfs/aprobes-test
cp guest-init initramfs/init
chmod +x initramfs/init
bash initramfs-jdk.sh
test -c initramfs/dev/console || sudo mknod initramfs/dev/console c 5 1
(cd initramfs; find . -print0 | cpio --null -o --format=newc 2>/dev/null | gzip -1) > initramfs.cpio.gz
sudo timeout 240 qemu-system-x86_64 -machine q35,accel=kvm -cpu host -smp 4 -m 3072 \
  -display none -serial stdio -monitor none -no-reboot -pidfile qemu.pid \
  -kernel "$kernel_build/arch/x86/boot/bzImage" -initrd initramfs.cpio.gz \
  -append 'console=ttyS0 rdinit=/init panic=1 oops=panic' > guest.log 2>&1
grep APROBES_TEST_PASS guest.log
grep HOTSPOT_LIFECYCLE_PASS guest.log
grep 'APROBES_GUEST_TEST_EXIT=0' guest.log
if grep -Eq 'BUG:|WARNING:|Oops:|kernel BUG|KASAN:' guest.log; then
  echo 'Kernel diagnostic detected' >&2
  exit 1
fi
printf 'KVM guest test passed\n'
