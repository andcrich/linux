#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Copyright 2026 Isovalent, Inc.
set -euo pipefail
jdk=/usr/lib/jvm/java-25-openjdk-amd64
"$jdk/bin/javac" AprobeHotSpot.java
gcc -shared -fPIC -O2 -Wall -Wextra -Werror -I"$jdk/include" -I"$jdk/include/linux" hotspot-agent.c -o libaprobe-hotspot.so
mkdir -p initramfs/etc
if [[ ! -d initramfs/jdk ]]; then cp -a "$jdk" initramfs/jdk; fi
cp -a /etc/java-25-openjdk initramfs/etc/
cp AprobeHotSpot.class libaprobe-hotspot.so initramfs/
while IFS= read -r dependency; do
  if [[ $dependency == /* && $dependency != "$jdk"/* && -f $dependency ]]; then
    cp -L --parents "$dependency" initramfs/
  fi
done < <(find "$jdk/lib" -name '*.so' -print0 | xargs -0 -r lddtree -l; lddtree -l "$jdk/bin/java")
"$jdk/bin/java" -version > jdk-version.txt 2>&1
