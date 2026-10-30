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

"$jdk/bin/javac" AprobeLifecycle.java
gcc -shared -fPIC -O2 -Wall -Wextra -Werror -I"$jdk/include" -I"$jdk/include/linux" hotspot-layout.c -ldl -o libhotspot-layout.so
"$jdk/bin/java" -agentpath:"$PWD/libhotspot-layout.so"="$PWD/hotspot-layout.h" -version
python3 prepare-hotspot.py
clang -target bpf -D__TARGET_ARCH_x86 -g -O2 -Wall -Werror -I/usr/include/$(gcc -dumpmachine) -c hotspot.bpf.c -o hotspot.bpf.o
gcc -O2 -g -Wall -Wextra -Werror -static hotspot-loader.c -o hotspot-loader $(pkg-config --libs --static libbpf)
gcc -shared -fPIC -O2 -Wall -Wextra -Werror -I"$jdk/include" -I"$jdk/include/linux" lifecycle-agent.c -o libaprobe-lifecycle.so
cp AprobeLifecycle*.class hotspot.bpf.o hotspot-loader libaprobe-lifecycle.so initramfs/
