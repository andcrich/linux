#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright 2026 Isovalent, Inc.
"""Resolve exact ELF file offsets for the installed JDK lifecycle entry hooks."""
import struct
import subprocess
from pathlib import Path
lib=Path('/usr/lib/jvm/java-25-openjdk-amd64/lib/server/libjvm.so')
data=lib.read_bytes()
assert data[:6]==b'\x7fELF\x02\x01'
phoff=struct.unpack_from('<Q',data,32)[0]
phsize,phnum=struct.unpack_from('<HH',data,54)
segments=[struct.unpack_from('<IIQQQQQQ',data,phoff+i*phsize) for i in range(phnum)]
rows=[]
for line in subprocess.check_output(['nm','--defined-only',str(lib)],text=True).splitlines():
    bits=line.split()
    if len(bits)==3 and bits[1] in ('t','T'): rows.append((int(bits[0],16),bits[2]))
names=subprocess.check_output(['c++filt'],input=''.join(sym+'\n' for _,sym in rows),text=True).splitlines()
prefixes=['Method::set_code(', 'InstanceKlass::add_osr_nmethod(', 'nmethod::make_not_entrant(', 'nmethod::unlink()', 'CodeCache::free(CodeBlob*)']
lines=['/* SPDX-License-Identifier: GPL-2.0-only */','/* Copyright 2026 Isovalent, Inc. */','static const unsigned long lifecycle_offsets[] = {']
for prefix in prefixes:
    matches=[(addr,name) for (addr,_),name in zip(rows,names) if name.startswith(prefix) and '[clone' not in name]
    assert len(matches)==1,(prefix,matches)
    address,name=matches[0]
    segment=next(p for p in segments if p[0]==1 and p[3]<=address<p[3]+p[5])
    offset=segment[2]+address-segment[3]
    lines.append(f'    0x{offset:x}, /* {name} */')
lines.append('};')
Path('hotspot-symbols.h').write_text('\n'.join(lines)+'\n')
print('\n'.join(lines))
