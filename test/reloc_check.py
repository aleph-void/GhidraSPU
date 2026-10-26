#!/usr/bin/env python3
"""Check Ghidra's application of SPU ELF relocations in a relocatable object: link the object
with GNU ld, placing every section at the address Ghidra gave it and every undefined symbol
at Ghidra's EXTERNAL address, then compare each relocated word with Ghidra's memory.
  reloc_check.py <object.o> <dump-prefix from DumpBlocks.java> <workdir>
Environment: SPU_LD, SPU_READELF, SPU_OBJCOPY (default spu-elf-*)."""
import os
import re
import subprocess
import sys
from collections import Counter

obj, pre, work = sys.argv[1:4]
tool = lambda n: os.environ.get('SPU_' + n.upper(), 'spu-elf-' + n)
blocks, ext, gsym = {}, {}, {}
for line in open(pre + '.map'):
    p = line.split()
    if p[0] == 'extern':
        ext[p[1]] = int(p[2], 16)
    elif p[0] == 'sym':
        gsym[p[1]] = int(p[2], 16)
    else:
        blocks[p[0]] = (int(p[1], 16), int(p[2]))
os.makedirs(work, exist_ok=True)
secs = [s for s in blocks if s.startswith('.')]
lds = ['SECTIONS {'] + ['  %s 0x%x : { *(%s) }' % (s, blocks[s][0], s) for s in secs] + \
      ['  /DISCARD/ : { *(.comment) *(.note.*) }', '}']
open(os.path.join(work, 'place.ld'), 'w').write('\n'.join(lds) + '\n')
undef, common = set(), set()
for line in subprocess.check_output([tool('readelf'), '-sW', obj], text=True).splitlines():
    p = line.split()
    if len(p) >= 8 and p[6] == 'UND' and p[7:]:
        undef.add(p[7])
    if len(p) >= 8 and p[6] == 'COM':
        common.add(p[7])
defs = []
for n in sorted(undef):
    if n in ext:
        defs += ['--defsym', '%s=0x%x' % (n, ext[n])]
# COMMON symbols: put them where Ghidra allocated them (its EXTERNAL block)
for n in sorted(common):
    if n in gsym or n in ext:
        defs += ['--defsym', '%s=0x%x' % (n, gsym.get(n, ext.get(n)))]
# Ghidra keeps mergeable sections (SHF_MERGE constants and strings) as they are in the object;
# clear the flag in a copy so ld does not merge duplicates and move their offsets.
flagged = []
for line in subprocess.check_output([tool('readelf'), '-SW', obj], text=True).splitlines():
    m = re.match(r'\s*\[\s*\d+\]\s+(\S+)\s+PROGBITS\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)', line)
    if m and 'M' in m.group(2):
        flagged += ['--set-section-flags', '%s=alloc,load,readonly,data' % m.group(1)]
plain = os.path.join(work, 'nomerge.o')
subprocess.check_call([tool('objcopy')] + flagged + [obj, plain])
obj = plain
elf = os.path.join(work, 'linked.elf')
# second link leaves undefined symbols undefined: ld rewrites R_SPU_ADD_PIC sites only then
elf_undef = os.path.join(work, 'linked-undef.elf')
for out, extra in ((elf, defs), (elf_undef, [])):
    subprocess.check_call([tool('ld'), '-o', out, '-T', os.path.join(work, 'place.ld'), '-e', '0',
                           '--no-check-sections', '--unresolved-symbols=ignore-all',
                           '--no-warn-rwx-segments', '--noinhibit-exec'] + extra + [obj],
                          stderr=subprocess.DEVNULL)
# relocation sites: section-relative offsets from readelf -r
sites = []
cur = None
for line in subprocess.check_output([tool('readelf'), '-rW', obj], text=True).splitlines():
    m = re.match(r"Relocation section '\.rela(\S+)'", line)
    if m:
        cur = m.group(1)
        continue
    p = line.split()
    if cur and len(p) >= 3 and re.fullmatch(r'[0-9a-f]{8}', p[0]) and p[2].startswith('R_SPU'):
        sym = p[4] if len(p) > 4 else ''
        sites.append((cur, int(p[0], 16), p[2], sym))
res = Counter()
cache = {}
for sec, off, typ, sym in sites:
    if sec not in blocks:
        res['section not loaded by Ghidra'] += 1
        continue
    if sym in undef and sym not in ext and typ != 'R_SPU_ADD_PIC':
        res['undefined symbol without a Ghidra address'] += 1
        continue
    if sec not in cache:
        out = os.path.join(work, 'sec.bin')
        got = []
        for e in (elf, elf_undef):
            subprocess.check_call([tool('objcopy'), '-O', 'binary', '-j', sec, e, out])
            got.append(open(out, 'rb').read())
        cache[sec] = (open('%s.%s.bin' % (pre, sec), 'rb').read(), got[0], got[1])
    n = 8 if typ == 'R_SPU_PPU64' else 4
    ref = cache[sec][2] if typ == 'R_SPU_ADD_PIC' else cache[sec][1]
    gb, lb = cache[sec][0][off:off + n], ref[off:off + n]
    if gb == lb:
        res['%s agree' % typ] += 1
    else:
        res['%s DIFFER' % typ] += 1
        if res['%s DIFFER' % typ] <= 3:
            print('  differ %s+%#x %s %s: ghidra %s ld %s' % (sec, off, typ, sym, gb.hex(), lb.hex()))
tot = sum(v for k, v in res.items() if k.endswith('agree') or k.endswith('DIFFER'))
ok = sum(v for k, v in res.items() if k.endswith('agree'))
print('relocations checked %d: %d agree with GNU ld, %d differ' % (tot, ok, tot - ok))
for k, v in sorted(res.items()):
    if v:
        print('  %6d %s' % (v, k))
sys.exit(0 if ok == tot else 1)
