#!/usr/bin/env python3
"""Check the opcode table of gen_spu_sinc.py against the SPU ISA v1.2 text (tools/fetch-isa.sh):
for every mnemonic, the instruction page's syntax line is followed by the encoding row whose
leading 0/1 cells are the opcode; they must equal the table's opcode at its format width.
Usage: tools/isa_check.py <SPU_ISA_v1.2.txt>"""
import importlib.util
import os
import re
import sys

here = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location('gen', os.path.join(here, 'gen_spu_sinc.py'))
gen = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen)

lines = open(sys.argv[1]).read().split('\n')
mns = {m for m, _, _, _ in gen.OPS}
found = {}
for i, l in enumerate(lines):
    m = re.match(r'^([a-z]+)(\s{2,}\S.*)?\s*$', l)
    if not m or m.group(1) not in mns:
        continue
    for j in range(i + 1, min(i + 6, len(lines))):
        t = lines[j].split()
        if not t:
            continue
        bits = ''
        for x in t:
            if x not in ('0', '1'):
                break
            bits += x
        if len(bits) >= 4:
            found.setdefault(m.group(1), []).append(bits)
        break
bad = 0
for mn, fmt, op, _ in gen.OPS:
    w = gen.OPWIDTH[fmt]
    want = format(op >> (11 - w), '0%db' % w)
    if not any(b[:w] == want for b in found.get(mn, [])):
        print('MISMATCH %-10s table %s ISA %s' % (mn, want, found.get(mn)))
        bad += 1
print('%d mnemonics checked against the ISA, %d mismatches' % (len(gen.OPS), bad))
sys.exit(1 if bad else 0)
