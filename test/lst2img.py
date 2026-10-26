#!/usr/bin/env python3
"""RealCheck listing ("<addr> <bytes-hex> <text>") -> a raw image of exactly the bytes Ghidra
decoded (gaps zero-filled) and a slot listing ("<addr> <len> <text>") for slotdis -l / compare.py.
  lst2img.py <listing> <out.img> <out.slots>   -> prints the image base (hex)"""
import sys

rows = []
for line in open(sys.argv[1]):
    p = line.rstrip('\n').split(' ', 2)
    rows.append((int(p[0], 16), bytes.fromhex(p[1]), p[2] if len(p) > 2 else ''))
lo = min(a for a, _, _ in rows)
hi = max(a + len(b) for a, b, _ in rows)
img = bytearray(hi - lo)
with open(sys.argv[3], 'w') as f:
    for a, b, t in rows:
        img[a - lo:a - lo + len(b)] = b
        f.write('%08x %d %s\n' % (a, len(b), t))
open(sys.argv[2], 'wb').write(img)
print('%x' % lo)
