#!/usr/bin/env python3
"""Turn the R_SPU_ADDR32 words at symbols pic_undef/pic_def of reloc_types.o into
"a $3,$4,$5" (0x18014203) with an R_SPU_ADD_PIC relocation (GNU as cannot emit that type).
  addpic.py <in.o> <out.o>"""
import struct
import sys

d = bytearray(open(sys.argv[1], 'rb').read())
assert d[:6] == b'\x7fELF\x01\x02', 'ELF32 big-endian only'
shoff, = struct.unpack_from('>I', d, 0x20)
shentsize, shnum, shstrndx = struct.unpack_from('>HHH', d, 0x2e)
secs = [struct.unpack_from('>IIIIIIIIII', d, shoff + i * shentsize) for i in range(shnum)]
strtab_off = secs[shstrndx][4]
name = lambda s: d[strtab_off + s[0]:d.index(0, strtab_off + s[0])].decode()
symtab = next(s for s in secs if s[1] == 2)
strs = secs[symtab[6]][4]
syms = {}
for i in range(symtab[5] // 16):
    nm, val, size, info, other, shndx = struct.unpack_from('>IIIBBH', d, symtab[4] + 16 * i)
    syms[d[strs + nm:d.index(0, strs + nm)].decode()] = (val, shndx)
text = next(i for i, s in enumerate(secs) if name(s) == '.text')
want = {syms['pic_undef'][0], syms['pic_def'][0]}
done = 0
for s in secs:
    if s[1] == 4 and s[7] == text:          # SHT_RELA for .text
        for j in range(s[5] // 12):
            o = s[4] + 12 * j
            off, info, add = struct.unpack_from('>IIi', d, o)
            if off in want and info & 0xff == 6:
                struct.pack_into('>I', d, o + 4, (info & ~0xff) | 17)
                struct.pack_into('>I', d, secs[text][4] + off, 0x18014203)
                done += 1
assert done == 2, done
open(sys.argv[2], 'wb').write(d)
