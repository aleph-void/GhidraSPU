#!/usr/bin/env python3
"""Write a raw big-endian corpus of SPU instruction words: every 11-bit opcode value with
<per> random operand fills (all-zero and all-one fills included), then <rand> random words.
Usage: gen_corpus.py <out.bin> [per=48] [rand=60000] [seed=1]"""
import random
import struct
import sys

out = sys.argv[1]
per = int(sys.argv[2]) if len(sys.argv) > 2 else 48
nrand = int(sys.argv[3]) if len(sys.argv) > 3 else 60000
rng = random.Random(int(sys.argv[4]) if len(sys.argv) > 4 else 1)
words = []
for op in range(2048):
    words.append(op << 21)
    words.append((op << 21) | 0x1fffff)
    for _ in range(per - 2):
        words.append((op << 21) | rng.getrandbits(21))
words += [rng.getrandbits(32) for _ in range(nrand)]
with open(out, 'wb') as f:
    f.write(b''.join(struct.pack('>I', w) for w in words))
print(len(words), 'words')
