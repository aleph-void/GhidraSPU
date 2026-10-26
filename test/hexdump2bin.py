#!/usr/bin/env python3
"""Linux spufs *_dump.h_shipped (C array of 32-bit words) -> raw big-endian SPU image."""
import re
import struct
import sys

words = [int(w, 16) for w in re.findall(r'0x([0-9a-fA-F]{1,8})\s*,', open(sys.argv[1]).read())]
open(sys.argv[2], 'wb').write(b''.join(struct.pack('>I', w) for w in words))
print(len(words), 'words')
