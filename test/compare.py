#!/usr/bin/env python3
"""Compare a Ghidra slot listing (DumpSlots.java) with a GNU libopcodes listing (slotdis) of the
same raw SPU file.  Both: "<offset-hex> <len> <text>" per 4-byte slot.

Normalization: registers ($N, $lr/$sp, Ghidra lr/sp/rN, channel and SPR names -> numbers),
numbers (decimal or hex, signed) -> integers, addresses masked to 32 bits, objdump's "# hex"
comments dropped.  "exact" = identical after that.  "equivalent" additionally accepts the
documented display differences:
  - stop: Ghidra also shows the 14-bit signal type;
  - PC-relative operands with a zero offset: objdump prints 0, Ghidra the target address;
  - lqa/lqr/stqa/stqr: Ghidra shows the quadword address the instruction accesses (low 4 bits
    cleared), objdump the encoded word address.
Usage: compare.py ghidra.txt gnu.txt [--examples N] [--base HEX]
"""
import collections
import re
import sys

sys.path.insert(0, __file__.rsplit('/', 1)[0])

CHANNELS = {
    0: 'SPU_RdEventStat', 1: 'SPU_WrEventMask', 2: 'SPU_WrEventAck', 3: 'SPU_RdSigNotify1',
    4: 'SPU_RdSigNotify2', 7: 'SPU_WrDec', 8: 'SPU_RdDec', 9: 'MFC_WrMSSyncReq',
    11: 'SPU_RdEventMask', 12: 'MFC_RdTagMask', 13: 'SPU_RdMachStat', 14: 'SPU_WrSRR0',
    15: 'SPU_RdSRR0', 16: 'MFC_LSA', 17: 'MFC_EAH', 18: 'MFC_EAL', 19: 'MFC_Size',
    20: 'MFC_TagID', 21: 'MFC_Cmd', 22: 'MFC_WrTagMask', 23: 'MFC_WrTagUpdate',
    24: 'MFC_RdTagStat', 25: 'MFC_RdListStallStat', 26: 'MFC_WrListStallAck',
    27: 'MFC_RdAtomicStat', 28: 'SPU_WrOutMbox', 29: 'SPU_RdInMbox', 30: 'SPU_WrOutIntrMbox',
}
CHNUM = {v: k for k, v in CHANNELS.items()}
REL = {'br', 'brsl', 'brz', 'brnz', 'brhz', 'brhnz', 'lqr', 'stqr', 'hbrr'}
ABS = {'bra', 'brasl', 'lqa', 'stqa', 'hbra'}
QUAD = {'lqa', 'lqr', 'stqa', 'stqr'}


def tok(text):
    text = text.split('\t#')[0].split(' #')[0].strip()
    if not text or text in ('BAD', '(bad)') or text.startswith('.long'):
        return None
    parts = text.split(None, 1)
    mn = parts[0]
    ops = []
    if len(parts) > 1:
        for t in re.split(r'[,()\s]+', parts[1]):
            if not t:
                continue
            ops.append(norm(t))
    return mn, ops


def norm(t):
    if t.startswith('$sp') and t[3:].isdigit():
        return ('spr', int(t[3:]))
    if t.startswith('$ch') and t[3:].isdigit():
        return ('ch', int(t[3:]))
    if t in ('$lr', 'lr'):
        return ('r', 0)
    if t in ('$sp', 'sp'):
        return ('r', 1)
    m = re.fullmatch(r'\$(\d+)', t) or re.fullmatch(r'r(\d+)', t)
    if m:
        return ('r', int(m.group(1)))
    m = re.fullmatch(r'spr(\d+)', t)
    if m:
        return ('spr', int(m.group(1)))
    m = re.fullmatch(r'ch(\d+)', t)
    if m:
        return ('ch', int(m.group(1)))
    if t in CHNUM:
        return ('ch', CHNUM[t])
    m = re.fullmatch(r'(-?)(0x[0-9a-fA-F]+|\d+)', t)
    if m:
        v = int(m.group(2), 0)
        return ('n', -v if m.group(1) else v)
    return ('s', t)


def load(path):
    d = {}
    for line in open(path):
        p = line.rstrip('\n').split(' ', 2)
        if len(p) < 3:
            p.append('')
        d[int(p[0], 16)] = p[2]
    return d


def classify(addr, g, o):
    """Return ('exact'|'equiv'|'diff'|'both-undef'|'ghidra-only'|'gnu-only', bucket)."""
    tg, to = tok(g), tok(o)
    if tg is None and to is None:
        return 'both-undef', None
    if tg is None:
        return 'gnu-only', 'ghidra rejects ' + to[0]
    if to is None:
        return 'ghidra-only', 'gnu rejects ' + tg[0]
    if tg == to:
        return 'exact', None
    mg, og = tg
    mo, oo = to
    # mask addresses / numbers to 32 bits for comparison
    def m32(ops):
        return [(k, v & 0xffffffff) if k == 'n' else (k, v) for k, v in ops]
    og, oo = m32(og), m32(oo)
    if mg == mo and og == oo:
        return 'exact', None
    if mg == mo:
        if mg == 'stop' and oo == [] and len(og) == 1:
            return 'equiv', 'stop signal type shown'
        if len(og) == len(oo):
            ok = True
            why = set()
            for x, y in zip(og, oo):
                if x == y:
                    continue
                if x[0] == 'n' and y[0] == 'n':
                    if mg in REL | ABS and y[1] == 0 and (x[1] == addr & 0xffffffff or mg in ABS):
                        why.add('zero offset printed as 0')
                        if mg in ABS and x[1] != 0:
                            ok = False
                        continue
                    if mg in QUAD and x[1] == (y[1] & ~0xf):
                        why.add('quadword address shown aligned')
                        continue
                ok = False
            if ok:
                return 'equiv', '; '.join(sorted(why))
    return 'diff', '%s / %s' % (mg, mo)


def main():
    g = load(sys.argv[1])
    o = load(sys.argv[2])
    nex = 3
    if '--examples' in sys.argv:
        nex = int(sys.argv[sys.argv.index('--examples') + 1])
    counts = collections.Counter()
    buckets = collections.Counter()
    ex = collections.defaultdict(list)
    for a in sorted(set(g) & set(o)):
        c, b = classify(a, g[a], o[a])
        counts[c] += 1
        if b:
            buckets[(c, b)] += 1
            if len(ex[(c, b)]) < nex:
                ex[(c, b)].append('%08x  ghidra: %-40s gnu: %s' % (a, g[a], o[a]))
    total = sum(counts.values())
    dec = total - counts['both-undef']
    print('slots %d: exact %d, equivalent %d, both undefined %d, different %d, '
          'only Ghidra decodes %d, only GNU decodes %d' % (
              total, counts['exact'], counts['equiv'], counts['both-undef'], counts['diff'],
              counts['ghidra-only'], counts['gnu-only']))
    if dec:
        print('agreement on decoded slots: exact %.3f%%, exact+equivalent %.3f%%' % (
            100.0 * counts['exact'] / dec, 100.0 * (counts['exact'] + counts['equiv']) / dec))
    for (c, b), n in sorted(buckets.items(), key=lambda x: (-x[1], x[0])):
        print('%7d  %-11s %s' % (n, c, b))
        for e in ex[(c, b)]:
            print('           ' + e)
    return 0 if counts['diff'] + counts['ghidra-only'] + counts['gnu-only'] == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
