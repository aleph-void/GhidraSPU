#!/usr/bin/env python3
# Copyright 2019-2023 the GhidraSPU authors; 2026 Ghidra-Rare contributors.
# Licensed under the Apache License, Version 2.0 (see LICENSE).
"""Generate data/languages/spu.sinc for the Cell Broadband Engine SPU.

Usage: tools/gen_spu_sinc.py > data/languages/spu.sinc

Registers are 128 bits wide.  Each register r<n> (r0 = lr, r1 = sp) also has overlapping lane
views, big-endian like the hardware: <name>_d0..d1 (doublewords), _w0..w3 (words; w0 is the
preferred slot), _h0..h7 and _b0..b15.  Instruction fields have one token field per register
position and lane (R0w3 = word 3 of the register in bits 0-6), so the p-code of a SIMD operation
is a short statement per lane.

The opcode table (OPS) and operand order come from the instruction pages of the SPU ISA v1.2
(tools/isa_check.py verifies every entry against the PDF).  Reserved fields are not checked, and
where opcodes of different widths overlap the shorter opcode wins (RRR, then RI18/LBT, RI10, RI16,
RI8, then the 11-bit RR/RI7 opcodes), which is how GNU objdump decodes them (measured by the decode
tests); check_decode() proves the generated patterns resolve every 11-bit opcode that way.

Single-precision arithmetic follows the ISA's extended-range rules (truncation, no NaN/Inf,
denormal inputs as zero, saturation to Smax, positive-zero underflow, FPSCR OVF/UNF/DIFF/DBZ
flags).  It is computed exactly through double precision; see sp_* helpers.
"""
import re
import sys

QNAMES = ['lr', 'sp'] + ['r%d' % i for i in range(2, 128)]
LANES = {'d': (8, 2), 'w': (4, 4), 'h': (2, 8), 'b': (1, 16)}
POS = {'T': 0, 'A': 7, 'B': 14, 'C': 21}

# CBEA channel names (Cell Broadband Engine Architecture, SPU channel map)
CHANNELS = {
    0: 'SPU_RdEventStat', 1: 'SPU_WrEventMask', 2: 'SPU_WrEventAck', 3: 'SPU_RdSigNotify1',
    4: 'SPU_RdSigNotify2', 7: 'SPU_WrDec', 8: 'SPU_RdDec', 9: 'MFC_WrMSSyncReq',
    11: 'SPU_RdEventMask', 12: 'MFC_RdTagMask', 13: 'SPU_RdMachStat', 14: 'SPU_WrSRR0',
    15: 'SPU_RdSRR0', 16: 'MFC_LSA', 17: 'MFC_EAH', 18: 'MFC_EAL', 19: 'MFC_Size',
    20: 'MFC_TagID', 21: 'MFC_Cmd', 22: 'MFC_WrTagMask', 23: 'MFC_WrTagUpdate',
    24: 'MFC_RdTagStat', 25: 'MFC_RdListStallStat', 26: 'MFC_WrListStallAck',
    27: 'MFC_RdAtomicStat', 28: 'SPU_WrOutMbox', 29: 'SPU_RdInMbox', 30: 'SPU_WrOutIntrMbox',
}
CHNAMES = [CHANNELS.get(i, 'ch%d' % i) for i in range(128)]
LSLR = 0x3ffff          # local store limit (256 KiB)
QMASK = LSLR & ~0xf     # quadword-aligned local store address
IMASK = LSLR & ~0x3     # instruction address

# Opcode table from the SPU ISA v1.2: (mnemonic, format, opcode as an 11-bit value, operands).
# Synonyms (lr, bit/bif, ...) and feature-bit forms (bie, bid, ...) are printed from these.
OPS = [
    ('a', 'RR', 0x0c0, 'T A B'), ('absdb', 'RR', 0x053, 'T A B'), ('addx', 'RR', 0x340, 'T A B'),
    ('ah', 'RR', 0x0c8, 'T A B'), ('ahi', 'RI10', 0x0e8, 'T A S10'), ('ai', 'RI10', 0x0e0, 'T A S10'),
    ('and', 'RR', 0x0c1, 'T A B'), ('andbi', 'RI10', 0x0b0, 'T A S10'), ('andc', 'RR', 0x2c1, 'T A B'),
    ('andhi', 'RI10', 0x0a8, 'T A S10'), ('andi', 'RI10', 0x0a0, 'T A S10'), ('avgb', 'RR', 0x0d3, 'T A B'),
    ('bg', 'RR', 0x042, 'T A B'), ('bgx', 'RR', 0x343, 'T A B'), ('bi', 'RR', 0x1a8, 'A'),
    ('bihnz', 'RR', 0x12b, 'T A'), ('bihz', 'RR', 0x12a, 'T A'), ('binz', 'RR', 0x129, 'T A'),
    ('bisl', 'RR', 0x1a9, 'T A'), ('bisled', 'RR', 0x1ab, 'T A'), ('biz', 'RR', 0x128, 'T A'),
    ('br', 'RI16', 0x190, 'R18'), ('bra', 'RI16', 0x180, 'S18'), ('brasl', 'RI16', 0x188, 'T S18'),
    ('brhnz', 'RI16', 0x118, 'T R18'), ('brhz', 'RI16', 0x110, 'T R18'), ('brnz', 'RI16', 0x108, 'T R18'),
    ('brsl', 'RI16', 0x198, 'T R18'), ('brz', 'RI16', 0x100, 'T R18'), ('cbd', 'RI7', 0x1f4, 'T I7 P A'),
    ('cbx', 'RR', 0x1d4, 'T A B'), ('cdd', 'RI7', 0x1f7, 'T I7 P A'), ('cdx', 'RR', 0x1d7, 'T A B'),
    ('ceq', 'RR', 0x3c0, 'T A B'), ('ceqb', 'RR', 0x3d0, 'T A B'), ('ceqbi', 'RI10', 0x3f0, 'T A S10'),
    ('ceqh', 'RR', 0x3c8, 'T A B'), ('ceqhi', 'RI10', 0x3e8, 'T A S10'), ('ceqi', 'RI10', 0x3e0, 'T A S10'),
    ('cflts', 'RI8', 0x3b0, 'T A U7A'), ('cfltu', 'RI8', 0x3b2, 'T A U7A'), ('cg', 'RR', 0x0c2, 'T A B'),
    ('cgt', 'RR', 0x240, 'T A B'), ('cgtb', 'RR', 0x250, 'T A B'), ('cgtbi', 'RI10', 0x270, 'T A S10'),
    ('cgth', 'RR', 0x248, 'T A B'), ('cgthi', 'RI10', 0x268, 'T A S10'), ('cgti', 'RI10', 0x260, 'T A S10'),
    ('cgx', 'RR', 0x342, 'T A B'), ('chd', 'RI7', 0x1f5, 'T I7 P A'), ('chx', 'RR', 0x1d5, 'T A B'),
    ('clgt', 'RR', 0x2c0, 'T A B'), ('clgtb', 'RR', 0x2d0, 'T A B'), ('clgtbi', 'RI10', 0x2f0, 'T A S10'),
    ('clgth', 'RR', 0x2c8, 'T A B'), ('clgthi', 'RI10', 0x2e8, 'T A S10'), ('clgti', 'RI10', 0x2e0, 'T A S10'),
    ('clz', 'RR', 0x2a5, 'T A'), ('cntb', 'RR', 0x2b4, 'T A'), ('csflt', 'RI8', 0x3b4, 'T A U7B'),
    ('cuflt', 'RI8', 0x3b6, 'T A U7B'), ('cwd', 'RI7', 0x1f6, 'T I7 P A'), ('cwx', 'RR', 0x1d6, 'T A B'),
    ('dfa', 'RR', 0x2cc, 'T A B'), ('dfceq', 'RR', 0x3c3, 'T A B'), ('dfcgt', 'RR', 0x2c3, 'T A B'),
    ('dfcmeq', 'RR', 0x3cb, 'T A B'), ('dfcmgt', 'RR', 0x2cb, 'T A B'), ('dfm', 'RR', 0x2ce, 'T A B'),
    ('dfma', 'RR', 0x35c, 'T A B'), ('dfms', 'RR', 0x35d, 'T A B'), ('dfnma', 'RR', 0x35f, 'T A B'),
    ('dfnms', 'RR', 0x35e, 'T A B'), ('dfs', 'RR', 0x2cd, 'T A B'), ('dftsv', 'RI7', 0x3bf, 'T A I7'),
    ('dsync', 'RR', 0x003, ''), ('eqv', 'RR', 0x249, 'T A B'), ('fa', 'RR', 0x2c4, 'T A B'),
    ('fceq', 'RR', 0x3c2, 'T A B'), ('fcgt', 'RR', 0x2c2, 'T A B'), ('fcmeq', 'RR', 0x3ca, 'T A B'),
    ('fcmgt', 'RR', 0x2ca, 'T A B'), ('fesd', 'RR', 0x3b8, 'T A'), ('fi', 'RR', 0x3d4, 'T A B'),
    ('fm', 'RR', 0x2c6, 'T A B'), ('fma', 'RRR', 0x700, 'C A B T'), ('fms', 'RRR', 0x780, 'C A B T'),
    ('fnms', 'RRR', 0x680, 'C A B T'), ('frds', 'RR', 0x3b9, 'T A'), ('frest', 'RR', 0x1b8, 'T A'),
    ('frsqest', 'RR', 0x1b9, 'T A'), ('fs', 'RR', 0x2c5, 'T A B'), ('fscrrd', 'RR', 0x398, 'T'),
    ('fscrwr', 'RR', 0x3ba, 'T A'), ('fsm', 'RR', 0x1b4, 'T A'), ('fsmb', 'RR', 0x1b6, 'T A'),
    ('fsmbi', 'RI16', 0x194, 'T X16'), ('fsmh', 'RR', 0x1b5, 'T A'), ('gb', 'RR', 0x1b0, 'T A'),
    ('gbb', 'RR', 0x1b2, 'T A'), ('gbh', 'RR', 0x1b1, 'T A'), ('hbr', 'LBTI', 0x1ac, 'S11I A'),
    ('hbra', 'LBT', 0x080, 'S11 S18'), ('hbrr', 'LBT', 0x090, 'S11 R18'), ('heq', 'RR', 0x3d8, 'T A B'),
    ('heqi', 'RI10', 0x3f8, 'T A S10'), ('hgt', 'RR', 0x258, 'T A B'), ('hgti', 'RI10', 0x278, 'T A S10'),
    ('hlgt', 'RR', 0x2d8, 'T A B'), ('hlgti', 'RI10', 0x2f8, 'T A S10'), ('il', 'RI16', 0x204, 'T S16'),
    ('ila', 'RI18', 0x210, 'T U18'), ('ilh', 'RI16', 0x20c, 'T X16'), ('ilhu', 'RI16', 0x208, 'T X16'),
    ('iohl', 'RI16', 0x304, 'T X16'), ('iret', 'RR', 0x1aa, 'A'), ('lnop', 'RR', 0x001, ''),
    ('lqa', 'RI16', 0x184, 'T S18'), ('lqd', 'RI10', 0x1a0, 'T S14 P A'), ('lqr', 'RI16', 0x19c, 'T R18'),
    ('lqx', 'RR', 0x1c4, 'T A B'), ('mfspr', 'RR', 0x00c, 'T S'), ('mpy', 'RR', 0x3c4, 'T A B'),
    ('mpya', 'RRR', 0x600, 'C A B T'), ('mpyh', 'RR', 0x3c5, 'T A B'), ('mpyhh', 'RR', 0x3c6, 'T A B'),
    ('mpyhha', 'RR', 0x346, 'T A B'), ('mpyhhau', 'RR', 0x34e, 'T A B'), ('mpyhhu', 'RR', 0x3ce, 'T A B'),
    ('mpyi', 'RI10', 0x3a0, 'T A S10'), ('mpys', 'RR', 0x3c7, 'T A B'), ('mpyu', 'RR', 0x3cc, 'T A B'),
    ('mpyui', 'RI10', 0x3a8, 'T A S10'), ('mtspr', 'RR', 0x10c, 'S T'), ('nand', 'RR', 0x0c9, 'T A B'),
    ('nop', 'RR', 0x201, 'T'), ('nor', 'RR', 0x049, 'T A B'), ('or', 'RR', 0x041, 'T A B'),
    ('orbi', 'RI10', 0x030, 'T A S10'), ('orc', 'RR', 0x2c9, 'T A B'), ('orhi', 'RI10', 0x028, 'T A S10'),
    ('ori', 'RI10', 0x020, 'T A S10'), ('orx', 'RR', 0x1f0, 'T A'), ('rchcnt', 'RR', 0x00f, 'T H'),
    ('rdch', 'RR', 0x00d, 'T H'), ('rot', 'RR', 0x058, 'T A B'), ('roth', 'RR', 0x05c, 'T A B'),
    ('rothi', 'RI7', 0x07c, 'T A I7'), ('rothm', 'RR', 0x05d, 'T A B'), ('rothmi', 'RI7', 0x07d, 'T A I7'),
    ('roti', 'RI7', 0x078, 'T A I7'), ('rotm', 'RR', 0x059, 'T A B'), ('rotma', 'RR', 0x05a, 'T A B'),
    ('rotmah', 'RR', 0x05e, 'T A B'), ('rotmahi', 'RI7', 0x07e, 'T A I7'), ('rotmai', 'RI7', 0x07a, 'T A I7'),
    ('rotmi', 'RI7', 0x079, 'T A I7'), ('rotqbi', 'RR', 0x1d8, 'T A B'), ('rotqbii', 'RI7', 0x1f8, 'T A I7'),
    ('rotqby', 'RR', 0x1dc, 'T A B'), ('rotqbybi', 'RR', 0x1cc, 'T A B'), ('rotqbyi', 'RI7', 0x1fc, 'T A I7'),
    ('rotqmbi', 'RR', 0x1d9, 'T A B'), ('rotqmbii', 'RI7', 0x1f9, 'T A I7'), ('rotqmby', 'RR', 0x1dd, 'T A B'),
    ('rotqmbybi', 'RR', 0x1cd, 'T A B'), ('rotqmbyi', 'RI7', 0x1fd, 'T A I7'), ('selb', 'RRR', 0x400, 'C A B T'),
    ('sf', 'RR', 0x040, 'T A B'), ('sfh', 'RR', 0x048, 'T A B'), ('sfhi', 'RI10', 0x068, 'T A S10'),
    ('sfi', 'RI10', 0x060, 'T A S10'), ('sfx', 'RR', 0x341, 'T A B'), ('shl', 'RR', 0x05b, 'T A B'),
    ('shlh', 'RR', 0x05f, 'T A B'), ('shlhi', 'RI7', 0x07f, 'T A I7'), ('shli', 'RI7', 0x07b, 'T A I7'),
    ('shlqbi', 'RR', 0x1db, 'T A B'), ('shlqbii', 'RI7', 0x1fb, 'T A I7'), ('shlqby', 'RR', 0x1df, 'T A B'),
    ('shlqbybi', 'RR', 0x1cf, 'T A B'), ('shlqbyi', 'RI7', 0x1ff, 'T A I7'), ('shufb', 'RRR', 0x580, 'C A B T'),
    ('stop', 'RR', 0x000, ''), ('stopd', 'RR', 0x140, 'T A B'), ('stqa', 'RI16', 0x104, 'T S18'),
    ('stqd', 'RI10', 0x120, 'T S14 P A'), ('stqr', 'RI16', 0x11c, 'T R18'), ('stqx', 'RR', 0x144, 'T A B'),
    ('sumb', 'RR', 0x253, 'T A B'), ('sync', 'RR', 0x002, ''), ('wrch', 'RR', 0x10d, 'H T'),
    ('xor', 'RR', 0x241, 'T A B'), ('xorbi', 'RI10', 0x230, 'T A S10'), ('xorhi', 'RI10', 0x228, 'T A S10'),
    ('xori', 'RI10', 0x220, 'T A S10'), ('xsbh', 'RR', 0x2b6, 'T A'), ('xshw', 'RR', 0x2ae, 'T A'),
    ('xswd', 'RR', 0x2a6, 'T A'),
]
OPWIDTH = {'RRR': 4, 'RI18': 7, 'LBT': 7, 'RI10': 8, 'RI16': 9, 'RI8': 10, 'RR': 11, 'RI7': 11, 'LBTI': 11}
DECODE_ORDER = [('RRR', 0x780), ('RI18', 0x7f0), ('RI10', 0x7f8), ('RI16', 0x7fc), ('RI8', 0x7fe)]


def check_decode():
    """Every 11-bit opcode must select the same instruction under the shorter-opcode-first order
    and under SLEIGH's rule (the most specific pattern wins)."""
    table = {}
    for mn, fmt, op, _ in OPS:
        table.setdefault(op, (mn, fmt))
    def ordered(v):
        for fmts, mask in DECODE_ORDER:
            e = table.get(v & mask)
            if e and (e[1] == fmts or (fmts == 'RI18' and e[1] == 'LBT')):
                return e[0]
        e = table.get(v)
        return e[0] if e else None
    def sleigh(v):
        best = None
        for mn, fmt, op, _ in OPS:
            w = OPWIDTH[fmt]
            if (v >> (11 - w)) == (op >> (11 - w)) and (best is None or w > best[0]):
                best = (w, mn)
        return best[1] if best else None
    bad = [(v, ordered(v), sleigh(v)) for v in range(2048) if ordered(v) != sleigh(v)]
    if bad:
        raise SystemExit('decode precedence differs: %r' % bad[:20])


# ---------------------------------------------------------------------------------------------
out = []


def emit(s=''):
    out.append(s)


def F(p, kind=None, k=None):
    return 'R%d' % p if kind is None else 'R%d%s%d' % (p, kind, k)


T, A, B, C = (lambda kind=None, k=None, p=p: F(p, kind, k) for p in (0, 7, 14, 21))

FIELD_RE = re.compile(r'\bR(?:0|7|14|21)(?:[dwhb]\d+)?\b')
IMM_NAMES = ['i7', 'u7', 'u8', 'i10', 'i16', 'u16', 'u18', 'u14', 'roh', 'rol', 'rohb', 'ca', 'cac',
             'sa', 'fbP', 'fbD', 'fbE', 'rt_raw', 'ra_raw', 'rb_raw',
             'LSA10', 'REL16', 'ABS16', 'QREL16', 'QABS16', 'BRI9A', 'BRI9B', 'FB', 'HP', 'SYNCF']


KSIZE = {'sch': 2, 'hv': 4, 'mhi': 8, 'mlo': 8, 'rep': 8, 'sc': 4, 'scd': 8, 'en': 4}
KTABLES = {}     # (expr, size) -> subtable name
ktext = []
FIELD_NAMES = ['i7', 'u7', 'u8', 'i10', 'i16', 'u16', 'u18', 'u14']


def K(expr, size):
    """A subtable exporting a decode-time constant (disassembly-action locals must be displayed,
    so constants the display does not show live in their own subtables)."""
    key = (expr, size)
    if key not in KTABLES:
        name = 'K%d' % len(KTABLES)
        KTABLES[key] = name
        flds = [f for f in FIELD_NAMES if re.search(r'\b%s\b' % f, expr)]
        ktext.append('%s: v is %s [ v = %s; ] { export *[const]:%d v; }' % (name, ' & '.join(flds), expr, size))
        IMM_NAMES.append(name)
    return KTABLES[key]


def ctor(head, disp, cons, body, action=None):
    """head: ':mnemonic' or 'table:'.  cons: opcode constraint string."""
    if action:
        keep = []
        for a in [x.strip() for x in action.split(';') if x.strip()]:
            name, expr = [x.strip() for x in a.split('=', 1)]
            if re.search(r'\b%s\b' % name, disp):
                keep.append(a + ';')
            else:
                body = re.sub(r'\b%s\b' % name, K(expr, KSIZE[name]), body)
        action = ' '.join(keep) or None
    text = head + ' ' + disp + ' ' + body + ' ' + (action or '')
    pats = [cons] if cons else []
    seen = set(re.findall(r'\b\w+\b', cons))
    for f in sorted(set(FIELD_RE.findall(text)), key=lambda s: (len(s), s)):
        if f not in seen:
            pats.append(f)
            seen.add(f)
    for n in IMM_NAMES:
        if n not in seen and re.search(r'\b%s\b' % n, text):
            pats.append(n)
            seen.add(n)
    act = ' [ %s ]' % action if action else ''
    emit('%s %s is %s%s\n{\n%s\n}\n' % (head, disp, ' & '.join(pats), act,
                                        '\n'.join('\t' + l for l in body.split('\n') if l.strip())))


def opc(fmt, op):
    w = OPWIDTH[fmt]
    return 'op%d=0x%x' % (w, op >> (11 - w))


def lanes(kind, fn):
    return '\n'.join(fn(k) for k in range(LANES[kind][1]))


# The decompiler names a temporary through a hash of its neighbouring p-code ops and gives up
# ("Unable to find unique hash for varnode") when more than 8 varnodes of one instruction hash
# alike.  Operations with 16 identical byte-lane chains (or 12 identical conversions in fma)
# therefore compute lanes 8-15 with an equivalent but differently shaped expression.
def alt(k):
    return k >= 8


def zero_rest(f):
    return '\n'.join('%s = 0;' % f('w', k) for k in (1, 2, 3))


# ---------------------------------------------------------------------------------------------
# Header: spaces, registers, tokens.

def header():
    emit('# Generated by tools/gen_spu_sinc.py -- do not edit by hand.')
    emit('# Cell Broadband Engine SPU (SPU ISA v1.2).  The main .slaspec defines endian and alignment.')
    emit()
    emit('define space ram type=ram_space size=4 default;')
    emit('define space register type=register_space size=4;')
    emit()
    emit('define register offset=0x0000 size=16 [ %s ];' % ' '.join(QNAMES))
    for kind, (sz, n) in LANES.items():
        names = ['%s_%s%d' % (q, kind, k) for q in QNAMES for k in range(n)]
        emit('define register offset=0x0000 size=%d [ %s ];' % (sz, ' '.join(names)))
    emit('define register offset=0x1000 size=4 [ pc SRR0 ];')
    emit('define register offset=0x1008 size=1 [ IE ];')
    emit('define register offset=0x1010 size=16 [ FPSCR ];')
    emit('define register offset=0x1010 size=4 [ FPSCR0 FPSCR1 FPSCR2 FPSCR3 ];')
    emit('define register offset=0x1100 size=4 [ %s ];' % ' '.join(CHNAMES))
    emit('define register offset=0x1300 size=4 [ %s ];' % ' '.join('%s_cnt' % c for c in CHNAMES))
    emit('define register offset=0x1500 size=4 [ %s ];' % ' '.join('spr%d' % i for i in range(128)))
    emit()
    emit('define token instr(32)')
    emit('\top4=(28,31) op7=(25,31) op8=(24,31) op9=(23,31) op10=(22,31) op11=(21,31)')
    for p in (0, 7, 14, 21):
        fs = ['R%d=(%d,%d)' % (p, p, p + 6)]
        for kind, (sz, n) in LANES.items():
            fs += ['R%d%s%d=(%d,%d)' % (p, kind, k, p, p + 6) for k in range(n)]
        emit('\t' + ' '.join(fs))
    emit('\trt_raw=(0,6) ra_raw=(7,13) rb_raw=(14,20)')
    emit('\ti7=(14,20) signed u7=(14,20) u8=(14,21) i10=(14,23) signed')
    emit('\ti16=(7,22) signed u16=(7,22) u18=(7,24) u14=(0,13)')
    emit('\troh=(23,24) signed rol=(0,6) rohb=(14,15) signed')
    emit('\tfbP=(20,20) fbD=(19,19) fbE=(18,18)')
    emit('\tca=(7,13) cac=(7,13) sa=(7,13)')
    emit(';')
    emit()
    for p in (0, 7, 14, 21):
        emit('attach variables [ R%d ] [ %s ];' % (p, ' '.join(QNAMES)))
        for kind, (sz, n) in LANES.items():
            for k in range(n):
                emit('attach variables [ R%d%s%d ] [ %s ];' % (
                    p, kind, k, ' '.join('%s_%s%d' % (q, kind, k) for q in QNAMES)))
    emit('attach variables [ ca ] [ %s ];' % ' '.join(CHNAMES))
    emit('attach variables [ cac ] [ %s ];' % ' '.join('%s_cnt' % c for c in CHNAMES))
    emit('attach variables [ sa ] [ %s ];' % ' '.join('spr%d' % i for i in range(128)))
    emit()
    emit('define pcodeop spu_stop;         # stop and signal the PPE (signal type)')
    emit('define pcodeop spu_stopd;        # stop with register dependencies')
    emit('define pcodeop spu_halt;         # halt instruction condition met')
    emit()


def operand_tables():
    emit('# lqd/stqd displacement: I10 quadwords')
    emit('LSA10: off is i10 [ off = i10 << 4; ] { export *[const]:4 off; }')
    emit('# PC-relative and absolute instruction addresses (I16 words), masked by LSLR like the hardware')
    emit('REL16: addr is i16 [ addr = (inst_start + (i16 << 2)) & %#x; ] { export *[ram]:4 addr; }' % LSLR)
    emit('ABS16: addr is u16 [ addr = u16 << 2; ] { export *[ram]:4 addr; }')
    emit('# lqa/lqr/stqa/stqr: the operand (and its reference) is the encoded word address, which')
    emit('# compilers set to the scalar being accessed; the access itself ignores the low 4 bits.')
    emit('QREL16: addr is i16 [ addr = (inst_start + (i16 << 2)) & %#x; ] { export *[ram]:4 addr; }' % LSLR)
    emit('QABS16: addr is u16 [ addr = u16 << 2; ] { export *[ram]:4 addr; }')
    emit('# hint-for-branch: address of the hinted branch instruction')
    emit('BRI9A: addr is roh & rol [ addr = (inst_start + (((roh << 7) | rol) << 2)) & 0xffffffff; ] '
         '{ export *[ram]:4 addr; }')
    emit('BRI9B: addr is rohb & rol [ addr = (inst_start + (((rohb << 7) | rol) << 2)) & 0xffffffff; ] '
         '{ export *[ram]:4 addr; }')
    emit()
    emit('# Feature bits of the indirect branches: P (bit 11), D (12, disable interrupts) and E (13, enable)')
    for p in (0, 1):
        for d in (0, 1):
            for e in (0, 1):
                s = ('p' if p else '') + ('d' if d else '') + ('e' if e else '')
                body = 'IE = 0;' if d and not e else ('IE = 1;' if e and not d else '')
                emit('FB: "%s" is fbP=%d & fbD=%d & fbE=%d { %s }' % (s, p, d, e, body)
                     if s else 'FB: is fbP=0 & fbD=0 & fbE=0 { }')
    # hbr: libopcodes prints the P bit and also bits 12/13 (reserved for hbr) as d/e
    for p in (0, 1):
        for d in (0, 1):
            for e in (0, 1):
                s = ('p' if p else '') + ('d' if d else '') + ('e' if e else '')
                emit('HP: "%s" is fbP=%d & fbD=%d & fbE=%d { }' % (s, p, d, e)
                     if s else 'HP: is fbP=0 & fbD=0 & fbE=0 { }')
    for p in (0, 1):
        for d in (0, 1):
            for e in (0, 1):
                s = ('c' if p else '') + ('d' if d else '') + ('e' if e else '')
                emit('SYNCF: "%s" is fbP=%d & fbD=%d & fbE=%d { }' % (s, p, d, e)
                     if s else 'SYNCF: is fbP=0 & fbD=0 & fbE=0 { }')
    emit()


# ---------------------------------------------------------------------------------------------
# Single-precision extended-range helpers (per lane, code as a list of lines).

def sp2d(x, n, variant=False):
    """SPU single (bits in x, 4 bytes) -> exact double n; exponent 0 reads as signed zero.
    variant: the same value through differently shaped p-code (see alt())."""
    if variant:
        return ['local %se:4 = (%s << 1) >> 24;' % (n, x),
                'local %sm:8 = (((zext(%se) + 896) << 52) + (zext(%s << 9) << 20)) & (0 - zext(%se != 0));'
                % (n, n, x, n),
                'local %s:8 = (zext(%s >> 31) << 63) + %sm;' % (n, x, n)]
    return ['local %se:4 = (%s >> 23) & 0xff;' % (n, x),
            'local %sm:8 = (((zext(%se) + 896) << 52) | (zext(%s & 0x7fffff) << 29)) * zext(%se != 0);'
            % (n, n, x, n),
            'local %s:8 = (zext(%s & 0x80000000) << 32) | %sm;' % (n, x, n)]


def sp_in_diff(n):
    """DIFF input condition for a value converted by sp2d (max exponent or denormal)."""
    return '(%se == 0xff)' % n, '((%se == 0) && (%sm != 0))' % (n, n)


def sp_in_flags(names, x_of):
    conds = []
    for n in names:
        conds.append('(%se == 0xff)' % n)
        conds.append('((%se == 0) && ((%s & 0x7fffff) != 0))' % (n, x_of[n]))
    return ' || '.join(conds)


def d2sp(d, o):
    """Exact double d -> SPU single o by truncation; o_ov/o_uf/o_mx are overflow, underflow and
    max-exponent-result booleans."""
    return ['local %shi:4 = %s(4);' % (o, d),
            'local %sde:4 = (%shi >> 20) & 0x7ff;' % (o, o),
            'local %sfr:8 = %s >> 29;' % (o, d),
            'local %sov:1 = %sde > 1151;' % (o, o),
            'local %suf:1 = (%sde != 0) && (%sde < 897);' % (o, o, o),
            'local %sok:1 = (%sde > 896) && (%sde < 1152);' % (o, o, o),
            'local %smx:1 = %sde > 1150;' % (o, o),
            'local %s:4 = (((%shi & 0x80000000) | 0x7fffffff) * zext(%sov)) | '
            '(((%shi & 0x80000000) | ((%sde - 896) << 23) | (%sfr:4 & 0x7fffff)) * zext(%sok));'
            % (o, o, o, o, o, o, o)]


def twosum_trunc(x, y, n):
    """n = x + y (doubles) with the sum nudged one double ulp toward zero when round-to-nearest
    landed on the single-precision grid from above, so truncation gives the exact result."""
    return ['local %ss:8 = %s f+ %s;' % (n, x, y),
            'local %sbb:8 = %ss f- %s;' % (n, n, x),
            'local %ser:8 = (%s f- (%ss f- %sbb)) f+ (%s f- %sbb);' % (n, x, n, n, y, n),
            'local %sadj:1 = (%ser f!= 0) && ((%ser f< 0) != (%ss f< 0)) && ((%ss & 0x1fffffff) == 0);'
            % (n, n, n, n, n),
            'local %s:8 = %ss - zext(%sadj);' % (n, n, n)]


def sp_flags(k, ov, uf, diff):
    return 'FPSCR%d = FPSCR%d | (zext(%s) << 2) | (zext(%s) << 1) | zext(%s);' % (k, k, ov, uf, diff)


def sp_arith(kind, dst, a, b, c=None):
    """kind: add, sub, mul, fma (a*b+c), fms (a*b-c), fnms (c-a*b).  Per word lane."""
    lines = []
    for k in range(4):
        n = 'f%d' % k
        ins = {}
        lines += sp2d(a('w', k), n + 'a'); ins[n + 'a'] = a('w', k)
        lines += sp2d(b('w', k), n + 'b'); ins[n + 'b'] = b('w', k)
        if c is not None:
            lines += sp2d(c('w', k), n + 'c', True); ins[n + 'c'] = c('w', k)
        if kind == 'mul':
            lines.append('local %sr:8 = %sa f* %sb;' % (n, n, n))
        elif kind == 'add':
            lines += twosum_trunc(n + 'a', n + 'b', n + 'r')
        elif kind == 'sub':
            lines.append('local %snb:8 = %sb ^ 0x8000000000000000;' % (n, n))
            lines += twosum_trunc(n + 'a', n + 'nb', n + 'r')
        else:
            lines.append('local %sp:8 = %sa f* %sb;' % (n, n, n))
            if kind == 'fma':
                lines += twosum_trunc(n + 'p', n + 'c', n + 'r')
            elif kind == 'fms':
                lines.append('local %snc:8 = %sc ^ 0x8000000000000000;' % (n, n))
                lines += twosum_trunc(n + 'p', n + 'nc', n + 'r')
            else:
                lines.append('local %snp:8 = %sp ^ 0x8000000000000000;' % (n, n))
                lines += twosum_trunc(n + 'c', n + 'np', n + 'r')
        lines += d2sp(n + 'r', n + 'o')
        diff = '(%s) || %somx || %souf' % (sp_in_flags(list(ins), ins), n, n)
        lines.append('local %sdf:1 = %s;' % (n, diff))
    for k in range(4):
        n = 'f%d' % k
        lines.append('%s = %so;' % (dst('w', k), n))
        lines.append(sp_flags(k, n + 'oov', n + 'ouf', n + 'df'))
    return '\n'.join(lines)


# Double-precision helpers: classification and FPSCR exception flags.
def dclass(x, n, size=8):
    """Classify IEEE bits x (8 bytes double, 4 bytes single): n_nan, n_snan, n_inf."""
    if size == 8:
        sh, em, fm, qb = 52, 0x7ff, 0xfffffffffffff, 0x0008000000000000
    else:
        sh, em, fm, qb = 23, 0xff, 0x7fffff, 0x400000
    return ['local %sx:%d = %s;' % (n, size, x),
            'local %sme:1 = ((%sx >> %d) & %#x) == %#x;' % (n, n, sh, em, em),
            'local %snan:1 = %sme && ((%sx & %#x) != 0);' % (n, n, n, fm),
            'local %ssnan:1 = %snan && ((%sx & %#x) == 0);' % (n, n, n, qb),
            'local %sinf:1 = %sme && ((%sx & %#x) == 0);' % (n, n, n, fm)]

def dflags(k, ins, r, err, rsize=8, minnorm=0x0010000000000000):
    """FPSCR flags of doubleword slot k for result bits r (rsize bytes) with the exact
    rounding error err (any float size; 0 when exact) of inputs ins (classified names)."""
    n = 'fl%d' % k
    absmask = 0x7fffffffffffffff if rsize == 8 else 0x7fffffff
    expmask = 0x7ff0000000000000 if rsize == 8 else 0x7f800000
    L = dclass(r, n + 'r', rsize)
    L += ['local %snanin:1 = %s;' % (n, ' || '.join('%snan' % i for i in ins)),
          'local %ssnanin:1 = %s;' % (n, ' || '.join('%ssnan' % i for i in ins)),
          'local %sinfin:1 = %s;' % (n, ' || '.join('%sinf' % i for i in ins)),
          'local %sinv:1 = %ssnanin || (%srnan && !%snanin);' % (n, n, n, n),
          'local %sovf:1 = %srinf && !%sinfin && !%snanin;' % (n, n, n, n),
          'local %sinx:1 = %sovf || (!%srnan && !%srinf && (%s f!= 0));' % (n, n, n, n, err),
          'local %sup:1 = ((%srx & %#x) == %#x) && ((%s f< 0) != ((%srx >> %d) != 0));'
          % (n, n, absmask, minnorm, err, n, rsize * 8 - 1),
          'local %sunf:1 = %sinx && (((%srx & %#x) == 0) || %sup);' % (n, n, n, expmask, n),
          'FPSCR%d = FPSCR%d | (zext(%sovf) << 13) | (zext(%sunf) << 12) | (zext(%sinx) << 11) | '
          '(zext(%sinv) << 10) | (zext(%snanin) << 9);' % (1 + k, 1 + k, n, n, n, n, n)]
    return L


# ---------------------------------------------------------------------------------------------
def instructions():
    I = {}  # mnemonic -> (fmt, opcode)
    for mn, fmt, op, args in OPS:
        I.setdefault(mn, (fmt, op))

    def op(mn):
        return opc(*I[mn])

    # ---- memory
    ctor(':lqd', 'R0, LSA10(R7)', op('lqd') + ' & ra_raw=1',
         'local ea:4 = sp_w0 + LSA10;\nR0 = *[ram]:16 ea;')
    ctor(':lqd', 'R0, LSA10(R7)', op('lqd'),
         'local ea:4 = (R7w0 + LSA10) & %#x;\nR0 = *[ram]:16 ea;' % QMASK)
    ctor(':stqd', 'R0, LSA10(R7)', op('stqd') + ' & ra_raw=1',
         'local ea:4 = sp_w0 + LSA10;\n*[ram]:16 ea = R0;')
    ctor(':stqd', 'R0, LSA10(R7)', op('stqd'),
         'local ea:4 = (R7w0 + LSA10) & %#x;\n*[ram]:16 ea = R0;' % QMASK)
    ctor(':lqx', 'R0, R7, R14', op('lqx'), 'local ea:4 = (R7w0 + R14w0) & %#x;\nR0 = *[ram]:16 ea;' % QMASK)
    ctor(':stqx', 'R0, R7, R14', op('stqx'), 'local ea:4 = (R7w0 + R14w0) & %#x;\n*[ram]:16 ea = R0;' % QMASK)
    for mn, sub in (('lqa', 'QABS16'), ('lqr', 'QREL16')):
        ctor(':' + mn, 'R0, ' + sub, op(mn), 'local ea:4 = &%s & %#x;\nR0 = *[ram]:16 ea;' % (sub, QMASK))
    for mn, sub in (('stqa', 'QABS16'), ('stqr', 'QREL16')):
        ctor(':' + mn, 'R0, ' + sub, op(mn), 'local ea:4 = &%s & %#x;\n*[ram]:16 ea = R0;' % (sub, QMASK))

    # ---- generate controls for insertion
    def ctrl(mn, size, idx, mask, rr):
        pos = {1: 15, 2: 14, 4: 12, 8: 8}[size]
        ins = {1: '0x03', 2: '0x0203', 4: '0x00010203', 8: '0x0001020304050607'}[size]
        m = {1: '0xff', 2: '0xffff', 4: '0xffffffff', 8: '0xffffffffffffffff'}[size]
        addr = '(R7w0 + R14w0)' if rr else '(R7w0 + i7)'
        body = '\n'.join([
            'local t:4 = %s & %#x;' % (addr, mask),
            'local sh:4 = (%d - t) * 8;' % pos,
            'local base:16 = (zext(0x1011121314151617:8) << 64) | zext(0x18191a1b1c1d1e1f:8);',
            'R0 = (base & ~(zext(%s:8) << sh)) | (zext(%s:8) << sh);' % (m, ins)])
        if rr:
            ctor(':' + mn, 'R0, R7, R14', op(mn), body)
        else:
            ctor(':' + mn, 'R0, i7(R7)', op(mn), body)
    for mn, size, mask in (('cb', 1, 0xf), ('ch', 2, 0xe), ('cw', 4, 0xc), ('cd', 8, 0x8)):
        ctrl(mn + 'd', size, None, mask, False)
        ctrl(mn + 'x', size, None, mask, True)

    # ---- constant formation
    # replicated constants are written as two doublewords: fewer identical p-code ops than word
    # lanes, and (unlike a 16-byte constant) the decompiler can fold them into the scalar slots
    QREP = 'R0d0 = rep;\nR0d1 = rep;'
    ctor(':ilh', 'R0, u16', op('ilh'), QREP, 'rep = u16 * 0x0001000100010001;')
    ctor(':ilhu', 'R0, u16', op('ilhu'), QREP, 'rep = (u16 << 16) * 0x0000000100000001;')
    ctor(':il', 'R0, i16', op('il'), QREP, 'rep = (i16 & 0xffffffff) * 0x0000000100000001;')
    ctor(':ila', 'R0, u18', op('ila'), QREP, 'rep = u18 * 0x0000000100000001;')
    ctor(':iohl', 'R0, u16', op('iohl'), 'R0d0 = R0d0 | rep;\nR0d1 = R0d1 | rep;', 'rep = u16 * 0x0000000100000001;')
    # (decode-time arithmetic is signed 64-bit, so build the masks with left shifts)
    hi = ' | '.join('(((u16 >> %d) & 1) * 0xff << %d)' % (15 - j, 56 - 8 * j) for j in range(8))
    lo = ' | '.join('(((u16 >> %d) & 1) * 0xff << %d)' % (7 - j, 56 - 8 * j) for j in range(8))
    ctor(':fsmbi', 'R0, u16', op('fsmbi'), 'R0d0 = mhi;\nR0d1 = mlo;', 'mhi = %s; mlo = %s;' % (hi, lo))

    # ---- integer arithmetic
    def rr3(mn, kind, fmt):
        ctor(':' + mn, 'R0, R7, R14', op(mn), lanes(kind, lambda k: fmt.format(t=T(kind, k), a=A(kind, k), b=B(kind, k))))

    def ri10(mn, kind, fmt, disp='i10'):
        ctor(':' + mn, 'R0, R7, %s' % disp, op(mn), lanes(kind, lambda k: fmt.format(t=T(kind, k), a=A(kind, k))))
    rr3('ah', 'h', '{t} = {a} + {b};')
    ri10('ahi', 'h', '{t} = {a} + i10;')
    rr3('a', 'w', '{t} = {a} + {b};')
    ri10('ai', 'w', '{t} = {a} + i10;')
    rr3('sfh', 'h', '{t} = {b} - {a};')
    ri10('sfhi', 'h', '{t} = i10 - {a};')
    rr3('sf', 'w', '{t} = {b} - {a};')
    ri10('sfi', 'w', '{t} = i10 - {a};')
    rr3('addx', 'w', '{t} = {a} + {b} + ({t} & 1);')
    rr3('sfx', 'w', '{t} = {b} + ~{a} + ({t} & 1);')
    ctor(':cg', 'R0, R7, R14', op('cg'), lanes('w', lambda k: '%s = zext(carry(%s, %s));' % (T('w', k), A('w', k), B('w', k))))
    ctor(':bg', 'R0, R7, R14', op('bg'), lanes('w', lambda k: '%s = zext(%s <= %s);' % (T('w', k), A('w', k), B('w', k))))
    ctor(':cgx', 'R0, R7, R14', op('cgx'), lanes('w', lambda k: 'local s%d:8 = zext(%s) + zext(%s) + zext(%s & 1);\n%s = s%d(4);'
                                                 % (k, A('w', k), B('w', k), T('w', k), T('w', k), k)))
    ctor(':bgx', 'R0, R7, R14', op('bgx'), lanes('w', lambda k: 'local s%d:8 = zext(%s) + zext(~%s) + zext(%s & 1);\n%s = s%d(4);'
                                                 % (k, B('w', k), A('w', k), T('w', k), T('w', k), k)))
    # multiplies: hi = halfword 2k (bits 0-15 of the word), lo = halfword 2k+1
    def mul(mn, fmt, regs='R0, R7, R14'):
        ctor(':' + mn, regs, op(mn), lanes('w', lambda k: fmt.format(
            t=T('w', k), ahi=A('h', 2 * k), alo=A('h', 2 * k + 1), bhi=B('h', 2 * k), blo=B('h', 2 * k + 1), k=k,
            c=C('w', k))))
    mul('mpy', '{t} = sext({alo}) * sext({blo});')
    mul('mpyu', '{t} = zext({alo}) * zext({blo});')
    mul('mpyh', '{t} = (zext({ahi}) * zext({blo})) << 16;')
    mul('mpys', 'local p{k}:4 = sext({alo}) * sext({blo});\n{t} = p{k} s>> 16;')
    mul('mpyhh', '{t} = sext({ahi}) * sext({bhi});')
    mul('mpyhha', '{t} = {t} + sext({ahi}) * sext({bhi});')
    mul('mpyhhu', '{t} = zext({ahi}) * zext({bhi});')
    mul('mpyhhau', '{t} = {t} + zext({ahi}) * zext({bhi});')
    ctor(':mpyi', 'R0, R7, i10', op('mpyi'), lanes('w', lambda k: '%s = sext(%s) * i10;' % (T('w', k), A('h', 2 * k + 1))))
    ctor(':mpyui', 'R0, R7, i10', op('mpyui'), 'local im:2 = i10;\n' + lanes(
        'w', lambda k: '%s = zext(%s) * zext(im);' % (T('w', k), A('h', 2 * k + 1))))
    ctor(':mpya', 'R21, R7, R14, R0', op('mpya'), lanes('w', lambda k: '%s = sext(%s) * sext(%s) + %s;' % (
        C('w', k), A('h', 2 * k + 1), B('h', 2 * k + 1), T('w', k))))
    ctor(':clz', 'R0, R7', op('clz'), lanes('w', lambda k: '%s = lzcount(%s);' % (T('w', k), A('w', k))))
    ctor(':cntb', 'R0, R7', op('cntb'), lanes('b', lambda k: ('%s = popcount(%s) & 0xf;' if alt(k) else
                                                          '%s = popcount(%s);') % (T('b', k), A('b', k))))
    # form select mask
    ctor(':fsmb', 'R0, R7', op('fsmb'), 'local s:2 = R7h1;\n' + lanes(
        'b', lambda k: ('local m%d:2 = ((s >> %d) & 1) * 0xff;\n%s = m%d:1;' if alt(k) else
                        'local m%d:2 = 0 - ((s >> %d) & 1);\n%s = m%d:1;') % (k, 15 - k, T('b', k), k)))
    ctor(':fsmh', 'R0, R7', op('fsmh'), 'local s:1 = R7b3;\n' + lanes(
        'h', lambda k: '%s = 0 - zext((s >> %d) & 1);' % (T('h', k), 7 - k)))
    ctor(':fsm', 'R0, R7', op('fsm'), 'local s:4 = R7w0;\n' + lanes(
        'w', lambda k: '%s = 0 - ((s >> %d) & 1);' % (T('w', k), 3 - k)))
    # gather bits
    ctor(':gbb', 'R0, R7', op('gbb'), 'local s:4 = %s;\nR0w0 = s;\n%s' % (
        ' | '.join(('((zext(%s) & 1) << %d)' if alt(j) else '(zext(%s & 1) << %d)') % (A('b', j), 15 - j)
                   for j in range(16)), zero_rest(T)))
    ctor(':gbh', 'R0, R7', op('gbh'), 'local s:4 = %s;\nR0w0 = s;\n%s' % (
        ' | '.join('(zext(%s & 1) << %d)' % (A('h', j), 7 - j) for j in range(8)), zero_rest(T)))
    ctor(':gb', 'R0, R7', op('gb'), 'local s:4 = %s;\nR0w0 = s;\n%s' % (
        ' | '.join('((%s & 1) << %d)' % (A('w', j), 3 - j) for j in range(4)), zero_rest(T)))
    ctor(':avgb', 'R0, R7, R14', op('avgb'), lanes('b', lambda k: (
        ('local s%d:2 = (zext(%s) + zext(%s) + 1) / 2;\n%s = s%d:1;' if alt(k) else
         'local s%d:2 = (zext(%s) + zext(%s) + 1) >> 1;\n%s = s%d:1;') % (k, A('b', k), B('b', k), T('b', k), k))))
    ctor(':absdb', 'R0, R7, R14', op('absdb'), lanes('b', lambda k: (
        ('local x%d:1 = %s;\nlocal y%d:1 = %s;\n%s = ((x%d - y%d) * zext(x%d > y%d)) ^ ((y%d - x%d) * zext(y%d >= x%d));'
         if alt(k) else
         'local x%d:1 = %s;\nlocal y%d:1 = %s;\n%s = ((x%d - y%d) * zext(y%d < x%d)) + ((y%d - x%d) * zext(x%d <= y%d));')
        % (k, A('b', k), k, B('b', k), T('b', k), k, k, k, k, k, k, k, k))))
    # byte sum of a word: add the byte pairs, then the two halfword sums
    ctor(':sumb', 'R0, R7, R14', op('sumb'), lanes('w', lambda k: (
        'local pb%d:4 = (%s & 0x00ff00ff) + ((%s >> 8) & 0x00ff00ff);\n'
        'local pa%d:4 = (%s & 0x00ff00ff) + ((%s >> 8) & 0x00ff00ff);\n'
        '%s = (((pb%d >> 16) + pb%d) << 16) | (((pa%d >> 16) + pa%d) & 0xffff);'
        % (k, B('w', k), B('w', k), k, A('w', k), A('w', k), T('w', k), k, k, k, k))))
    ctor(':xsbh', 'R0, R7', op('xsbh'), lanes('h', lambda k: '%s = sext(%s);' % (T('h', k), A('b', 2 * k + 1))))
    ctor(':xshw', 'R0, R7', op('xshw'), lanes('w', lambda k: '%s = sext(%s);' % (T('w', k), A('h', 2 * k + 1))))
    ctor(':xswd', 'R0, R7', op('xswd'), lanes('d', lambda k: '%s = sext(%s);' % (T('d', k), A('w', 2 * k + 1))))

    # ---- logical
    for mn, e in (('and', 'R7 & R14'), ('andc', 'R7 & ~R14'), ('or', 'R7 | R14'), ('orc', 'R7 | ~R14'),
                  ('xor', 'R7 ^ R14'), ('nand', '~(R7 & R14)'), ('nor', '~(R7 | R14)'), ('eqv', '~(R7 ^ R14)')):
        ctor(':' + mn, 'R0, R7, R14', op(mn), 'R0 = %s;' % e)
    for base, o in (('and', '&'), ('or', '|'), ('xor', '^')):
        for suf, m, rep in (('bi', 0xff, 0x0101010101010101), ('hi', 0xffff, 0x0001000100010001),
                            ('i', 0xffffffff, 0x0000000100000001)):
            ctor(':' + base + suf, 'R0, R7, i10', op(base + suf),
                 'R0d0 = R7d0 %s rep;\nR0d1 = R7d1 %s rep;' % (o, o), 'rep = (i10 & %#x) * %#x;' % (m, rep))
    ctor(':orx', 'R0, R7', op('orx'), 'local s:4 = R7w0 | R7w1 | R7w2 | R7w3;\nR0w0 = s;\n' + zero_rest(T))
    ctor(':selb', 'R21, R7, R14, R0', op('selb'), 'R21 = (R0 & R14) | (~R0 & R7);')
    sh = ['local a:16 = R7;', 'local b:16 = R14;', 'local c:16 = R0;']
    for j in range(16):
        if alt(j):
            sh += ['local c%d:1 = c(%d);' % (j, 15 - j),
                   'local x%d:1 = (c%d << 3) >> 3;' % (j, j),
                   'local n%d:1 = (~x%d & 15) << 3;' % (j, j),
                   'local ta%d:16 = a >> n%d;' % (j, j),
                   'local tb%d:16 = b >> n%d;' % (j, j),
                   'local sa%d:1 = ta%d:1;' % (j, j),
                   'local sb%d:1 = tb%d:1;' % (j, j),
                   'local v%d:1 = ((sa%d * zext((x%d & 0x10) == 0)) + (sb%d * zext((x%d & 0x10) != 0))) * zext((c%d & 0x80) == 0);'
                   % (j, j, j, j, j, j),
                   '%s = v%d + (0xff * zext((c%d >> 5) == 6)) + (0x80 * zext((c%d >> 5) == 7));' % (C('b', j), j, j, j)]
            continue
        sh += ['local c%d:1 = c(%d);' % (j, 15 - j),
               'local x%d:1 = c%d & 0x1f;' % (j, j),
               'local n%d:1 = (15 - (x%d & 15)) * 8;' % (j, j),
               'local ta%d:16 = a >> n%d;' % (j, j),
               'local tb%d:16 = b >> n%d;' % (j, j),
               'local sa%d:1 = ta%d:1;' % (j, j),
               'local sb%d:1 = tb%d:1;' % (j, j),
               'local v%d:1 = ((sa%d * zext(x%d < 16)) | (sb%d * zext(x%d > 15))) * zext(c%d < 0x80);' % (j, j, j, j, j, j),
               '%s = v%d | (0xff * zext((c%d & 0xe0) == 0xc0)) | (0x80 * zext((c%d & 0xe0) == 0xe0));' % (C('b', j), j, j, j)]
    ctor(':shufb', 'R21, R7, R14, R0', op('shufb'), '\n'.join(sh))

    # ---- shifts and rotates
    def shrot(mn, kind, bits, how, amt_rr, amt_imm=None, imm_mn=None):
        mask = {'h': 0x1f, 'w': 0x3f}[kind] if how in ('shl', 'rotm', 'rotma') else bits - 1
        def body(amt):
            def lane(k):
                t, a = T(kind, k), A(kind, k)
                s = amt(k)
                if how == 'shl':
                    return '%s = %s << (%s);' % (t, a, s)
                if how == 'rot':
                    return 'local s%d:%d = %s;\n%s = (%s << s%d) | (%s >> (%d - s%d));' % (k, LANES[kind][0], s, t, a, k, a, bits, k)
                if how == 'rotm':
                    return '%s = %s >> (%s);' % (t, a, s)
                return '%s = %s s>> (%s);' % (t, a, s)
            return lanes(kind, lane)
        if how in ('shl', 'rot'):
            ctor(':' + mn, 'R0, R7, R14', op(mn), body(lambda k: '%s & %#x' % (B(kind, k), mask)))
            sc = 'sch' if kind == 'h' else 'sc'
            ctor(':' + imm_mn, 'R0, R7, i7', op(imm_mn), body(lambda k: sc), '%s = i7 & %#x;' % (sc, mask))
        else:
            ctor(':' + mn, 'R0, R7, R14', op(mn), body(lambda k: '(0 - %s) & %#x' % (B(kind, k), mask)))
            sc = 'sch' if kind == 'h' else 'sc'
            ctor(':' + imm_mn, 'R0, R7, i7', op(imm_mn), body(lambda k: sc), '%s = (0 - i7) & %#x;' % (sc, mask))
    shrot('shlh', 'h', 16, 'shl', None, imm_mn='shlhi')
    shrot('shl', 'w', 32, 'shl', None, imm_mn='shli')
    shrot('roth', 'h', 16, 'rot', None, imm_mn='rothi')
    shrot('rot', 'w', 32, 'rot', None, imm_mn='roti')
    shrot('rothm', 'h', 16, 'rotm', None, imm_mn='rothmi')
    shrot('rotm', 'w', 32, 'rotm', None, imm_mn='rotmi')
    shrot('rotmah', 'h', 16, 'rotma', None, imm_mn='rotmahi')
    shrot('rotma', 'w', 32, 'rotma', None, imm_mn='rotmai')
    # quadword
    def quad(mn, amt, how, disp='R0, R7, R14', action=None):
        lines = ['local s:4 = %s;' % amt]
        if how == 'rotby':
            lines.append('R0 = (R7 << (s * 8)) | (R7 >> ((16 - s) * 8));')
        elif how == 'rotbi':
            lines.append('R0 = (R7 << s) | (R7 >> (128 - s));')
        elif how == 'shrby':
            lines.append('R0 = R7 >> (s * 8);')
        elif how == 'shrbi':
            lines.append('R0 = R7 >> s;')
        elif how == 'shlby':
            lines.append('R0 = R7 << (s * 8);')
        elif how == 'shlbi':
            lines.append('R0 = R7 << s;')
        ctor(':' + mn, disp, op(mn), '\n'.join(lines), action)
    quad('rotqby', 'R14w0 & 0xf', 'rotby')
    quad('rotqbyi', 'sc', 'rotby', 'R0, R7, i7', 'sc = i7 & 0xf;')
    quad('rotqbybi', '(R14w0 >> 3) & 0xf', 'rotby')
    quad('rotqbi', 'R14w0 & 7', 'rotbi')
    quad('rotqbii', 'sc', 'rotbi', 'R0, R7, i7', 'sc = i7 & 7;')
    quad('rotqmby', '(0 - R14w0) & 0x1f', 'shrby')
    quad('rotqmbyi', 'sc', 'shrby', 'R0, R7, i7', 'sc = (0 - i7) & 0x1f;')
    quad('rotqmbybi', '(0 - ((R14w0 >> 3) & 0x1f)) & 0x1f', 'shrby')
    quad('rotqmbi', '(0 - R14w0) & 7', 'shrbi')
    quad('rotqmbii', 'sc', 'shrbi', 'R0, R7, i7', 'sc = (0 - i7) & 7;')
    quad('shlqby', 'R14w0 & 0x1f', 'shlby')
    quad('shlqbyi', 'sc', 'shlby', 'R0, R7, i7', 'sc = i7 & 0x1f;')
    quad('shlqbybi', '(R14w0 >> 3) & 0x1f', 'shlby')
    quad('shlqbi', 'R14w0 & 7', 'shlbi')
    quad('shlqbii', 'sc', 'shlbi', 'R0, R7, i7', 'sc = i7 & 7;')

    # ---- compares
    for base, opr in (('ceq', '=='), ('cgt', 's>'), ('clgt', '>')):
        for suf, kind in (('b', 'b'), ('h', 'h'), ('', 'w')):
            if kind == 'b':
                neg = {'==': '!=', 's>': 's<=', '>': '<='}[opr]
                for mn, rhs, disp in ((base + suf, '%s', 'R0, R7, R14'), (base + suf + 'i', 'i10', 'R0, R7, i10')):
                    ctor(':' + mn, disp, op(mn), lanes('b', lambda k: (
                        '%s = zext(%s %s %s) - 1;' % (T('b', k), A('b', k), neg, rhs % B('b', k) if '%' in rhs else rhs)
                        if alt(k) else
                        '%s = 0 - zext(%s %s %s);' % (T('b', k), A('b', k), opr, rhs % B('b', k) if '%' in rhs else rhs))))
                continue
            rr3(base + suf, kind, '{t} = 0 - zext({a} %s {b});' % opr)
            ri10(base + suf + 'i', kind, '{t} = 0 - zext({a} %s i10);' % opr)

    # ---- halt
    for mn, opr in (('heq', '=='), ('hgt', 's>'), ('hlgt', '>')):
        ctor(':' + mn, 'R0, R7, R14', op(mn), 'if (!(R7w0 %s R14w0)) goto inst_next;\nspu_halt();' % opr)
        ctor(':' + mn + 'i', 'R0, R7, i10', op(mn + 'i'), 'if (!(R7w0 %s i10)) goto inst_next;\nspu_halt();' % opr)

    # ---- branches
    def link(f=T):
        return '%s = inst_next;\n%s' % (f('w', 0), zero_rest(f))
    ctor(':br', 'REL16', op('br'), 'goto REL16;')
    ctor(':bra', 'ABS16', op('bra'), 'goto ABS16;')
    ctor(':brsl', 'R0, REL16', op('brsl') + ' & i16=1', link() + '\ngoto REL16;')
    ctor(':brsl', 'R0, REL16', op('brsl'), link() + '\ncall REL16;')
    ctor(':brasl', 'R0, ABS16', op('brasl'), link() + '\ncall ABS16;')
    for mn, cond in (('brz', 'R0w0 == 0'), ('brnz', 'R0w0 != 0'), ('brhz', 'R0h1 == 0'), ('brhnz', 'R0h1 != 0')):
        ctor(':' + mn, 'R0, REL16', op(mn), 'if (%s) goto REL16;' % cond)
    ctor(':bi^FB', 'R7', op('bi') + ' & ra_raw=0', 'local ea:4 = lr_w0 & %#x;\nbuild FB;\nreturn [ea];' % IMASK)
    ctor(':bi^FB', 'R7', op('bi'), 'local ea:4 = R7w0 & %#x;\nbuild FB;\ngoto [ea];' % IMASK)
    ctor(':bisl^FB', 'R0, R7', op('bisl'), 'local ea:4 = R7w0 & %#x;\n%s\nbuild FB;\ncall [ea];' % (IMASK, link()))
    ctor(':iret^FB', 'R7', op('iret'), 'build FB;\nreturn [SRR0];')
    ctor(':bisled^FB', 'R0, R7', op('bisled'),
         'local ea:4 = R7w0 & %#x;\n%s\nif (SPU_RdEventStat_cnt == 0) goto inst_next;\nbuild FB;\ncall [ea];' % (IMASK, link()))
    for mn, cond in (('biz', 'R0w0 == 0'), ('binz', 'R0w0 != 0'), ('bihz', 'R0h1 == 0'), ('bihnz', 'R0h1 != 0')):
        ctor(':%s^FB' % mn, 'R0, R7', op(mn) + ' & ra_raw=0',
             'local ea:4 = lr_w0 & %#x;\nif (!(%s)) goto inst_next;\nbuild FB;\nreturn [ea];' % (IMASK, cond))
        ctor(':%s^FB' % mn, 'R0, R7', op(mn),
             'local ea:4 = R7w0 & %#x;\nif (!(%s)) goto inst_next;\nbuild FB;\ngoto [ea];' % (IMASK, cond))
    # hints: no architectural effect
    ctor(':hbr^HP', 'BRI9B, R7', op('hbr'), '')
    ctor(':hbra', 'BRI9A, ABS16', op('hbra'), '')
    ctor(':hbrr', 'BRI9A, REL16', op('hbrr'), '')

    # ---- control
    ctor(':stop', 'u14', op('stop'), 'spu_stop(u14:2);')
    ctor(':stopd', 'R0, R7, R14', op('stopd'), 'spu_stopd();')
    ctor(':lnop', '', op('lnop'), '')
    ctor(':nop', 'R0', op('nop'), '')
    ctor(':sync^SYNCF', '', op('sync'), '')
    ctor(':dsync', '', op('dsync'), '')
    ctor(':mfspr', 'R0, sa', op('mfspr'), 'R0w0 = sa;\n' + zero_rest(T))
    ctor(':mtspr', 'sa, R0', op('mtspr'), 'sa = R0w0;')
    ctor(':rdch', 'R0, ca', op('rdch') + ' & ra_raw=15', 'R0w0 = SRR0;\n' + zero_rest(T))
    ctor(':rdch', 'R0, ca', op('rdch'), 'R0w0 = ca;\n' + zero_rest(T))
    ctor(':rchcnt', 'R0, ca', op('rchcnt') + ' & cac', 'R0w0 = cac;\n' + zero_rest(T))
    ctor(':wrch', 'ca, R0', op('wrch') + ' & ra_raw=14', 'SRR0 = R0w0;')
    ctor(':wrch', 'ca, R0', op('wrch'), 'ca = R0w0;')

    # ---- single precision (extended range)
    for mn, kind in (('fa', 'add'), ('fs', 'sub'), ('fm', 'mul')):
        ctor(':' + mn, 'R0, R7, R14', op(mn), sp_arith(kind, T, A, B))
    for mn, kind in (('fma', 'fma'), ('fms', 'fms'), ('fnms', 'fnms')):
        ctor(':' + mn, 'R21, R7, R14, R0', op(mn), sp_arith(kind, C, A, B, T))
    # floating interpolate: RT = (-1)^S (1.BaseFraction - 0.000StepFraction * 0.RA[13:31]) 2^(E-127)
    lines = []
    for k in range(4):
        n = 'f%d' % k
        b = B('w', k)
        lines += ['local %sbe:4 = (%s >> 23) & 0xff;' % (n, b),
                  'local %sn:8 = (zext(((%s >> 10) & 0x1fff) + 0x2000) << 19) - (zext(%s & 0x3ff) * zext(%s & 0x7ffff));'
                  % (n, b, b, A('w', k)),
                  'local %snd:8 = int2float(%sn);' % (n, n),
                  'local %ssc:8 = zext(%sbe + 864) << 52;' % (n, n),
                  'local %sr:8 = (%snd f* %ssc) | (zext(%s & 0x80000000) << 32);' % (n, n, n, b)]
        lines += d2sp(n + 'r', n + 'o')
        lines.append('local %sdf:1 = (%sbe == 0xff) || %somx || %souf;' % (n, n, n, n))
    for k in range(4):
        n = 'f%d' % k
        lines += ['%s = %so;' % (T('w', k), n), sp_flags(k, n + 'oov', n + 'ouf', n + 'df')]
    ctor(':fi', 'R0, R7, R14', op('fi'), '\n'.join(lines))
    # estimates: the hardware table is implementation-specific; this model returns the exact
    # reciprocal (square root) truncated to the 13-bit base fraction with a zero step.
    for mn in ('frest', 'frsqest'):
        lines = []
        for k in range(4):
            n = 'f%d' % k
            a = A('w', k)
            lines += sp2d(a, n + 'a')
            if mn == 'frest':
                lines.append('local %sq:8 = 0x3ff0000000000000 f/ %sa;' % (n, n))
                sign = '(%s & 0x80000000)' % a
            else:
                lines.append('local %sq:8 = 0x3ff0000000000000 f/ sqrt(abs(%sa));' % (n, n))
                sign = '0'
            lines += d2sp(n + 'q', n + 'o')
            lines.append('local %sz:1 = %sae == 0;' % (n, n))
            lines.append('local %sv:4 = ((%so & 0xfffffc00) * zext(!%sz)) | ((%s | 0x7fffffff) * zext(%sz));'
                         % (n, n, n, sign, n))
        for k in range(4):
            n = 'f%d' % k
            lines += ['%s = %sv;' % (T('w', k), n),
                      'FPSCR3 = FPSCR3 | (zext(%sz) << %d);' % (n, 11 - k)]
        ctor(':' + mn, 'R0, R7', op(mn), '\n'.join(lines))
    # compares: zero exponent compares as zero
    def fcmp(mn, expr):
        lines = []
        for k in range(4):
            a, b = A('w', k), B('w', k)
            lines += ['local za%d:1 = (%s & 0x7f800000) == 0;' % (k, a),
                      'local zb%d:1 = (%s & 0x7f800000) == 0;' % (k, b),
                      'local ma%d:4 = (%s & 0x7fffffff) * zext(!za%d);' % (k, a, k),
                      'local mb%d:4 = (%s & 0x7fffffff) * zext(!zb%d);' % (k, b, k),
                      'local ka%d:4 = (ma%d ^ (0 - (%s >> 31))) + (%s >> 31);' % (k, k, a, a),
                      'local kb%d:4 = (mb%d ^ (0 - (%s >> 31))) + (%s >> 31);' % (k, k, b, b)]
        for k in range(4):
            lines.append('%s = 0 - zext(%s);' % (T('w', k), expr.format(k=k)))
        ctor(':' + mn, 'R0, R7, R14', op(mn), '\n'.join(lines))
    fcmp('fceq', 'ka{k} == kb{k}')
    fcmp('fcmeq', 'ma{k} == mb{k}')
    fcmp('fcgt', 'ka{k} s> kb{k}')
    fcmp('fcmgt', 'ma{k} > mb{k}')
    # conversions; scale = 173 - I8 (to integer) or 155 - I8 (to float)
    for mn, signed in (('csflt', True), ('cuflt', False)):
        lines = []
        for k in range(4):
            n = 'f%d' % k
            lines += ['local %si:8 = %s(%s);' % (n, 'sext' if signed else 'zext', A('w', k)),
                      'local %sr:8 = int2float(%si) f* scd;' % (n, n)]
            lines += d2sp(n + 'r', n + 'o')
            lines.append('local %sdf:1 = %somx || %souf;' % (n, n, n))
        for k in range(4):
            n = 'f%d' % k
            lines += ['%s = %so;' % (T('w', k), n), sp_flags(k, n + 'oov', n + 'ouf', n + 'df')]
        ctor(':' + mn, 'R0, R7, scale', op(mn), '\n'.join(lines),
             'scale = 155 - u8; scd = ((1023 - (155 - u8)) & 0x7ff) << 52;')
    for mn, signed in (('cflts', True), ('cfltu', False)):
        lines = []
        for k in range(4):
            n = 'f%d' % k
            lines += sp2d(A('w', k), n + 'a')
            lines.append('local %sd:8 = %sa f* scd;' % (n, n))
            if signed:
                lines += ['local %shi:1 = %sd f>= 0x41e0000000000000;' % (n, n),
                          'local %slo:1 = %sd f< 0xc1e0000000000000;' % (n, n),
                          'local %ssafe:8 = %sd * zext(!%shi && !%slo);' % (n, n, n, n),
                          'local %st:8 = trunc(%ssafe);' % (n, n),
                          'local %sv:4 = %st:4 | (0x7fffffff * zext(%shi)) | (0x80000000 * zext(%slo));' % (n, n, n, n)]
            else:
                lines += ['local %shi:1 = %sd f>= 0x41f0000000000000;' % (n, n),
                          'local %slo:1 = %sd f< 0;' % (n, n),
                          'local %ssafe:8 = %sd * zext(!%shi && !%slo);' % (n, n, n, n),
                          'local %st:8 = trunc(%ssafe);' % (n, n),
                          'local %sv:4 = %st:4 | (0xffffffff * zext(%shi));' % (n, n, n)]
        for k in range(4):
            lines.append('%s = f%dv;' % (T('w', k), k))
        ctor(':' + mn, 'R0, R7, scale', op(mn), '\n'.join(lines),
             'scale = 173 - u8; scd = ((1023 + (173 - u8)) & 0x7ff) << 52;')
    lines = []
    for k in range(2):
        n = 'e%d' % k
        lines += dclass(A('w', 2 * k), n + 'a', 4)
        lines += ['local %sd:8 = float2float(%sax);' % (n, n),
                  'FPSCR%d = FPSCR%d | (zext(%sasnan) << 10) | (zext(%sanan) << 9);' % (1 + k, 1 + k, n, n)]
    lines += ['R0d0 = e0d;', 'R0d1 = e1d;']
    ctor(':fesd', 'R0, R7', op('fesd'), '\n'.join(lines))
    lines = []
    for k in range(2):
        n = 'e%d' % k
        lines += dclass(A('d', k), n + 'a')
        lines += ['local %ss:4 = float2float(%sax);' % (n, n),
                  'local %ser:8 = %sax f- float2float(%ss);' % (n, n, n)]
        lines += dflags(k, [n + 'a'], n + 's', n + 'er', 4, 0x00800000)
    lines += ['R0w0 = e0s;', 'R0w1 = 0;', 'R0w2 = e1s;', 'R0w3 = 0;']
    ctor(':frds', 'R0, R7', op('frds'), '\n'.join(lines))
    ctor(':fscrrd', 'R0', op('fscrrd'), 'R0w0 = FPSCR0 & 0xf07;\nR0w1 = FPSCR1 & 0x3f07;\nR0w2 = FPSCR2 & 0x3f07;\nR0w3 = FPSCR3 & 0xf07;')
    ctor(':fscrwr', 'R0, R7', op('fscrwr'), 'FPSCR0 = R7w0 & 0xf07;\nFPSCR1 = R7w1 & 0x3f07;\nFPSCR2 = R7w2 & 0x3f07;\nFPSCR3 = R7w3 & 0xf07;')

    # ---- double precision (IEEE, round to nearest; FPSCR exception flags per slot)
    for mn in ('dfa', 'dfs', 'dfm'):
        lines = []
        for k in range(2):
            n = 'd%d' % k
            a, b = A('d', k), B('d', k)
            lines += dclass(a, n + 'a') + dclass(b, n + 'b')
            if mn == 'dfm':
                lines += ['local %sp:16 = float2float(%sax) f* float2float(%sbx);' % (n, n, n),
                          'local %ss:8 = float2float(%sp);' % (n, n),
                          'local %ser:16 = %sp f- float2float(%ss);' % (n, n, n)]
            else:
                y = n + 'bx' if mn == 'dfa' else n + 'nb'
                if mn == 'dfs':
                    lines.append('local %snb:8 = %sbx ^ 0x8000000000000000;' % (n, n))
                lines += ['local %ss:8 = %sax f+ %s;' % (n, n, y),
                          'local %sbb:8 = %ss f- %sax;' % (n, n, n),
                          'local %ser:8 = (%sax f- (%ss f- %sbb)) f+ (%s f- %sbb);' % (n, n, n, n, y, n)]
            lines += dflags(k, [n + 'a', n + 'b'], n + 's', n + 'er')
        for k in range(2):
            lines.append('%s = d%ds;' % (T('d', k), k))
        ctor(':' + mn, 'R0, R7, R14', op(mn), '\n'.join(lines))
    # fused multiply-add: exact product in binary128, correctly rounded once to double
    for mn, sgnp, sgnt in (('dfma', '', ''), ('dfms', '', '-'), ('dfnms', '-', ''), ('dfnma', '-', '-')):
        lines = []
        for k in range(2):
            t, a, b = T('d', k), A('d', k), B('d', k)
            n = 'q%d' % k
            lines += dclass(a, n + 'ia') + dclass(b, n + 'ib') + dclass(t, n + 'ic')
            lines += ['local %sa:16 = float2float(%siax);' % (n, n),
                      'local %sb:16 = float2float(%sibx);' % (n, n),
                      'local %sc:16 = float2float(%sicx);' % (n, n),
                      'local %sp:16 = %sa f* %sb;' % (n, n, n)]
            if sgnp:
                lines.append('%sp = f- %sp;' % (n, n))
            if sgnt:
                lines.append('%sc = f- %sc;' % (n, n))
            lines += ['local %ss:16 = %sp f+ %sc;' % (n, n, n),
                      'local %sbb:16 = %ss f- %sp;' % (n, n, n),
                      'local %ser:16 = (%sp f- (%ss f- %sbb)) f+ (%sc f- %sbb);' % (n, n, n, n, n, n),
                      # a binary128 sum exactly halfway between doubles with a nonzero remainder would
                      # round the wrong way: move it one binary128 ulp toward the remainder
                      'local %smid:1 = (%ss:8 & 0x0fffffffffffffff) == 0x0800000000000000;' % (n, n),
                      'local %sup:1 = %smid && (%ser f!= 0) && ((%ser f< 0) == (%ss f< 0));' % (n, n, n, n, n),
                      'local %sdn:1 = %smid && (%ser f!= 0) && ((%ser f< 0) != (%ss f< 0));' % (n, n, n, n, n),
                      '%ss = %ss + zext(%sup) - zext(%sdn);' % (n, n, n, n),
                      'local %sr:8 = float2float(%ss);' % (n, n),
                      'local %ste:16 = (%ss f- float2float(%sr)) f+ %ser;' % (n, n, n, n)]
            lines += dflags(k, [n + 'ia', n + 'ib', n + 'ic'], n + 'r', n + 'te')
        for k in range(2):
            lines.append('%s = q%dr;' % (T('d', k), k))
        ctor(':' + mn, 'R0, R7, R14', op(mn), '\n'.join(lines))
    rr3('dfceq', 'd', '{t} = 0 - zext({a} f== {b});')
    rr3('dfcgt', 'd', '{t} = 0 - zext({b} f< {a});')
    rr3('dfcmeq', 'd', '{t} = 0 - zext(abs({a}) f== abs({b}));')
    rr3('dfcmgt', 'd', '{t} = 0 - zext(abs({b}) f< abs({a}));')
    lines = ['local en:1 = u7;']
    for k in range(2):
        a = A('d', k)
        lines += ['local x%d:8 = %s;' % (k, a),
                  'local ex%d:8 = (x%d >> 52) & 0x7ff;' % (k, k),
                  'local fr%d:8 = x%d & 0xfffffffffffff;' % (k, k),
                  'local ng%d:1 = (x%d >> 63) != 0;' % (k, k),
                  'local hit%d:1 = ((ex%d == 0x7ff) && (fr%d != 0) && (en & 0x40) != 0)' % (k, k, k)
                  + ' || ((ex%d == 0x7ff) && (fr%d == 0) && !ng%d && (en & 0x20) != 0)' % (k, k, k)
                  + ' || ((ex%d == 0x7ff) && (fr%d == 0) && ng%d && (en & 0x10) != 0)' % (k, k, k)
                  + ' || ((ex%d == 0) && (fr%d == 0) && !ng%d && (en & 0x08) != 0)' % (k, k, k)
                  + ' || ((ex%d == 0) && (fr%d == 0) && ng%d && (en & 0x04) != 0)' % (k, k, k)
                  + ' || ((ex%d == 0) && (fr%d != 0) && !ng%d && (en & 0x02) != 0)' % (k, k, k)
                  + ' || ((ex%d == 0) && (fr%d != 0) && ng%d && (en & 0x01) != 0);' % (k, k, k)]
    for k in range(2):
        lines.append('%s = 0 - zext(hit%d);' % (T('d', k), k))
    ctor(':dftsv', 'R0, R7, i7', op('dftsv'), '\n'.join(lines))


def main():
    check_decode()
    header()
    operand_tables()
    n = len(out)
    instructions()
    out[n:n] = ['# decode-time constants'] + ktext + ['']
    sys.stdout.write('\n'.join(out) + '\n')


if __name__ == '__main__':
    main()
