#!/usr/bin/env python3
"""P-code semantic tests for the SPU module, run in Ghidra's emulator by EmuCheck.java.

  emu_tests.py <outdir> [--break NAME]  -> emu.s, emu.bin (spu-elf-as / ld at address 0), emu.txt

Each test is a short instruction sequence at its own label; the emulator starts there and must
reach the end label.  emu.txt has one line per test:
  <name> <start-hex> <stop-hex> <init: key=val,...|-> <expect: key=val,...>
Keys are register names (quads lr, sp, r2..r127; lane views r3_w0, r3_d1, r3_h1, r3_b15; FPSCR,
SRR0, IE, channel registers) or m<N>:<addr> for N bytes of memory.  Values are hex; '@label'
values are resolved to the label's address.  Before every test all quads are 0, sp holds
0x3ff00 in its preferred slot, FPSCR and IE are 0.
Expected values were worked out by hand from the SPU ISA v1.2 (comments show the arithmetic).
--break NAME makes that test's first expectation wrong, to show the harness can fail.
Environment: SPU_AS, SPU_LD, SPU_OBJCOPY, SPU_NM (default spu-elf-as/-ld/-objcopy/-nm).
"""
import os
import re
import subprocess
import sys

M32 = 0xffffffff


def Q(w0, w1=0, w2=0, w3=0):
    return ((w0 & M32) << 96) | ((w1 & M32) << 64) | ((w2 & M32) << 32) | (w3 & M32)


def D(d0, d1=0):
    return (d0 << 64) | d1


ONE = 0x3f800000
TESTS = [
    # --- constant formation
    ("immediates", ["il $3,-2", "ilhu $4,0x1234", "iohl $4,0x5678", "ila $5,0x3ffff",
                    "ilh $6,0xabcd", "fsmbi $7,0x8001"], {},
     {"r3": Q(0xfffffffe, 0xfffffffe, 0xfffffffe, 0xfffffffe), "r4_w2": 0x12345678,
      "r5_w3": 0x3ffff, "r6_w1": 0xabcdabcd, "r7": Q(0xff000000, 0, 0, 0xff)}),
    # --- word and halfword add/subtract (each slot independent)
    ("add_sub", ["a $3,$10,$11", "sf $4,$10,$11", "ai $5,$10,-1", "sfi $6,$10,0", "ah $7,$10,$11"],
     {"r10": Q(1, 2, M32, 0x80000000), "r11": Q(5, 6, 1, 0x80000000)},
     {"r3": Q(6, 8, 0, 0), "r4": Q(4, 4, 2, 0), "r5": Q(0, 1, 0xfffffffe, 0x7fffffff),
      "r6": Q(M32, 0xfffffffe, 1, 0x80000000),
      # halves (0,1)+(0,5), (0,2)+(0,6), (ffff,ffff)+(0,1), (8000,0)+(8000,0)
      "r7": Q(6, 8, 0xffff0000, 0)}),
    # --- carry/borrow generate and extended add/subtract (carry-in = bit 31 of RT)
    ("carry_borrow", ["cg $3,$10,$11", "bg $4,$10,$11", "addx $12,$10,$11", "cgx $13,$10,$11",
                      "sfx $14,$10,$11", "bgx $15,$10,$11"],
     {"r10": Q(1, 2, M32, 0x80000000), "r11": Q(5, 6, 1, 0x80000000),
      "r12": Q(1, 0, 1, 0), "r13": Q(1, 0, 1, 0), "r14": Q(1, 0, 0, 1), "r15": Q(1, 0, 1, 0)},
     {"r3": Q(0, 0, 1, 1),            # carries of 1+5, 2+6, ffffffff+1, 80000000+80000000
      "r4": Q(1, 1, 0, 1),            # RB >= RA (unsigned)
      "r12": Q(7, 8, 1, 0),           # RA+RB+c: ffffffff+1+1 = 1_00000001
      "r13": Q(0, 0, 1, 1),
      "r14": Q(4, 3, 1, 0),           # RB + ~RA + c: 5-1, 6-2-1, 1+0, 80000000+7fffffff+1
      "r15": Q(1, 1, 0, 0)}),         # c=1: RB>=RA, c=0: RB>RA
    # --- 16x16 multiplies: hi = bits 0-15 of the word, lo = bits 16-31
    ("multiply", ["mpy $3,$10,$11", "mpyu $4,$10,$11", "mpyh $5,$10,$11", "mpyhh $6,$10,$11",
                  "mpyi $7,$10,-3", "mpys $8,$10,$11", "mpya $20,$10,$11,$12", "mpyhhu $9,$10,$11"],
     {"r10": Q(0x0002fffe, 0x00010003, 0x7fff8000, 0xffff0004),
      "r11": Q(0x00030005, 0xfffffffd, 0x00028000, 0x00100010), "r12": Q(10, 10, 10, 10)},
     {"r3": Q(0xfffffff6, 0xfffffff7, 0x40000000, 0x40),     # -2*5, 3*-3, -32768*-32768, 4*16
      "r4": Q(0x4fff6, 0x2fff7, 0x40000000, 0x40),           # unsigned
      "r5": Q(0xa0000, 0xfffd0000, 0x80000000, 0xfff00000),  # (hi(a)*lo(b)) << 16
      "r6": Q(6, M32, 0xfffe, 0xfffffff0),                   # signed hi*hi
      "r7": Q(6, 0xfffffff7, 0x18000, 0xfffffff4),           # lo(a) * -3
      "r8": Q(M32, M32, 0x4000, 0),                          # (lo*lo) >> 16 arithmetic
      "r20": Q(0, 1, 0x4000000a, 0x4a),                      # lo*lo + RC
      "r9": Q(6, 0xffff, 0xfffe, 0xffff0)}),                 # unsigned hi*hi
    # --- logical, including the byte/halfword/word immediate forms
    ("logic", ["and $3,$10,$11", "or $4,$10,$11", "xor $5,$10,$11", "andc $6,$10,$11",
               "nor $7,$10,$11", "andbi $8,$10,0x3c", "orhi $9,$10,-16", "xori $12,$10,0x1ff",
               "eqv $13,$10,$11", "orc $14,$10,$11"],
     {"r10": Q(0xff00ff00, 0x0f0f0f0f, 0x12345678, 0), "r11": Q(0x0ff00ff0, 0xffff0000, M32, 1)},
     {"r3": Q(0x0f000f00, 0x0f0f0000, 0x12345678, 0),
      "r4": Q(0xfff0fff0, 0xffff0f0f, M32, 1),
      "r5": Q(0xf0f0f0f0, 0xf0f00f0f, 0xedcba987, 1),
      "r6": Q(0xf000f000, 0x00000f0f, 0, 0),
      "r7": Q(0x000f000f, 0x0000f0f0, 0, 0xfffffffe),
      "r8": Q(0x3c003c00, 0x0c0c0c0c, 0x10341438, 0),        # each byte & 0x3c
      "r9": Q(0xfff0fff0, M32, 0xfff4fff8, 0xfff0fff0),      # each halfword | 0xfff0
      "r12": Q(0xff00feff, 0x0f0f0ef0, 0x12345787, 0x1ff),   # each word ^ 0x1ff
      "r13": Q(0x0f0f0f0f, 0x0f0ff0f0, 0x12345678, 0xfffffffe),
      "r14": Q(0xff0fff0f, 0x0f0fffff, 0x12345678, 0xfffffffe)}),
    # --- select bits and shuffle bytes (all control byte classes)
    ("selb_shufb", ["selb $20,$10,$11,$12", "shufb $21,$10,$11,$13"],
     {"r10": Q(0xff00ff00, 0x0f0f0f0f, 0x12345678, 0), "r11": Q(0x0ff00ff0, 0xffff0000, M32, 1),
      "r12": Q(M32, 0, 0x0000ffff, 0xf0f0f0f0),
      "r13": Q(0x00010203, 0x10111213, 0x80c0e01f, 0x0f1e0a14)},
     {"r20": Q(0x0ff00ff0, 0x0f0f0f0f, 0x1234ffff, 0),
      # a[0..3]; b[0..3]; 80->00, c0->ff, e0->80, 1f->b[15]; a[15], b[14], a[10], b[4]
      "r21": Q(0xff00ff00, 0x0ff00ff0, 0x00ff8001, 0x000056ff)}),
    # --- insertion controls for scalar stores
    ("insert_controls", ["cwd $3,4($4)", "cbd $5,3($4)", "chx $6,$4,$7", "cdd $8,8($4)",
                         "cwx $9,$4,$7"],
     {"r4_w0": 0x100, "r7_w0": 0xa},
     {"r3": Q(0x10111213, 0x00010203, 0x18191a1b, 0x1c1d1e1f),
      "r5": Q(0x10111203, 0x14151617, 0x18191a1b, 0x1c1d1e1f),
      "r6": Q(0x10111213, 0x14151617, 0x18190203, 0x1c1d1e1f),
      "r8": Q(0x10111213, 0x14151617, 0x00010203, 0x04050607),
      "r9": Q(0x10111213, 0x14151617, 0x00010203, 0x1c1d1e1f)}),   # 0x10a & 0xc = 8
    # --- quadword loads and stores: the low 4 address bits are ignored
    ("load_store", ["lqd $3,16($4)", "lqd $6,0($5)", "lqx $7,$4,$8", "stqd $3,32($4)",
                    "stqx $9,$4,$10", "lqa $11,0x1010"],
     {"r4_w0": 0x1000, "r5_w0": 0x1013, "r8_w0": 0x1f, "r10_w0": 0x30,
      "r9": Q(1, 2, 3, 4), "m16:1010": 0x00112233445566778899aabbccddeeff},
     {"r3": 0x00112233445566778899aabbccddeeff, "r6": 0x00112233445566778899aabbccddeeff,
      "r7": 0x00112233445566778899aabbccddeeff, "m16:1020": 0x00112233445566778899aabbccddeeff,
      "m16:1030": Q(1, 2, 3, 4), "r11": 0x00112233445566778899aabbccddeeff}),
    # --- stack-relative access through sp (0x3ff00)
    ("stack_access", ["stqd $10,-16($sp)", "ai $sp,$sp,-32", "lqd $3,16($sp)", "ai $sp,$sp,32"],
     {"r10": Q(0xdead, 0xbeef, 1, 2)},
     {"r3": Q(0xdead, 0xbeef, 1, 2), "m16:3fef0": Q(0xdead, 0xbeef, 1, 2), "sp_w0": 0x3ff00}),
    # --- PC-relative quadword load/store (lqr/stqr) of data in the image
    ("pc_relative", ["lqr $3,qdata", "ai $4,$3,1", "stqr $4,qdata2"], {},
     {"r3": Q(0x11111111, 0x22222222, 0x33333333, 0x44444444),
      "m16:@qdata2": Q(0x11111112, 0x22222223, 0x33333334, 0x44444445)}),
    # --- unaligned scalar load idiom: lqd + rotqby by the address
    ("scalar_load", ["lqd $3,0($4)", "rotqby $3,$3,$4"],
     {"r4_w0": 0x1012, "m16:1010": 0x00112233445566778899aabbccddeeff},
     {"r3_w0": 0x22334455, "r3_w3": 0xeeff0011}),
    # --- quadword rotates and shifts
    ("quad_shifts", ["rotqbyi $3,$10,4", "rotqmbyi $4,$10,-4", "shlqbyi $5,$10,4", "rotqbii $6,$10,4",
                     "rotqmbii $7,$10,-4", "shlqbybi $8,$10,$11", "rotqmby $9,$10,$12",
                     "shlqbi $13,$10,$14", "rotqbybi $15,$10,$11", "rotqmbybi $16,$10,$17"],
     {"r10": Q(0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210), "r11_w0": 0x20,
      "r12_w0": 0xfffffffc, "r14_w0": 0x3, "r17_w0": 0xffffffe0},
     {"r3": Q(0x89abcdef, 0xfedcba98, 0x76543210, 0x01234567),
      "r4": Q(0, 0x01234567, 0x89abcdef, 0xfedcba98),
      "r5": Q(0x89abcdef, 0xfedcba98, 0x76543210, 0),
      "r6": Q(0x12345678, 0x9abcdeff, 0xedcba987, 0x65432100),
      "r7": Q(0x00123456, 0x789abcde, 0xffedcba9, 0x87654321),
      "r8": Q(0x89abcdef, 0xfedcba98, 0x76543210, 0),       # (0x20 >> 3) & 0x1f = 4 bytes
      "r9": Q(0, 0x01234567, 0x89abcdef, 0xfedcba98),       # (0 - -4) & 0x1f = 4 bytes right
      "r13": Q(0x091a2b3c, 0x4d5e6f7f, 0xf6e5d4c3, 0xb2a19080),   # << 3 bits
      "r15": Q(0x89abcdef, 0xfedcba98, 0x76543210, 0x01234567),   # rotate 4 bytes
      "r16": Q(0, 0x01234567, 0x89abcdef, 0xfedcba98)}),          # -(0xffffffe0>>3) & 0x1f = 4
    # --- word/halfword shifts and rotates (counts >= width give 0 or sign fill)
    ("word_shifts", ["shl $3,$10,$11", "rot $4,$10,$11", "rotm $5,$10,$12", "rotma $6,$10,$12",
                     "shlhi $7,$10,4", "rotmahi $8,$10,-4", "roti $9,$10,-1", "rothm $13,$10,$14"],
     {"r10": Q(0x80000001, 0x12345678, M32, 0x00000010), "r11": Q(1, 36, 0, 33),
      "r12": Q(M32, 0xfffffffc, 0xffffffe1, 0xffffffe0), "r14": Q(0xffff0001, 0, 0, 0xfff00010)},
     {"r3": Q(2, 0, M32, 0),
      "r4": Q(3, 0x23456781, M32, 0x20),
      "r5": Q(0x40000000, 0x01234567, 1, 0),
      "r6": Q(0xc0000000, 0x01234567, M32, 0),
      "r7": Q(0x00000010, 0x23406780, 0xfff0fff0, 0x00000100),
      "r8": Q(0xf8000000, 0x01230567, M32, 0x00000001),
      "r9": Q(0xc0000000, 0x091a2b3c, M32, 8),
      # halfwords: 8000>>1, 0001>>(-1&0x1f=31: 0); 1234>>0, 5678>>0; ...; 0000>>16, 0010>>16
      "r13": Q(0x40000000, 0x12345678, M32, 0)}),
    # --- compares
    ("compares", ["ceq $3,$10,$11", "clgt $5,$10,$11", "cgti $6,$10,-6", "ceqbi $7,$10,5",
                  "clgthi $8,$10,4", "cgt $9,$11,$10", "ceqh $12,$10,$11"],
     {"r10": Q(5, 0xfffffffb, 0x80000000, 7), "r11": Q(5, 5, 0x7fffffff, 8)},
     {"r3": Q(M32, 0, 0, 0), "r5": Q(0, M32, M32, 0), "r6": Q(M32, M32, 0, M32),
      "r7": Q(0xff, 0, 0, 0), "r8": Q(0xffff, M32, 0xffff0000, 0xffff),
      "r9": Q(0, M32, M32, M32), "r12": Q(M32, 0, 0, 0xffff0000)}),
    # --- counting, extension, masks and gathers
    ("bit_ops", ["clz $3,$10", "cntb $4,$10", "xswd $5,$10", "xshw $6,$10", "xsbh $7,$10",
                 "orx $8,$10", "gb $9,$10", "gbb $12,$10", "fsm $13,$14", "fsmb $15,$14",
                 "fsmh $16,$14", "gbh $18,$10"],
     {"r10": Q(0x00010000, 0x80000000, 0, 0x0f0f00ff), "r14_w0": 5},
     {"r3": Q(15, 0, 32, 4), "r4": Q(0x00010000, 0x01000000, 0, 0x04040008),
      "r5": Q(M32, 0x80000000, 0, 0x0f0f00ff), "r6": Q(0, 0, 0, 0xff),
      "r7": Q(0x00010000, 0, 0, 0x000fffff), "r8": Q(0x8f0f00ff, 0, 0, 0),
      "r9": Q(1, 0, 0, 0), "r12": Q(0x400d, 0, 0, 0), "r13": Q(0, M32, 0, M32),
      "r15": Q(0, 0, 0, 0x00ff00ff), "r16": Q(0, 0, 0x0000ffff, 0x0000ffff),
      # halfword lsbs: 0001 0000 8000 0000 0000 0000 0f0f 00ff -> 1,0,0,0,0,0,1,1
      "r18": Q(0x83, 0, 0, 0)}),
    ("byte_ops", ["sumb $3,$10,$11", "avgb $4,$10,$11", "absdb $5,$10,$11"],
     {"r10": Q(0x00010000, 0x80000000, 0, 0x0f0f00ff), "r11": Q(0x01020304, M32, 0, 0x10203040)},
     {"r3": Q(0x000a0001, 0x03fc0080, 0, 0x00a0011d),
      "r4": Q(0x01020202, 0xc0808080, 0, 0x101818a0),     # (a + b + 1) >> 1 per byte
      "r5": Q(0x01010304, 0x7fffffff, 0, 0x011130bf)}),   # |a - b| per byte
    # --- branches: relative, conditional on word and halfword preferred slots, indirect
    ("branches", ["il $3,0", "br 1f", "il $3,99", "1: brz $4,2f", "il $3,98",
                  "2: brnz $5,3f", "il $3,97", "3: brhz $6,4f", "il $3,96",
                  "4: brhnz $7,5f", "ai $3,$3,1", "5: ila $8,6f", "bi $8", "il $3,95",
                  "6: biz $4,$9", "il $3,94", "7: ai $3,$3,10"],
     {"r5_w0": 1, "r6_w0": 0xffff0000, "r7_w0": 0x0000ffff, "r9_w0": "@7f"},
     {"r3_w0": 10}),
    ("not_taken", ["il $3,0", "brz $5,1f", "ai $3,$3,1", "1: brhz $7,2f", "ai $3,$3,2",
                   "2: binz $4,$9", "ai $3,$3,4", "brhnz $6,3f", "ai $3,$3,8", "3: nop"],
     {"r5_w0": 1, "r6_w0": 0xffff0000, "r7_w0": 0x0000ffff, "r9_w0": 0},
     {"r3_w0": 15}),
    # --- call and return: brsl/brasl set the link (other slots zero), bi $lr returns
    ("call_return", ["il $3,5", "brsl $lr,cfunc", "ret1: ai $3,$3,1", "ila $10,cfunc",
                     "bisl $lr,$10", "ret2: brasl $11,cfunc2"],
     {"lr": Q(1, 2, 3, 4)},
     {"r3_w0": 26, "lr_w0": "@ret2", "lr_w1": 0, "lr_w2": 0, "lr_w3": 0,
      "r11_w0": "@end_call_return"}),
    # --- hints and no-ops have no architectural effect
    ("hints_nops", ["hbrr 1f,2f", "nop $127", "lnop", "sync", "dsync", "syncc", "1: br 2f",
                    "2: il $3,7"], {}, {"r3_w0": 7}),
    # --- halt conditions not met fall through
    ("halt_not_taken", ["heqi $3,$4,1", "hgt $3,$4,$5", "hlgti $3,$5,-1", "il $6,3"],
     {"r5_w0": 2}, {"r6_w0": 3}),
    # --- channels: data and count registers, SRR0 via SPU_WrSRR0/SPU_RdSRR0
    ("channels", ["wrch $ch28,$3", "rdch $4,$ch29", "rchcnt $5,$ch29", "wrch $ch14,$6",
                  "rdch $7,$ch15", "mtspr $sp5,$3", "mfspr $8,$sp5"],
     {"r3_w0": 0x1234, "r4": Q(9, 9, 9, 9), "SPU_RdInMbox": 0xcafe, "SPU_RdInMbox_cnt": 1,
      "r6_w0": 0x200},
     {"SPU_WrOutMbox": 0x1234, "r4": Q(0xcafe, 0, 0, 0), "r5": Q(1, 0, 0, 0), "SRR0": 0x200,
      "r7": Q(0x200, 0, 0, 0), "r8": Q(0x1234, 0, 0, 0)}),
    # --- interrupt return to SRR0 with the enable feature bit; bid disables
    ("iret_interrupts", ["ila $3,1f", "wrch $ch14,$3", "irete", "il $4,1", "1: ila $5,2f", "bid $5",
                         "il $4,2", "2: il $6,6"],
     {}, {"r4_w0": 0, "r6_w0": 6, "IE": 0, "SRR0": "@1f"}),
    ("bisled_event", ["ila $3,1f", "bisled $lr,$3", "il $4,1", "1: il $5,5"],
     {"SPU_RdEventStat_cnt": 1}, {"r4_w0": 0, "r5_w0": 5}),
    # --- single precision: truncation, extended range, denormals as zero, FPSCR flags
    ("sp_truncation", ["fa $3,$10,$11", "fs $4,$10,$12", "fm $5,$13,$14", "fma $6,$10,$10,$15"],
     {"r10_w0": ONE, "r11_w0": 0x33c00000,   # 1.0 + 0.75 ulp -> 1.0 (IEEE rounds up)
      "r12_w0": 0x2b800000,                  # 1.0 - 2^-40 -> 0x3f7fffff
      "r13_w0": 0x3fc00000, "r14_w0": 0x3f800001,   # 1.5 * (1 + 2^-23) = 1.5 + 1.5 ulp
      "r15_w0": 0xa1800000},                 # 1.0*1.0 - 2^-60 -> 0x3f7fffff
     {"r3_w0": ONE, "r4_w0": 0x3f7fffff, "r5_w0": 0x3fc00001, "r6_w0": 0x3f7fffff}),
    ("sp_extended_range", ["fm $3,$10,$11", "fm $4,$10,$12", "fm $5,$13,$14", "fm $6,$15,$16",
                           "fscrrd $7", "fscrwr $0,$8", "fscrrd $9"],
     {"r10": Q(0x7f000000), "r11": Q(0x40000000), "r12": Q(0x40800000),
      "r13": Q(0, 0x0d800000), "r14": Q(0, 0x30800000),   # 2^-100 * 2^-30 underflows
      "r15": Q(0, 0, 0x00400000), "r16": Q(0, 0, 0x71800000),   # denormal * 2^100 = 0
      "r8": Q(0x300, 0, 0, 0)},
     {"r3_w0": 0x7f800000,          # 2^128 is an ordinary number on the SPU
      "r4_w0": 0x7fffffff,          # 2^129 saturates to Smax
      "r5_w1": 0, "r6_w2": 0,
      # FPSCR read after the last fm: slot 0 OVF|DIFF (4|1), slot 1 UNF|DIFF (2|1), slot 2 DIFF
      # (denormal input); then fscrwr wrote rounding controls only
      "r7": Q(0x5, 0x3, 0x1, 0), "r9": Q(0x300, 0, 0, 0)}),
    ("sp_negative_underflow", ["fm $3,$10,$11", "fnms $4,$12,$12,$13", "fms $5,$12,$12,$13"],
     {"r10_w0": 0x8d800000, "r11_w0": 0x30800000,   # -2^-100 * 2^-30 -> +0
      "r12_w0": 0x40000000, "r13_w0": 0x40a00000},  # 5 - 2*2 = 1, 2*2 - 5 = -1
     {"r3_w0": 0, "r4_w0": ONE, "r5_w0": 0xbf800000}),
    ("sp_convert", ["csflt $3,$10,0", "cflts $4,$11,0", "cflts $5,$12,4", "cfltu $6,$11,0",
                    "cuflt $7,$13,0", "csflt $8,$14,4"],
     {"r10": Q(0x01000003, 0xfffffffd), "r11": Q(0x40300000, 0xc0300000, 0x4f32d05e, 0x5095e0f2),
      "r12_w0": 0x3fc00000, "r13_w0": 0xffffffff, "r14_w0": 40},
     {"r3": Q(0x4b800001, 0xc0400000),                 # 16777219 truncates to 16777218; -3
      "r4": Q(2, 0xfffffffe, 0x7fffffff, 0x7fffffff),  # 2.75, -2.75, 3e9 and 2e10 saturate
      "r5_w0": 24,                                    # 1.5 * 2^4
      "r6": Q(2, 0, 0xb2d05e00, 0xffffffff),           # -2.75 -> 0; 3e9 fits; 2e10 saturates
      "r7_w0": 0x4f7fffff,                            # 4294967295 truncates to 0xffffff00
      "r8_w0": 0x40200000}),                          # 40 / 16 = 2.5
    ("sp_compare", ["fceq $3,$10,$11", "fcgt $4,$12,$13", "fcmgt $5,$14,$15", "fcmeq $6,$16,$17"],
     {"r10": Q(0x80000000, 0x00000001, ONE, 0x40000000), "r11": Q(0, 0, ONE, 0x3f800001),
      "r12": Q(0x7f800000, 0xbf800000, 0x00400000, 0), "r13": Q(0x7f7fffff, 0xc0000000, 0, 0x80000000),
      "r14": Q(0xc0000000, ONE), "r15": Q(ONE, 0xc0000000),
      "r16": Q(0xc0000000, 0x00000001), "r17": Q(0x40000000, 0x80000000)},
     {"r3": Q(M32, M32, M32, 0), "r4": Q(M32, M32, 0, 0), "r5": Q(M32, 0, 0, 0),
      "r6": Q(M32, M32, M32, M32)}),
    ("sp_interpolate", ["fi $3,$10,$11"],
     {"r10_w0": 0x00040000, "r11_w0": 0x3fa00008},
     # (1 + 0x800/2^13 - 8/2^13 * 0.5) = 1.25 - 2^-11 -> fraction 0x1ff000
     {"r3_w0": 0x3f9ff000}),
    # --- estimates (model: exact value truncated to the 13-bit base, zero step); DBZ for exponent 0
    ("sp_estimates", ["frest $3,$10", "frsqest $4,$11", "fscrrd $5"],
     {"r10": Q(0x40000000, 0x40400000, 0, 0xc0000000), "r11": Q(0x40800000, 0xc0800000, 0, ONE)},
     {"r3": Q(0x3f000000, 0x3eaaa800, 0x7fffffff, 0xbf000000),   # 1/2, 1/3 (base), 1/0, 1/-2
      "r4": Q(0x3f000000, 0x3f000000, 0x7fffffff, ONE),          # 1/sqrt(|x|)
      "r5": Q(0, 0, 0, 0x200)}),                                   # DBZ for slot 2
    ("multiply_more", ["mpyui $3,$10,-3", "mpyhhau $4,$12,$13", "mpyhha $5,$12,$13"],
     {"r10": Q(0x0000fffe, 2, 0, 1), "r4": Q(10, 10, 10, 10), "r5": Q(10, 10, 10, 10),
      "r12": Q(0xffff0000, 0x00020000), "r13": Q(0xffff0000, 0x00030000)},
     {"r3": Q(0xfffb0006, 0x1fffa, 0, 0xfffd),       # lo(a) * 0xfffd, unsigned
      "r4": Q(0xfffe000b, 0x10, 10, 10),             # unsigned hi*hi + RT
      "r5": Q(11, 0x10, 10, 10)}),                   # signed: -1 * -1 + 10
    # --- double precision (IEEE), fused multiply-add rounds once
    ("dp_arith", ["dfa $3,$10,$11", "dfm $4,$10,$12", "dfs $5,$12,$10", "dfms $6,$13,$14",
                  "dfma $7,$12,$12"],
     {"r10": D(0x3ff0000000000000, 0x4000000000000000), "r11": D(0x3c30000000000000, 0x4008000000000000),
      "r12": D(0x4000000000000000, 0xbff0000000000000),
      "r13": D(0x3ff0000000000001), "r14": D(0x3fefffffffffffff), "r6": D(0x3ff0000000000000),
      "r7": D(0x3ff0000000000000, 0x3ff0000000000000)},
     {"r3": D(0x3ff0000000000000, 0x4014000000000000),     # 1 + 2^-60 rounds to 1; 2 + 3
      "r4": D(0x4000000000000000, 0xc000000000000000),     # 1*2; 2*-1
      "r5": D(0x3ff0000000000000, 0xc008000000000000),     # 2-1; -1-2
      # (1+2^-52)(1-2^-53) - 1 = 2^-53 - 2^-105 exactly (a separate multiply would give 0)
      "r6": D(0x3c9ffffffffffffe),
      "r7": D(0x4014000000000000, 0x4000000000000000)}),   # 2*2+1; -1*-1+1
    ("dp_compare", ["dfceq $3,$10,$11", "dfcgt $4,$10,$11", "dfcmgt $5,$11,$10", "dftsv $6,$12,0x44",
                    "dftsv $7,$12,0x22"],
     {"r10": D(0x7ff8000000000000, 0x4000000000000000), "r11": D(0x7ff8000000000000, 0xc008000000000000),
      "r12": D(0x7ff0000000000001, 0x8000000000000000)},
     {"r3": D(0, 0), "r4": D(0, 0xffffffffffffffff), "r5": D(0, 0xffffffffffffffff),
      "r6": D(0xffffffffffffffff, 0xffffffffffffffff), "r7": D(0, 0)}),
    # --- double-precision exception flags in the FPSCR (slot 0 in word 1, slot 1 in word 2:
    # OVF 0x2000, UNF 0x1000, INX 0x800, INV 0x400, NAN 0x200)
    ("dp_flags", ["dfa $3,$10,$11", "dfm $4,$12,$13", "fscrrd $5", "fscrwr $0,$14", "dfs $6,$15,$16",
                  "dfm $7,$17,$18", "fscrrd $8"],
     {"r10": D(0x3ff0000000000000, 0x7ff8000000000000), "r11": D(0x3c30000000000000, 0x3ff0000000000000),
      "r12": D(0x7fefffffffffffff, 0x0170000000000000), "r13": D(0x4000000000000000, 0x39b0000000000000),
      "r15": D(0x7ff0000000000000, 0x4008000000000000), "r16": D(0x7ff0000000000000, 0x4008000000000000),
      "r17": D(0x7ff0000000000001, 0), "r18": D(0x3ff0000000000000, 0x7ff0000000000000)},
     {"r3_d0": 0x3ff0000000000000, "r4": D(0x7ff0000000000000, 0),
      # 1 + 2^-60 inexact; QNaN + 1 sets NAN; max * 2 overflows; 2^-1000 * 2^-100 underflows to 0
      "r5": Q(0, 0x2800, 0x1a00, 0),
      # inf - inf invalid; SNaN * 1 invalid and NaN; 3 - 3 exact; 0 * inf invalid
      "r8": Q(0, 0x600, 0x400, 0)}),
    ("dp_convert_flags", ["fesd $3,$10", "frds $4,$11", "fscrrd $5"],
     {"r10": Q(0x7f800001, 0, ONE, 0), "r11": D(0x7e37e43c8800759c, 0x3ff0000004000000)},
     {"r3_d1": 0x3ff0000000000000, "r4": Q(0x7f800000, 0, ONE, 0),
      # fesd of a signalling NaN: INV|NAN; frds of 1e300 overflows; 1 + 2^-30 is inexact
      "r5": Q(0, 0x2e00, 0x800, 0)}),
    ("sp_dp_convert", ["fesd $3,$10", "frds $4,$11"],
     {"r10": Q(0x3fc00000, 0x12345678, 0xc0000000, 0), "r11": D(0x3ff0000000000001, 0x400921fb54442d18)},
     {"r3": D(0x3ff8000000000000, 0xc000000000000000), "r4": Q(ONE, 0, 0x40490fdb, 0)}),
]

DATA = """
	.align 4
qdata:
	.long 0x11111111, 0x22222222, 0x33333333, 0x44444444
qdata2:
	.long 0, 0, 0, 0
"""

HELPERS = """
cfunc:
	ai $3,$3,10
	bi $lr
cfunc2:
	bi $11
"""


def tool(name, env):
    return os.environ.get(env, 'spu-elf-' + name)


def main():
    outdir = sys.argv[1]
    brk = sys.argv[sys.argv.index('--break') + 1] if '--break' in sys.argv else None
    os.makedirs(outdir, exist_ok=True)
    src = ['\t.text', '\t.global _start', '_start:']
    for name, lines, init, exp in TESTS:
        src.append('test_%s:' % name)
        for l in lines:
            # numeric labels ("1:", referenced as "1f") become <test>_<n>
            l = re.sub(r'\b(\d+)f\b', lambda m: '%s_%s' % (name, m.group(1)), l)
            m = re.match(r'(\w+):\s*(.*)', l)
            if m:
                lab = m.group(1)
                src.append('%s:' % (('%s_%s' % (name, lab)) if lab.isdigit() else lab))
                if m.group(2):
                    src.append('\t' + m.group(2))
            else:
                src.append('\t' + l)
        src.append('end_%s:' % name)
        src.append('\tstop 0x3fff')
    src.append(HELPERS)
    src.append(DATA)
    s = os.path.join(outdir, 'emu.s')
    o = os.path.join(outdir, 'emu.o')
    elf = os.path.join(outdir, 'emu.elf')
    b = os.path.join(outdir, 'emu.bin')
    open(s, 'w').write('\n'.join(src) + '\n')
    subprocess.check_call([tool('as', 'SPU_AS'), '-o', o, s])
    subprocess.check_call([tool('ld', 'SPU_LD'), '-Ttext=0', '-e', '_start', '-o', elf, o])
    subprocess.check_call([tool('objcopy', 'SPU_OBJCOPY'), '-O', 'binary', '-j', '.text', elf, b])
    syms = {}
    for line in subprocess.check_output([tool('nm', 'SPU_NM'), elf], text=True).splitlines():
        p = line.split()
        if len(p) == 3:
            syms[p[2]] = int(p[0], 16)

    def val(v, name):
        if isinstance(v, str):
            lab = v[1:]
            m = re.fullmatch(r'(\d+)f', lab)
            return syms['%s_%s' % (name, m.group(1))] if m else syms[lab]
        return v
    out = []
    for name, lines, init, exp in TESTS:
        def kv(d):
            items = []
            for k, v in d.items():
                if k.startswith('m') and ':@' in k:
                    k = k.split(':@')[0] + ':%x' % syms[k.split(':@')[1]]
                items.append('%s=%x' % (k, val(v, name)))
            return ','.join(items) or '-'
        e = dict(exp)
        if name == brk:
            k0 = next(iter(e))
            e[k0] = val(e[k0], name) ^ 1
        out.append('%s %x %x %s %s' % (name, syms['test_' + name], syms['end_' + name], kv(init), kv(e)))
    open(os.path.join(outdir, 'emu.txt'), 'w').write('\n'.join(out) + '\n')
    print('%d tests -> %s' % (len(out), outdir))


if __name__ == '__main__':
    main()
