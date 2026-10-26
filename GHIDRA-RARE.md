# Ghidra-Rare notes: Cell Broadband Engine SPU

This fork of [aerosoul94/GhidraSPU](https://github.com/aerosoul94/GhidraSPU) (commit `b85076d`,
Apache-2.0) is part of [Ghidra-Rare](https://github.com/aleph-void/Ghidra-Rare). It was checked to
the same standard as the project's own modules: decoding against GNU objdump and the ISA, an
every-constructor test, p-code in Ghidra's emulator, and real third-party binaries.
`CREDITS.md` lists the authors and every change; this page has the evidence. Prebuilt zips for
Ghidra 12.1.3, 12.1.4 and 12.2 are on the fork's Releases page.

## Coverage

The SPU instruction set architecture v1.2 (all 199 opcodes, including the double-precision
compares and `dftsv` of v1.2), as implemented by the Cell Broadband Engine and PowerXCell 8i.
One language, `SPU:BE:32:default`, with GCC's SPU ABI and the ELF opinion for `EM_SPU` (23).

Registers r0-r127 are 128 bits; `lr`/`sp` are r0/r1. Each has lane views named
`<reg>_d0..d1`, `_w0..w3`, `_h0..h7`, `_b0..b15` (big-endian, `_w0` is the preferred slot), which
is where the decompiler shows scalar values: arguments are `r3_w0`, `r4_w0`, ... Channels are
registers with CBEA names (`MFC_Cmd`, `SPU_RdInMbox`, ...) and a count register each
(`<name>_cnt`); `SRR0`, `IE` (interrupts enabled) and `FPSCR` complete the state.

## Results

| Check | Result |
|---|---|
| Opcode table vs the SPU ISA v1.2 PDF (`tools/isa_check.py`) | 199 of 199 opcodes match the instruction pages |
| Decode corpus: every 11-bit opcode with 48 operand fills (98,304 words) + 60,000 random words, vs GNU objdump 2.45 | 97,791 decoded words agree (97,699 identical, 92 differ only in documented display choices, below); 60,513 rejected by both; no other differences |
| Every-constructor test (`CoverageCheck.java`) | 262 of 262 constructors reached |
| Emulator (`emu_tests.py`, `EmuCheck.java`) | 37 of 37 hand-computed sequences pass; a deliberately wrong expectation fails |
| Relocations (`reloc_check.py`): Ghidra's applied ELF relocations vs GNU ld linking the same object at Ghidra's addresses | 8,570 of 8,570 agree (every relocation type in `reloc_types.o`; Ubuntu's libm and libc) |
| Extension build (`tools/build-module.sh`) | Ghidra 12.1.3, 12.1.4 and 12.2 |
| Old language ID | a program saved with upstream's `SPU:BE:128:default` opens as `SPU:BE:32:default` with its instructions and functions intact |

The emulator tests cover word/halfword/byte arithmetic, carries and borrows (`cg`, `bg`,
`addx`, `sfx`, `cgx`, `bgx`), all multiplies, logical immediates, `selb` and every `shufb`
control class, insertion controls (`cbd`/`chx`/`cwd`/`cdd`/`cwx`), every load and store
addressing mode (low address bits ignored, sp-relative frames, PC-relative data), the
unaligned scalar load idiom, quadword rotates and shifts (byte, bit and bit-count forms),
word/halfword shifts with out-of-range counts, compares, `clz`/`cntb`/`gb*`/`fsm*`/`sumb`/
`avgb`/`absdb`/sign extensions, relative/conditional/indirect branches taken and not taken,
calls and returns (`brsl`, `brasl`, `bisl`, `bi $lr`), hints and no-ops, halts not taken,
channels and SPRs, `iret` with SRR0 and the interrupt feature bits, `bisled`,
single-precision truncation (cases where IEEE rounding differs), extended range (2^128, Smax
saturation, positive-zero underflow, denormal input as zero), FPSCR OVF/UNF/DIFF flags,
conversions with scales and saturation, extended-range compares, `fi`, the `frest`/`frsqest`
model and its DBZ flag, double-precision arithmetic including a fused multiply-subtract that a
separate multiply would get wrong, double-precision compares/`dftsv`, `fesd`/`frds`, and the
double-precision FPSCR flags.

## Real binaries

Fetched by `test/fetch-real-samples.sh` (pinned URLs and SHA-256; nothing is committed):

- `zlib_example.elf`: zlib 1.3.1 and its `test/example.c`, compiled with GCC 6.5.0
  (`-O2 -g`, built by `test/build-toolchain.sh`) and linked with Ubuntu 14.04's prebuilt SPU
  newlib 1.18 and libgcc 4.7 (packages `newlib-spu`, `gcc-4.7-spu`): third-party compiled C
  library code plus DWARF.
- `libm_all.o`, `libc_a.o`, `libc_b.o`: Ubuntu's SPU libm and the two halves of its libc as
  relocatable objects (`ld -r`; each half fits the 256 KiB local store).
- `spu_save.bin`, `spu_restore.bin`: the SPU context save/restore programs IBM built for the
  Linux spufs driver (`*_dump.h_shipped`, Linux 6.6), raw local-store images at address 0.
- `reloc_types.o`: one relocation of every SPU type (`test/reloc_types.s`).

ELF files were imported headless without `-processor` (the opinion picks the language), auto
analysed, every function decompiled (60 s limit), and every instruction Ghidra found compared
with objdump disassembling the same bytes.

| Sample | Functions decompiled | Instructions | Same decoding as objdump | Bad-instruction / error bookmarks | Relocations agreeing with GNU ld | `switch` statements |
|---|---:|---:|---:|---:|---:|---:|
| zlib_example.elf | 184/184 | 57,695 | 100% (16 display differences) | 0 / 0 | (linked) | 4 |
| libm_all.o | 293/293 | 33,776 | 100% (3) | 0 / 0 | 3,611/3,611 | 10 |
| libc_a.o | 359/359 | 34,327 | 100% (37) | 0 / 0 | 2,577/2,577 | 10 |
| libc_b.o | 277/277 | 23,534 | 100% (25) | 0 / 0 | 2,364/2,364 | 8 |
| spu_save.bin | 2/2 | 154 | 100% (3) | 0 / 0 | (raw) | 0 |
| spu_restore.bin | 2/2 | 164 | 100% (4) | 0 / 0 | (raw) | 0 |
| reloc_types.o | 3/3 | 16 | 100% | 0 / 0 | 18/18 | 0 |

"Display differences" are the `stop` signal type and zero PC-relative offsets (below). The kernel
images are fully disassembled: their code ends at 0x268 and 0x290, the rest is zero-filled save
area. The only indirect jumps the decompiler still reports are genuine: newlib's `_mcount`
profiling stub returns through a computed address, and `spu_restore` jumps into the restored
context.

## Switch tables

GCC compiles dense switches to a table read with `lqx` and `rotqby` and a `bi` through the
loaded word. The decompiler cannot follow the quadword load and rotate and reported such jumps
as calls ("Treating indirect jump as call") or gave up on the table. The "SPU Switch Tables"
analyzer (on by default) finds the table base (`ila`, `ilhu`/`iohl`, `ai`), the index scaling
(`shli ...,2`) and the bound (`clgti`), adds the computed-jump references, disassembles and types
the table and writes a jump-table override, so the decompiler emits a `switch`.

## Display choices (the "equivalent" decode differences)

- `stop` shows its 14-bit signal type (objdump prints only `stop`).
- A PC-relative operand with offset 0 shows its target address; objdump prints `0` (in object
  files this is usually an unrelocated field).
- Register names are `lr`, `sp`, `r2`...; channels and SPRs use names.

## Semantics notes

- Local-store addresses: loads, stores and indirect branches use the low 18 bits (256 KiB) and
  ignore the low 4 (2 for branches), like the hardware. `lqd`/`stqd` through `sp` skip the mask
  so the decompiler recognises stack frames; the ABI keeps `sp` 16-byte aligned. Relative
  branch targets are computed modulo 256 KiB too.
- The `lqa`/`lqr`/`stqa`/`stqr` operand is the encoded address, which compilers set to the
  scalar being accessed; the access is to the containing quadword.
- `brsl` to the next instruction (used to read the PC) is a jump, other `brsl`/`brasl`/`bisl`
  are calls; `bi $lr` and the conditional `bi*` on `$lr` are returns; `iret` returns to SRR0.
- Single precision is the ISA's extended-range arithmetic, computed exactly: operands become
  exact doubles, sums use an error-free transformation so truncation is exact, products are
  exact, results saturate to Smax, underflow to +0, and set FPSCR OVF/UNF/DIFF per slot;
  `frest`/`frsqest` set DBZ for zero exponents.
- Double precision is IEEE with round-to-nearest; `dfma`/`dfms`/`dfnms`/`dfnma` compute the
  product exactly in binary128 and round once. OVF, UNF (tiny before rounding and inexact),
  INX, INV and NAN (any NaN operand) are accumulated in the FPSCR.
- `rdch`/`wrch`/`rchcnt` read and write the channel and count registers; `wrch SPU_WrSRR0`
  and `rdch SPU_RdSRR0` access SRR0; `bisled` branches when `SPU_RdEventStat_cnt` is nonzero.
- `stop`, `stopd` and the taken `h*` halts call the user operations `spu_stop(signal)`,
  `spu_stopd()` and `spu_halt()`.
- Byte-lane instructions compute lanes 8-15 with an equivalent but differently shaped
  expression: Ghidra's decompiler gives up ("Unable to find unique hash for varnode") when more
  than eight values in one instruction have the same data-flow shape.

## Remaining gaps, and why

- **Double-precision rounding modes.** The FPSCR RN0/RN1 fields are kept but not applied; DP
  results always round to nearest (the reset mode, used by compiled code). Applying them would
  make every DP result depend on FPSCR in the decompiled C. The exception flags are modelled.
- **`frest`/`frsqest` values.** The ISA leaves the estimate table to the implementation and the
  Cell BE table is not published. The model returns the exact reciprocal (square root) truncated
  to the 13-bit base fraction with a zero step, so `fi` returns the base and the usual
  Newton-Raphson step meets the ISA's 1-ulp accuracy, but intermediate bits differ from the
  hardware's.
- **The other side of the channels.** Channel writes store into the channel register; DMA,
  mailboxes, signals and the decrementer are hardware outside the SPU. `stop` and the halts hand
  control to the PPE, which p-code cannot represent: they are user operations.
- **DENORM flag.** Never set: the model treats double-precision denormal operands as IEEE does.
  The ISA lets an implementation flush them to zero and set DENORM instead; which Cell
  processors do is not documented in the ISA and could not be checked without hardware.
- **DWARF values wider than a word in registers.** Ghidra places a variable smaller than its
  register at the register's low-order end, which for SPU registers is slot 3; scalars live in
  slot 0. DWARF registers therefore map to the preferred words `rN_w0`, which is right for
  every value of up to 4 bytes; an 8-byte or vector variable that DWARF places in a register
  cannot be described with one mapping. (Function parameters come from the calling convention
  and are unaffected.)
- **PPU relocations** (`R_SPU_PPU32/64`) patch the PPU program that embeds the SPU image; they
  are reported, not applied.
- **Decompiler output is wide.** Every SPU instruction is SIMD, so scalar code also computes the
  other three slots: the decompiler shows `in_r3_w1`-style inputs and 16-byte temporaries, and
  `shufb` expands to per-byte selections. The values in the preferred slots are correct.

Not verified: behaviour on SPU hardware or a cycle-accurate simulator (none is available). The
semantics follow the ISA text and the hand-computed tests; where the ISA leaves results to the
implementation (estimate tables, NaN payloads, DENORM), the Cell BE's exact output is unknown.

## How to test

    test/build-toolchain.sh <work> <prefix>          # binutils 2.45 + GCC 6.5.0 for spu-elf
    export PATH=<prefix>/bin:$PATH GHIDRA_INSTALL_DIR=<ghidra 12.x>
    test/fetch-real-samples.sh <samples>             # optional
    tools/fetch-isa.sh <isa>                         # optional
    SLOTDIS=<slotdis> ISA_TXT=<isa>/SPU_ISA_v1.2.txt REAL_SAMPLES=<samples> test/run-tests.sh <work>

`test/slotdis.c` is a small libopcodes driver (build it against a binutils 2.45 tree, or let
`run-tests.sh` build it from `BU_SRC`/`BU_BUILD`). `tools/gen_spu_sinc.py` and
`tools/gen_spu_cspec.py` regenerate `spu.sinc` and `spu.cspec`; `run-tests.sh` checks that the
committed files match.

## Confirmed reference-tool behaviour

- objdump ignores reserved fields and prints the feature-bit letters of `hbr` from bits that
  the ISA reserves (`hbrd`, `hbre`); the module decodes the same way.
- objdump prints a zero PC-relative offset as `0` rather than as an address.
