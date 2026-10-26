# Credits

## Upstream

- Repository: <https://github.com/aerosoul94/GhidraSPU>
- Commit: `b85076d8a0d0bd6d2df5c3bfa8d84e5390c1e5e9` ("Merge branch 'master'", 2023-07-07)
- License: Apache License 2.0 (`LICENSE`)
- Authors (GitHub logins and commit names):
  - aerosoul94 (aerosoul): language skeleton, floating-point instructions, DWARF map,
    the ELF relocation handler
  - balika011: most of the original instruction set and channels
  - elad335 (Eladash): loads/stores, branches, many instruction implementations
  - VelocityRa (Nick Renieris): shift and rotate implementations

Alternatives and forks that were compared:

- Forks of GhidraSPU: Goatman13 (absolute branch fixes, unsigned `fsmbi` display), Vestrel
  (`cgthi` fix, branch handling), elad335's open pull request #6 (channel names, `bisl`, `brsl`/
  `brasl` to the next instruction as a jump), clienthax and ennuo (Ghidra 12 relocation API;
  ennuo also adds a loader for SPURS job binaries). Ghidra-Rare reimplemented these points
  rather than merging the forks; no code was copied from them.
- Danil6969/ghidra-extensions `Processors/SPU`: no license; only compared, nothing copied.

Reference material: IBM, Sony and Toshiba, *Synergistic Processor Unit Instruction Set
Architecture* v1.2 (2007), the source of the opcode table and of every p-code semantic; GNU
binutils 2.45 `objdump` (GPL) as the decode oracle only, run as a separate program.

## What Ghidra-Rare changed

Language (`tools/gen_spu_sinc.py` generates `data/languages/spu.sinc`):

- 128-bit registers (upstream: 64-bit) with big-endian doubleword, word, halfword and byte lane
  views; every SIMD instruction computes all of its lanes.
- p-code for every instruction of the SPU ISA v1.2. Upstream had 94 instructions as opaque
  pcodeops (`mpy*`, `clz`, `cntb`, `gb*`, `fsm*`, `shufb`, `cbd`-family controls, quadword
  shifts, compares, floating point, conversions, channels, ...), and the implemented ones
  computed one 64-bit value instead of the 128-bit lanes (`ah` kept only the low halfword,
  loads and stores moved 8 of 16 bytes, `fsm` reversed the slot order and inverted three of
  its bits, `bg` was wrong for equal operands, addresses were neither wrapped at 256 KiB nor
  quadword-aligned).
- Single precision follows the ISA's extended-range arithmetic exactly (truncation, no
  Inf/NaN, denormals as zero, Smax saturation, FPSCR OVF/UNF/DIFF/DBZ); double precision is
  IEEE, with the fused multiply-adds rounded once and the FPSCR OVF/UNF/INX/INV/NAN flags.
- Decoding of all 199 opcodes checked against the ISA (`tools/isa_check.py`) and against GNU
  objdump on every opcode; reserved fields ignored as objdump does; feature-bit
  mnemonics (`bie`, `bisld`, `irete`, `hbrp`, `syncc`, ...).
- Calls and returns: `bi $lr` and conditional `bi*` on `$lr` return; `brsl` to the next
  instruction is a jump; `iret` returns to SRR0; `bisled` tests the event channel count.
- Channels and SPRs are registers (CBEA channel names; SRR0 through `SPU_WrSRR0`/`SPU_RdSRR0`);
  interrupt enable state follows the D/E feature bits.
- The operand of `lqa`/`lqr`/`stqa`/`stqr` references the encoded (scalar) address.

Specs and loader:

- Language ID `SPU:BE:32:default` (was `SPU:BE:128:default`, which Ghidra's ELF loader never
  offers for 32-bit ELF files); `data/languages/old/` upgrades programs saved with the old ID.
- ELF opinion fixed (`loader=` attribute; upstream's `load=` matched nothing).
- `spu.cspec` rewritten for GCC's SPU ABI (preferred-slot arguments in r3-r74, r80-r127
  callee-saved, unsigned char, stack at sp+32).
- `spu.dwarf` maps all 128 registers (upstream used an attribute Ghidra ignores).
- ELF relocation handler ported to Ghidra 12's API; `R_SPU_ADD_PIC` applied only for undefined
  symbols, PPU relocations reported.
- New analyzer "SPU Switch Tables" (`src/main/java/spu/analysis`): recovers GCC's jump tables
  (`ila`/`shli`/`a`/`lqx`/`rotqby`/`bi`), which the decompiler otherwise treats as calls.
- Build files for Ghidra 12.1.3, 12.1.4 and 12.2; `test/` and `tools/` are not packaged.

Tests (`test/`), verification notes (`GHIDRA-RARE.md`) and this file are new.
