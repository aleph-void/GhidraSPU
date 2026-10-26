# GhidraSPU

SPU processor implementation for Ghidra: the Synergistic Processor Unit of the Cell Broadband
Engine (PlayStation 3, IBM QS20/QS21/QS22, PowerXCell 8i). Written by aerosoul94, balika011,
Eladash and VelocityRa.

Upstream described the module as a work in progress. This fork (part of
[Ghidra-Rare](https://github.com/aleph-void/Ghidra-Rare)) completes it: every instruction of the
SPU ISA v1.2 decodes like GNU objdump and has p-code on full 128-bit registers, SPU ELF files
import automatically, and the module is tested against reference tools and real binaries. See
[GHIDRA-RARE.md](GHIDRA-RARE.md) for the results and [CREDITS.md](CREDITS.md) for the list of
changes.

## Install

Prebuilt extension zips for Ghidra 12.1.3, 12.1.4 and 12.2 are on this fork's Releases page.
In Ghidra: File > Install Extensions > + > select the zip, then restart Ghidra.

To build from source, compile the language and build the extension with the Ghidra version you
use:

    $GHIDRA_INSTALL_DIR/support/sleigh data/languages/spu.slaspec
    gradle -PGHIDRA_INSTALL_DIR=$GHIDRA_INSTALL_DIR buildExtension

## Use

SPU ELF files (`EM_SPU`, e.g. the SPU programs embedded in PS3 or Cell Linux executables) are
recognised by the ELF loader. For raw local-store images choose the language
`SPU:BE:32:default` and load them at address 0. Programs created with the earlier language ID
`SPU:BE:128:default` are upgraded when opened.

## Known limitations

Status of the limitations and TODOs of the upstream version:

- Fixed: registers were 64 bits wide; 128-bit operations and most SIMD lanes were not
  modelled ("fix this once 128 bits supported properly").
- Fixed: 94 instructions had no p-code (named pcodeops only); `stopd` (marked TODO) now
  stops like `stop`.
- Fixed: `andbi`/`orbi` ("IS THIS IMPLEMENTATION RIGHT?").
- Fixed: interrupt enable/disable feature bits of the indirect branches were ignored.
- Fixed: `hbr`, `hbra`, `hbrr` did not show their operands.
- Fixed: SPU ELF files were not recognised (opinion attribute and language size).
- Fixed: the relocation handler did not build with current Ghidra.
- New: switch statements compiled to jump tables are recovered by the "SPU Switch Tables"
  analyzer (enabled by default).

Remaining, by design (details in GHIDRA-RARE.md): double-precision results always use
round-to-nearest (the FPSCR rounding-mode fields are not applied), `frest`/`frsqest` return an
exact estimate rather than the hardware's table values, and channel and stop instructions do
not model the MFC or the PPE on the other side.
