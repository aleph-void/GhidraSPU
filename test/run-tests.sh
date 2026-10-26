#!/usr/bin/env bash
# Cell SPU processor module tests.
#
#   test/run-tests.sh [workdir]
#
# 1. regenerate spu.sinc/spu.cspec and check they match the committed files; compile the
#    SLEIGH spec; link the module into $GHIDRA_INSTALL_DIR/Ghidra/Processors/SPU and build
#    lib/SPU.jar (relocation handler)
# 2. if ISA_TXT is set (tools/fetch-isa.sh output): check the opcode table against the SPU ISA
# 3. decode corpus (gen_corpus.py: every 11-bit opcode with 48 operand fills, plus 60,000
#    random words): Ghidra (DumpSlots.java) vs GNU objdump's disassembler (slotdis, binutils
#    2.45 libopcodes); compare.py scores exact/equivalent agreement and buckets every difference
# 4. every-constructor decode test (CoverageCheck.java)
# 5. p-code emulator tests (emu_tests.py, EmuCheck.java), then once more with one expectation
#    deliberately wrong to show the harness fails; needs spu-elf-as/ld (build-toolchain.sh)
# 6. if REAL_SAMPLES is set (fetch-real-samples.sh output): real-binaries.sh
#
# Environment: GHIDRA_INSTALL_DIR; SLOTDIS, or BU_SRC + BU_BUILD (binutils 2.45 source and a
# build tree configured with --enable-targets=all or --target=spu-elf) to build it.
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MOD=$(cd "$HERE/.." && pwd)
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
W=$(mkdir -p "${1:-$PWD/spu-test-work}" && cd "${1:-$PWD/spu-test-work}" && pwd)
cd "$W"
fail=0

echo "== generators and SLEIGH"
python3 "$MOD/tools/gen_spu_sinc.py" | cmp - "$MOD/data/languages/spu.sinc" && echo "   spu.sinc is up to date"
python3 "$MOD/tools/gen_spu_cspec.py" | cmp - "$MOD/data/languages/spu.cspec" && echo "   spu.cspec is up to date"
"$GHIDRA_INSTALL_DIR/support/sleigh" "$MOD/data/languages/spu.slaspec" 2>&1 | grep -E "^ERROR|^Error" && fail=1
ls -l "$MOD/data/languages/spu.sla" | awk '{print "   " $5, $9}'
P="$GHIDRA_INSTALL_DIR/Ghidra/Processors/SPU"
if [[ ! -e $P ]]; then ln -s "$MOD" "$P"; elif [[ $(readlink -f "$P") != "$MOD" ]]; then
	echo "warning: $P exists and is not this module" >&2; fi
"$HERE/build-jar.sh"

if [[ -n ${ISA_TXT:-} ]]; then
	echo "== opcode table vs SPU ISA v1.2"
	python3 "$MOD/tools/isa_check.py" "$ISA_TXT" || fail=1
fi

if [[ -z ${SLOTDIS:-} ]]; then
	: "${BU_SRC:?set SLOTDIS, or BU_SRC and BU_BUILD to build it}" "${BU_BUILD:?set BU_BUILD}"
	SLOTDIS=$W/slotdis
	gcc -O2 -DPACKAGE=1 -DPACKAGE_VERSION=1 -include "$BU_BUILD/bfd/config.h" -o "$SLOTDIS" \
		"$HERE/slotdis.c" -I"$BU_BUILD/bfd" -I"$BU_SRC/include" -I"$BU_SRC/bfd" \
		"$BU_BUILD/opcodes/.libs/libopcodes.a" "$BU_BUILD/bfd/.libs/libbfd.a" \
		"$BU_BUILD/libiberty/libiberty.a" "$BU_BUILD/libsframe/.libs/libsframe.a" \
		"$BU_BUILD/zlib/libz.a" -lzstd 2>/dev/null
fi
export SLOTDIS

echo "== decode corpus vs GNU objdump"
python3 "$HERE/gen_corpus.py" corpus.bin
"$SLOTDIS" spu 4 corpus.bin >gnu.txt
"$HERE/ghidra-slots.sh" SPU:BE:32:default corpus.bin 4 ghidra.txt
python3 "$HERE/compare.py" ghidra.txt gnu.txt | tee compare.txt | head -12 || fail=1

echo "== every-constructor decode test"
head -c 64 /dev/zero >zero.bin
"$HERE/ghidra-script.sh" raw SPU:BE:32:default zero.bin CoverageCheck.java "$W/cov.txt" 64
tail -1 cov.txt
grep '^unreached' cov.txt && fail=1

echo "== p-code emulator tests"
python3 "$HERE/emu_tests.py" emu
"$HERE/ghidra-script.sh" raw SPU:BE:32:default emu/emu.bin EmuCheck.java "$W/emu/emu.txt" "$W/emu/out.txt"
grep -v '^PASS' emu/out.txt
grep -q ', 0 failed' emu/out.txt || fail=1
echo "-- negative control: one wrong expectation must fail"
python3 "$HERE/emu_tests.py" emu-break --break sp_truncation >/dev/null
"$HERE/ghidra-script.sh" raw SPU:BE:32:default emu-break/emu.bin EmuCheck.java "$W/emu-break/emu.txt" "$W/emu-break/out.txt"
grep '^FAIL' emu-break/out.txt || { echo "   the harness did not fail"; fail=1; }

if [[ -n ${REAL_SAMPLES:-} ]]; then
	echo "== real binaries"
	"$HERE/real-binaries.sh" "$REAL_SAMPLES" "$W/real" || fail=1
fi
echo "== done: $([[ $fail == 0 ]] && echo PASS || echo FAIL)"
exit $fail
