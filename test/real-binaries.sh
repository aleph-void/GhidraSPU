#!/usr/bin/env bash
# Real-binary check of the samples built by fetch-real-samples.sh.  ELF files (*.elf, *.o) are
# imported headless WITHOUT -processor (the ELF opinion picks SPU:BE:32:default); raw local-store
# images (*.bin) use the BinaryLoader at address 0 with RawEntry.java.  Each is auto-analyzed and
# every function decompiled (RealCheck.java).  Every instruction Ghidra found is disassembled by
# GNU libopcodes from the same bytes (lst2img.py, slotdis -l) and scored by compare.py.  For
# relocatable objects, reloc_check.py links the object with GNU ld at Ghidra's addresses and
# compares every relocated field.
#   test/real-binaries.sh <samples-dir> [workdir]
# Environment: GHIDRA_INSTALL_DIR (this module installed or symlinked into Ghidra/Processors,
# with lib/*.jar from build-jar.sh), SLOTDIS (slotdis built from slotdis.c), spu-elf-ld/objcopy/
# readelf on PATH, DECOMP_TIMEOUT (seconds, default 60).
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
: "${GHIDRA_INSTALL_DIR:?set GHIDRA_INSTALL_DIR}"
: "${SLOTDIS:?set SLOTDIS}"
TMO=${DECOMP_TIMEOUT:-60}
SAMPLES=$(readlink -f "$1")
W=$(mkdir -p "${2:-real-out}" && cd "${2:-real-out}" && pwd)
PROJ=$(mktemp -d "${TMPDIR:-/tmp}/spu-real.XXXXXX")
trap 'rm -rf "$PROJ"' EXIT

run_one() {
	local f=$1 n p imp=()
	n=$(basename "$f")
	p=$(mktemp -d "$PROJ/p.XXXXXX")
	[[ $n == *.bin ]] && imp=(-loader BinaryLoader -processor SPU:BE:32:default -preScript RawEntry.java)
	"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" "$p" p -import "$f" "${imp[@]}" -scriptPath "$HERE" \
		-postScript RealCheck.java "$W/$n.sum" "$W/$n.lst" "$W/$n.c" "$TMO" \
		-postScript DumpBlocks.java "$W/$n.mem" \
		-deleteProject >"$W/$n.log" 2>&1 || tail -20 "$W/$n.log" >&2
	rm -rf "$p"
}

mapfile -t files < <(find "$SAMPLES" -maxdepth 1 \( -name '*.elf' -o -name '*.o' -o -name '*.bin' \) | sort)
echo "== headless import + analysis + decompile (${#files[@]} files, 3 at a time)"
i=0
for f in "${files[@]}"; do
	run_one "$f" &
	i=$((i + 1))
	((i % 3 == 0)) && wait
done
wait

echo "== results"
rc=0
for f in "${files[@]}"; do
	n=$(basename "$f")
	echo "-- $n"
	grep -E "^(language|functions|instructions|bad-instruction|error bookmarks|relocations|decompile|functions whose)" \
		"$W/$n.sum" | sed 's/^/   /'
	base=$(python3 "$HERE/lst2img.py" "$W/$n.lst" "$W/$n.img" "$W/$n.slots")
	"$SLOTDIS" spu 4 "$W/$n.img" -l "$W/$n.slots" -b "$base" >"$W/$n.ref"
	python3 "$HERE/compare.py" "$W/$n.slots" "$W/$n.ref" >"$W/$n.cmp" || rc=1
	echo "   vs objdump: $(head -1 "$W/$n.cmp")"
	echo "               $(sed -n 2p "$W/$n.cmp")"
	if [[ $n == *.o ]]; then
		python3 "$HERE/reloc_check.py" "$f" "$W/$n.mem" "$W/$n.rel" >"$W/$n.relcheck" || rc=1
		echo "   $(grep '^relocations checked' "$W/$n.relcheck")"
	fi
done
echo "(full outputs: $W/<file>.{sum,lst,c,cmp,relcheck})"
exit $rc
