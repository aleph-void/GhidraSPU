#!/usr/bin/env bash
# Download the SPU ISA v1.2 (IBM/Sony/Toshiba, 2007) by pinned URL and SHA-256 and convert it to
# text for isa_check.py.  Usage: tools/fetch-isa.sh <dir>   (needs curl, pdftotext)
set -euo pipefail
D=${1:?usage: fetch-isa.sh <dir>}
mkdir -p "$D"
URL=http://web.archive.org/web/20260427211226id_/https://arcb.csc.ncsu.edu/~mueller/cluster/ps3/SDK3.0/docs/arch/SPU_ISA_v1.2_27Jan2007_pub.pdf
SHA=e699698426796c3e9157af938c7512e6d341ae2b0a6721c8a6fcd21b6ce4a141
[[ -f $D/SPU_ISA_v1.2.pdf ]] || curl -sSfL -o "$D/SPU_ISA_v1.2.pdf" "$URL"
echo "$SHA  $D/SPU_ISA_v1.2.pdf" | sha256sum -c --quiet
pdftotext -layout "$D/SPU_ISA_v1.2.pdf" "$D/SPU_ISA_v1.2.txt"
echo "$D/SPU_ISA_v1.2.txt"
