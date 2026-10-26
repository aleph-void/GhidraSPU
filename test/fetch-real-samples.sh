#!/usr/bin/env bash
# Fetch freely licensed SPU code (pinned URLs, SHA-256 checked) and build the real-binary
# samples into <outdir>.  Nothing fetched or built here is committed.
#   test/fetch-real-samples.sh <outdir>
# Needs spu-elf-gcc/as/ld/ar (build-toolchain.sh) on PATH, curl, dpkg-deb.
#
# Inputs and licences:
#  - Ubuntu 14.04 newlib-spu 1.18.0-6.2ubuntu1 (newlib libc/libm/libgloss built for the SPU by
#    Ubuntu with its gcc-spu; BSD-style licences) and gcc-4.7-spu 4.7.3-9ubuntu2 (libgcc, crt
#    files; GPL with the GCC runtime exception)
#  - zlib 1.3.1 (zlib licence), compiled here with GCC 6.5.0 -O2 -g
#  - Linux 6.6 arch/powerpc/platforms/cell/spufs/spu_{save,restore}_dump.h_shipped: the SPU
#    context save/restore programs IBM built from spu_save.c/spu_restore.c (GPL-2.0)
# Outputs:
#  zlib_example.elf  zlib's test/example.c linked with all of zlib, Ubuntu's newlib and libgcc
#  libm_all.o, libc_a.o, libc_b.o  Ubuntu's libm and the two halves of libc as relocatable
#                    objects (ld -r), each small enough for the 256 KiB local store
#  spu_save.bin, spu_restore.bin  the kernel's raw local-store images (loaded at 0)
#  reloc_types.o     every SPU relocation type (reloc_types.s, addpic.py)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
O=$(mkdir -p "$1" && cd "$1" && pwd)
S=$O/src
mkdir -p "$S"
fetch() { # url sha256 file
	[[ -f $S/$3 ]] || curl -fsSL -o "$S/$3" "$1"
	echo "$2  $S/$3" | sha256sum -c --quiet
}
LP=https://launchpad.net/ubuntu/+archive/primary/+files
fetch $LP/newlib-spu_1.18.0-6.2ubuntu1_powerpc.deb c13888e5e4fe76455cde2ceec1af49585a753577823a82fbe47070195c7319e6 newlib-spu.deb
fetch $LP/gcc-4.7-spu_4.7.3-9ubuntu2_powerpc.deb 321b669d60bae9cee14f905bcaac0cb511793cd6204372f470f0d1d3f447d785 gcc-4.7-spu.deb
fetch https://zlib.net/fossils/zlib-1.3.1.tar.gz 9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23 zlib-1.3.1.tar.gz
K=https://raw.githubusercontent.com/torvalds/linux/v6.6/arch/powerpc/platforms/cell/spufs
fetch $K/spu_save_dump.h_shipped 0c6cc12c62062100c768e3e828186d3a9074650c4e90c798d7b11fcf0a1e287b spu_save_dump.h
fetch $K/spu_restore_dump.h_shipped d251327c0d9afe5794d4fdaf4de870197818600a7c572e26ffe19740526545d4 spu_restore_dump.h

cd "$S"
rm -rf newlib gcc47 zlib-1.3.1 libc_x
dpkg-deb -x newlib-spu.deb newlib
dpkg-deb -x gcc-4.7-spu.deb gcc47
tar xzf zlib-1.3.1.tar.gz
NL=$S/newlib/usr/spu
GL=$S/gcc47/usr/spu/lib/gcc-cross/spu/4.7
spu-elf-gcc --version | head -1

# zlib example, linked against Ubuntu's C library and libgcc
(cd zlib-1.3.1 &&
	for f in adler32 compress crc32 deflate gzclose gzlib gzread gzwrite infback inffast \
		inflate inftrees trees uncompr zutil test/example; do
		spu-elf-gcc -O2 -g -isystem "$NL/include" -isystem "$GL/include" -I. -c $f.c -o "$(basename $f).o"
	done &&
	spu-elf-gcc -nostdlib -o "$O/zlib_example.elf" "$NL/lib/crt1.o" "$NL/lib/crti.o" "$GL/crtbegin.o" \
		./*.o -L"$NL/lib" -L"$GL" -lc -lgloss -lc -lgcc "$GL/crtend.o" "$NL/lib/crtn.o")

# libm and libc as relocatable objects (-z muldefs: newlib defines some aliases twice)
spu-elf-ld -r -z muldefs --whole-archive "$NL/lib/libm.a" -o "$O/libm_all.o"
mkdir libc_x && (cd libc_x && spu-elf-ar x "$NL/lib/libc.a")
mapfile -t M < <(spu-elf-ar t "$NL/lib/libc.a" | sort)
H=$((${#M[@]} / 2))
(cd libc_x && spu-elf-ld -r -z muldefs -o "$O/libc_a.o" "${M[@]:0:$H}")
(cd libc_x && spu-elf-ld -r -z muldefs -o "$O/libc_b.o" "${M[@]:$H}")

# kernel local-store images
python3 "$HERE/hexdump2bin.py" spu_save_dump.h "$O/spu_save.bin"
python3 "$HERE/hexdump2bin.py" spu_restore_dump.h "$O/spu_restore.bin"

# every relocation type
spu-elf-as -o reloc_types_plain.o "$HERE/reloc_types.s"
python3 "$HERE/addpic.py" reloc_types_plain.o "$O/reloc_types.o"
ls -l "$O"
