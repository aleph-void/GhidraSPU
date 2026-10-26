#!/usr/bin/env bash
# Build the GNU SPU toolchain the tests use: binutils 2.45 (spu-elf-as/ld/objdump; also the
# libopcodes slotdis.c links against) and GCC 6.5.0 (C compiler only; GCC dropped the SPU port
# after GCC 8), from pinned upstream tarballs.  The C library (newlib) and libgcc come from
# Ubuntu's prebuilt SPU packages, see fetch-real-samples.sh.
#   test/build-toolchain.sh <workdir> <prefix>
# Afterwards put <prefix>/bin on PATH. Needs a host C/C++ compiler, make, curl; GCC's
# prerequisites (gmp, mpfr, mpc) are downloaded in-tree by contrib/download_prerequisites.
# GCC 6.5 predates current host compilers: it is built with -std=gnu99 / -std=gnu++98.
set -euo pipefail
W=$(mkdir -p "$1" && cd "$1" && pwd)
P=$(mkdir -p "$2" && cd "$2" && pwd)
J=${JOBS:-$(nproc)}
fetch() { # url sha256
	local f=$W/$(basename "$1")
	[[ -f $f ]] || curl -fsSL -o "$f" "$1"
	echo "$2  $f" | sha256sum -c --quiet
}
fetch https://ftp.gnu.org/gnu/binutils/binutils-2.45.tar.xz c50c0e7f9cb188980e2cc97e4537626b1672441815587f1eab69d2a1bfbef5d2
fetch https://ftp.gnu.org/gnu/gcc/gcc-6.5.0/gcc-6.5.0.tar.xz 7ef1796ce497e89479183702635b14bb7a46b53249209a5e0f999bebf4740945
cd "$W"
[[ -d binutils-2.45 ]] || tar xf binutils-2.45.tar.xz
[[ -d gcc-6.5.0 ]] || { tar xf gcc-6.5.0.tar.xz; (cd gcc-6.5.0 && ./contrib/download_prerequisites); }
mkdir -p build-binutils build-gcc
(cd build-binutils && ../binutils-2.45/configure --target=spu-elf --prefix="$P" --disable-nls \
	--disable-werror --disable-gdb --disable-sim --disable-gprofng && make -j"$J" && make install)
export PATH=$P/bin:$PATH
(cd build-gcc && CFLAGS="-O2 -g0 -std=gnu99 -w" CXXFLAGS="-O2 -g0 -std=gnu++98 -fpermissive -w" \
	../gcc-6.5.0/configure --target=spu-elf --prefix="$P" --enable-languages=c --with-newlib \
	--without-headers --disable-nls --disable-libssp --disable-shared --disable-threads \
	--disable-libquadmath --without-isl --disable-werror --disable-multilib &&
	make -j"$J" MAKEINFO=true all-gcc && make install-gcc MAKEINFO=true)
echo "toolchain in $P/bin"
