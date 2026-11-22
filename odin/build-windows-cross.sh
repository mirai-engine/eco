#!/bin/sh
# Produce a Windows x64 PE using the LLVM-MinGW UCRT toolchain and Odin.
set -eu
if [ "$#" -ne 1 ]; then printf 'usage: %s /absolute/path/to/llvm-mingw/bin\n' "$0" >&2; exit 2; fi
toolchain=$(cd "$1" && pwd)
cd "$(dirname "$0")/.."
./odin/build.sh deps
target=.eco-deps/windows_amd64
mkdir -p "$target" bin
compiler="$toolchain/x86_64-w64-mingw32-clang"
for source in odin/platform_windows_io.c odin/platform_windows_fs.c \
              odin/platform_windows_process.c .eco-deps/kcp/ikcp.c; do
    "$compiler" -O2 -Wall -Wextra -Werror -Wno-unused-parameter -c "$source" \
        -o "$target/$(basename "$source" .c).obj"
done
"$toolchain/llvm-ar" rcs "$target/eco_platform.lib" \
    "$target/platform_windows_io.obj" "$target/platform_windows_fs.obj" \
    "$target/platform_windows_process.obj" "$target/ikcp.obj"
cp "$target/eco_platform.lib" .eco-deps/eco_platform.lib
"${ODIN:-odin}" build odin -target:windows_amd64 -build-mode:obj -out:"$target/eco.obj" \
    "-collection:deps=$PWD/.eco-deps" -o:speed
# Arguments must arrive as UTF-16 and reach os.args as UTF-8: an Odin whose Windows entry point is
# `main` gets them in the ANSI code page, which mangles every non-ASCII path.
if ! "$toolchain/llvm-nm" "$target/eco.obj" | grep -q ' T wmain$'; then
    printf '%s: this Odin has no wmain entry point; use Odin dev-2026-11 or newer\n' "$0" >&2
    exit 1
fi

# Odin emits these MSVC runtime references. MinGW has the equivalent x64 stack probe.
cat > "$target/cross_crt.c" <<'SRC'
int _fltused = 0x9875;
#pragma comment(linker, "/alternatename:__chkstk=___chkstk_ms")
SRC
"$compiler" -fms-extensions -c "$target/cross_crt.c" -o "$target/cross_crt.obj"
"$compiler" -municode -Wl,--subsystem,console -o bin/eco.exe "$target/eco.obj" \
    "$target/cross_crt.obj" "$target/eco_platform.lib" -lws2_32 -ladvapi32 -lbcrypt -liphlpapi -luserenv -lole32 -lntdll
