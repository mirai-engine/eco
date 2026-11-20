#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p .eco-deps bin

if [ "${1:-}" = desktop ]; then
    if [ "$(uname -s)" != Darwin ]; then
        echo "the desktop helper requires macOS 14 or newer" >&2
        exit 1
    fi
    "${CC:-cc}" -mmacosx-version-min=14.0 -std=c11 -O2 -c odin/platform.c -o .eco-deps/desktop-platform.o
    "${CC:-cc}" -mmacosx-version-min=14.0 -std=c11 -O2 -c odin/platform_linux.c -o .eco-deps/desktop-linux.o
    shift
    exec swiftc -O -parse-as-library -target "$(uname -m)-apple-macosx14.0" \
        -import-objc-header odin/desktop_ipc.h odin/desktop_macos.swift \
        .eco-deps/desktop-platform.o .eco-deps/desktop-linux.o -o bin/eco-desktop "$@"
fi

dependency() {
    name=$1 url=$2 revision=$3
    dir=".eco-deps/$name"
    if [ ! -d "$dir/.git" ]; then
        git init -q "$dir"
    fi
    if ! git -C "$dir" cat-file -e "$revision^{commit}" 2>/dev/null; then
        git -C "$dir" fetch -q --depth 1 "$url" "$revision"
    fi
    git -C "$dir" checkout -q --detach "$revision"
}

dependency blake3 https://github.com/mirai-engine/odin-blake3.git d937acf940a85fa26b2ec207df51b9bda04f6c20
dependency kcp https://github.com/skywind3000/kcp.git b1a7a2101dcbb96017681a500d6b82bbe5a88766

if [ "${1:-}" = deps ]; then exit 0; fi

"${CC:-cc}" -O3 -c .eco-deps/kcp/ikcp.c -o .eco-deps/ikcp.o
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror -Wno-deprecated-declarations -O2 -c odin/platform.c -o .eco-deps/platform.o
linux_flags=
link_flags=
if [ "$(uname -s)" = Linux ]; then
    link_flags="-extra-linker-flags:-lutil"
    if command -v pkg-config >/dev/null && pkg-config --exists liburing; then
        linux_flags="-DECO_HAVE_LIBURING=1"
        link_flags="-extra-linker-flags:-lutil -luring"
    fi
fi
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror -O2 $linux_flags -c odin/platform_linux.c -o .eco-deps/platform_linux.o
if command -v pkg-config >/dev/null && pkg-config --exists libcrypto; then
    crypto_dir=$(pkg-config --variable=libdir libcrypto)
    crypto_name=libcrypto.so
    if [ "$(uname -s)" = Darwin ]; then crypto_name=libcrypto.dylib; fi
    "${CC:-cc}" -std=c11 -Wall -Wextra -Werror -O2 $(pkg-config --cflags libcrypto) \
        "-DECO_LIBCRYPTO=\"$crypto_dir/$crypto_name\"" -c odin/platform_crypto.c -o .eco-deps/platform_crypto.o
else
    "${CC:-cc}" -std=c11 -Wall -Wextra -Werror -O2 -c odin/platform_crypto.c -o .eco-deps/platform_crypto.o
fi
ar rcs .eco-deps/libeco_platform.a .eco-deps/ikcp.o .eco-deps/platform.o .eco-deps/platform_linux.o .eco-deps/platform_crypto.o

lock_flags="-collection:deps=$PWD/.eco-deps"
if [ "${1:-}" = test ]; then
    shift
    exec "${ODIN:-odin}" test odin "$lock_flags" ${link_flags:+"$link_flags"} "$@"
fi
exec "${ODIN:-odin}" build odin "$lock_flags" ${link_flags:+"$link_flags"} -o:speed -out:bin/eco "$@"
