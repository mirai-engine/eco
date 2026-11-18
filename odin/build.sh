#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p .eco-deps bin

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

"${CC:-cc}" -O3 -c .eco-deps/kcp/ikcp.c -o .eco-deps/ikcp.o
"${CC:-cc}" -std=c11 -Wall -Wextra -Werror -Wno-deprecated-declarations -O2 -c odin/platform.c -o .eco-deps/platform.o
ar rcs .eco-deps/libeco_platform.a .eco-deps/ikcp.o .eco-deps/platform.o

lock_flags="-collection:deps=$PWD/.eco-deps"
if [ "${1:-}" = test ]; then
    shift
    exec "${ODIN:-odin}" test odin "$lock_flags" "$@"
fi
exec "${ODIN:-odin}" build odin "$lock_flags" -o:speed -out:bin/eco-odin "$@"
