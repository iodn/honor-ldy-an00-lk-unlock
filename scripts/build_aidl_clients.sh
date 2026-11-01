#!/usr/bin/env bash
# Build the two Android AArch64 clients used by the inactive-B executor.
#
#   read_only_client      - getters only; used for the preflight gate.
#   inactive_b_client_ver - full interface; setActiveBootSlot mutator.
#
# The tested binaries were built with:
#   NDK 27.0.12077973 (clang 18.0.1)
#   AIDL compiler (build-tools 34/35), --lang=ndk
#   -O2 -fPIE -pie -static-libstdc++
#
# A rebuild can produce a different SHA-256 for the same source. The executor
# pins the phone-tested mutation-client hash; if you rebuild, review the source
# and set LK_MUTATION_CLIENT_SHA to your local hash, or use the tested binary.
set -euo pipefail
cd "$(dirname "$0")"

AIDL="${AIDL:-aidl}"
NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-/usr/lib/android-sdk/ndk/27.0.12077973}}"
API="${API:-34}"
HOST_TAG="${HOST_TAG:-linux-x86_64}"
OUT="${OUT:-$PWD/out}"
GEN="$OUT/aidl-gen"
IFACE_HASH="2400346954240a5de495a1debc81429dd012d7b7"
CXX="$NDK/toolchains/llvm/prebuilt/$HOST_TAG/bin/aarch64-linux-android$API-clang++"

command -v "$AIDL" >/dev/null 2>&1 || {
    echo "error: aidl not found (set AIDL=/path/to/aidl)" >&2; exit 1; }
[ -x "$CXX" ] || {
    echo "error: NDK clang++ not found at $CXX" >&2
    echo "       set ANDROID_NDK_HOME to an NDK 27+ tree" >&2
    exit 1
}
mkdir -p "$GEN" "$OUT"

echo "[*] generating NDK AIDL headers"
"$AIDL" --lang=ndk --structured --stability=vintf -v 1 --hash "$IFACE_HASH" \
    -I aidl -o "$GEN" -h "$GEN" \
    aidl/android/hardware/boot/MergeStatus.aidl \
    aidl/android/hardware/boot/IBootControl.aidl

build() {
    local src="$1" out="$2"
    echo "[*] compiling $src"
    "$CXX" -O2 -std=c++17 -fPIE -pie -static-libstdc++ \
        -ffile-prefix-map="$PWD"=. -ffile-prefix-map="$NDK"=/android-ndk -I "$GEN" \
        -o "$OUT/$out" "$src" \
        "$GEN/android/hardware/boot/IBootControl.cpp" \
        "$GEN/android/hardware/boot/MergeStatus.cpp" \
        -lbinder_ndk -llog -ldl -lm
    echo "[+] $OUT/$out"
    sha256sum "$OUT/$out"
}

build read_only_client.cpp read_only_client
build inactive_b_client.cpp inactive_b_client_ver

cat <<EOF

Reference hashes of the phone-tested binaries:
  inactive_b_client_ver  2f3d1dea3df37fb64932eddde9f4ab56adc7f55737e594d1d2da46081ae80041
The read-only deployed binary was built from a getter-only AIDL subset; this
build uses the full interface but the read-only source calls getters only.
If your rebuild hashes differ, set LK_MUTATION_CLIENT_SHA before running the
executor (after reviewing the source).
EOF
