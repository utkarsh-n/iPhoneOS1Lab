#!/bin/bash
set -euo pipefail

project_root="$(cd "$(dirname "$0")/.." && pwd)"
source_root="$project_root/vendor/qemu"
source_alias="${IPHONEOS1_SOURCE_ALIAS:-$HOME/iphoneos1-qemu-source}"
build_root="${IPHONEOS1_BUILD_ROOT:-$HOME/iphoneos1-qemu-build}"
ninja="${NINJA:-$(command -v ninja)}"
openssl_prefix="/opt/homebrew/opt/openssl@3.3"
build_jobs="${IPHONEOS1_BUILD_JOBS:-1}"
[[ "$build_jobs" =~ ^[1-9][0-9]*$ ]]

# QEMU 6.2's configure script explicitly rejects whitespace in its paths.
if [[ -L "$source_alias" ]]; then
    [[ "$(readlink "$source_alias")" == "$source_root" ]]
elif [[ -e "$source_alias" ]]; then
    printf 'Source alias already exists: %s\n' "$source_alias" >&2
    exit 1
else
    ln -s "$source_root" "$source_alias"
fi
mkdir -p "$build_root" "$project_root/reports"
if [[ ! -e "$source_root/build-host" ]]; then
    ln -s "$build_root" "$source_root/build-host"
fi

git -C "$source_root" submodule update --init \
    meson dtc ui/keycodemapdb \
    tests/fp/berkeley-softfloat-3 tests/fp/berkeley-testfloat-3
cd "$build_root"
"$source_alias/configure" \
    --target-list=arm-softmmu \
    --enable-sdl --disable-cocoa \
    --disable-capstone --disable-pie --disable-slirp \
    --disable-docs --disable-werror \
    --ninja="$ninja" \
    --extra-cflags="-I$openssl_prefix/include" \
    --extra-ldflags="-L$openssl_prefix/lib -lcrypto" \
    > "$project_root/reports/qemu-configure.log" 2>&1
"$ninja" -j"$build_jobs" qemu-system-arm qemu-img \
    > "$project_root/reports/qemu-build.log" 2>&1
"$build_root/qemu-system-arm" --version
"$build_root/qemu-system-arm" -machine help
