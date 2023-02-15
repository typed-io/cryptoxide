#!/bin/sh

set -e

ARM=0
MAC=0

ARCH=`uname -m`

if [ "$ARCH" == "arm64" ]; then
	ARM=1
fi
if [[ "$OSTYPE" == "darwin"* ]]; then
	MAC=1
fi

TARGET_X86_64="x86_64-unknown-unknown"
if [ $MAC -eq 1 ]; then
	TARGET_X86_64="x86_64-apple-darwin"
fi

# native testing
cargo test

# 32bits x86 testing
for flag in force-32bits
do
    cargo test --features $flag --target $TARGET_X86_64
done

# x86-64 architecture testing
if [ $ARM -eq 1 ]; then
	# TODO : sandybridge & broadwell triggers a SIGILL, investigate why.
	# possibly according to
	# https://developer.apple.com/documentation/apple-silicon/about-the-rosetta-translation-environment
	# AVX, AVX2, AVX512 instruction sets are not supported
	X86_VARIANTS="core2 nehalem"
else
	X86_VARIANTS="core2 nehalem sandybridge broadwell"
fi

for arch in $X86_VARIANTS
do
    echo "#### testing x86-64 $arch variant"
    RUSTFLAGS="-C target_cpu=$arch" cargo test --target $TARGET_X86_64
done

# native optimisation testing
RUSTFLAGS="-C target_cpu=native" cargo test
