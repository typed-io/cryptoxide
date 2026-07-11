#!/bin/sh
#
# Run the test suite under Miri.
#
# Miri interprets MIR and does not implement the CPU crypto/SIMD intrinsics used
# by the accelerated backends (aarch64 NEON/AES/SHA, x86 SSE2/SSE4.1/AVX/AVX2).
# Those backends are selected at build time from the target features, so we
# disable the relevant features here to force the portable software ("reference")
# backends, which Miri can interpret.
#
# Usage: ./tests-miri.sh [extra cargo miri test args...]
#   e.g. ./tests-miri.sh aes::      # only the AES tests

set -e

ARCH=$(uname -m)

# Target features to turn off so the pure-software backends get compiled in.
case "$ARCH" in
    arm64 | aarch64)
        # NEON -> reference ChaCha/Salsa; aes/sha2/sha3 -> reference AES + SHA-2/3.
        # NOTE: disabling the baseline NEON feature emits an ABI phase-out
        # warning; the self-contained Miri test binary stays internally
        # consistent and valid.
        DISABLE="-neon,-aes,-sha2,-sha3"
        ;;
    x86_64 | amd64)
        # SSE2 -> reference ChaCha/Salsa; disabling it cascades to SSE4.1/AVX/AVX2,
        # selecting the reference SHA-2/BLAKE2 backends as well.
        # NOTE: disabling the baseline SSE2 feature emits an ABI phase-out warning.
        DISABLE="-sse2"
        ;;
    *)
        DISABLE=""
        ;;
esac

RUSTFLAGS="-C target-feature=$DISABLE"
export RUSTFLAGS

echo "==== cargo +nightly miri test  (software backends, $ARCH)"
echo "     RUSTFLAGS=\"$RUSTFLAGS\""
echo

exec cargo +nightly miri test "$@"
