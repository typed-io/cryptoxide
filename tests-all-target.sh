#!/bin/sh
#
# Run the test suite across every backend the crate can select at compile time.
#
# Several primitives (AES, ChaCha/Salsa, SHA-2, BLAKE2, poly1305) ship both an
# accelerated backend (SIMD / CPU crypto instructions) and a portable software
# ("reference") backend. Which one is compiled in is decided at build time from
# the target features, so the only way to exercise them all is to re-run the
# suite under different target-feature / target-cpu configurations (and, for the
# x86 SIMD backends, to cross-compile to an x86-64 target and run the result).
#
# Backends covered:
#   * aarch64: NEON ChaCha/Salsa, SHA-2 (sha2/sha3 ext.), AES (crypto ext.)
#   * x86-64:  SSE2 ChaCha, SSE4.1/AVX SHA-256, AVX/AVX2 BLAKE2
#   * software: reference AES, reference ChaCha/Salsa/SHA-2/BLAKE2
#   * 32-bit software arithmetic: poly1305 donna32

set -e

ARCH=$(uname -m)
OS=$(uname -s)

# Is the host an aarch64 / arm64 machine?
ARM=0
case "$ARCH" in
    arm64 | aarch64) ARM=1 ;;
esac

# x86-64 target used for the cross-compiled SIMD matrix.
if [ "$OS" = "Darwin" ]; then
    TARGET_X86_64="x86_64-apple-darwin"
else
    TARGET_X86_64="x86_64-unknown-linux-gnu"
fi

# Can we cross-compile to that x86-64 target?
X86_BUILD=0
if rustup target list --installed 2>/dev/null | grep -qx "$TARGET_X86_64"; then
    X86_BUILD=1
fi

# Can we *execute* x86-64 binaries (native x86-64, or Rosetta 2 on Apple Silicon)?
X86_RUN=0
case "$ARCH" in
    x86_64 | amd64) X86_RUN=1 ;;
    *)
        if [ "$OS" = "Darwin" ] && arch -x86_64 /usr/bin/true >/dev/null 2>&1; then
            X86_RUN=1
        fi
        ;;
esac

# run <label> <rustflags> <cargo args...>
run() {
    label=$1
    flags=$2
    shift 2
    echo
    echo "==== $label"
    echo "     RUSTFLAGS=\"$flags\" cargo $*"
    RUSTFLAGS="$flags" cargo "$@"
}

# ------------------------------------------------------------------
# Native host backends
# ------------------------------------------------------------------
echo "################ native host backends ($ARCH) ################"

# Accelerated backends provided by the host's default target features.
run "native: default target features (accelerated)" "" test

# Everything the host CPU actually supports.
run "native: target-cpu=native" "-C target-cpu=native" test

if [ $ARM -eq 1 ]; then
    # Drop the aarch64 crypto extensions -> reference AES + reference SHA-2,
    # while keeping the NEON ChaCha/Salsa backends.
    run "native: software crypto (AES reference, SHA-2 reference)" \
        "-C target-feature=-aes,-sha2,-sha3" test
    # Also drop NEON -> reference ChaCha/Salsa as well.
    # NOTE: disabling the baseline NEON feature emits an ABI phase-out warning;
    # the self-contained test binary is internally consistent and stays valid.
    run "native: all software (also reference ChaCha/Salsa)" \
        "-C target-feature=-neon,-aes,-sha2,-sha3" test
else
    # On x86-64 the reference SHA-2/BLAKE2 engines are already used at the
    # baseline; dropping SSE2 additionally selects the reference ChaCha/Salsa.
    # NOTE: disabling the baseline SSE2 feature emits an ABI phase-out warning.
    run "native: all software (reference backends)" \
        "-C target-feature=-sse2" test
fi

# 32-bit software arithmetic: poly1305 32 bits
run "native: force-32bits donna32" "" test --features force-32bits

# ------------------------------------------------------------------
# x86-64 SIMD backend matrix
# ------------------------------------------------------------------
echo
echo "################ x86-64 SIMD backend matrix ################"

if [ $X86_BUILD -eq 0 ]; then
    echo "==== SKIP: target $TARGET_X86_64 not installed"
    echo "     install it with: rustup target add $TARGET_X86_64"
else
    if [ $X86_RUN -eq 0 ]; then
        echo "note: cannot execute x86-64 binaries on this host -- compile-checking only."
        if [ "$OS" = "Darwin" ]; then
            echo "      (install Rosetta 2 to run them: softwareupdate --install-rosetta)"
        fi
    fi

    # Each CPU model enables a superset of SIMD features, selecting different
    # backends:
    #   core2        SSE2/SSSE3   -> SSE2 ChaCha; reference SHA-2/BLAKE2
    #   nehalem      +SSE4.1      -> SSE4.1 SHA-256
    #   sandybridge  +AVX         -> AVX SHA-256, AVX BLAKE2
    #   broadwell    +AVX2        -> AVX2 BLAKE2
    for cpu in core2 nehalem sandybridge broadwell; do
        # Rosetta 2 does not implement AVX/AVX2, so those variants SIGILL under
        # emulation -> only build (never run) them on Apple Silicon.
        avx=0
        case "$cpu" in
            sandybridge | broadwell) avx=1 ;;
        esac

        if [ $X86_RUN -eq 1 ] && ! { [ $ARM -eq 1 ] && [ $avx -eq 1 ]; }; then
            run "x86-64 $cpu (run)" "-C target-cpu=$cpu" test --target "$TARGET_X86_64"
        else
            run "x86-64 $cpu (build-only)" "-C target-cpu=$cpu" build --target "$TARGET_X86_64"
        fi
    done

    # Reference backends on x86-64 (no SSE2 -> reference ChaCha/Salsa).
    # NOTE: disabling the baseline SSE2 feature emits an ABI phase-out warning.
    if [ $X86_RUN -eq 1 ]; then
        run "x86-64 reference (no SSE2)" "-C target-feature=-sse2" \
            test --target "$TARGET_X86_64"
    else
        run "x86-64 reference (no SSE2, build-only)" "-C target-feature=-sse2" \
            build --target "$TARGET_X86_64"
    fi

    # 32-bit software arithmetic on x86-64.
    if [ $X86_RUN -eq 1 ]; then
        run "x86-64 force-32bits (run)" "" \
            test --target "$TARGET_X86_64" --features force-32bits
    else
        run "x86-64 force-32bits (build-only)" "" \
            build --target "$TARGET_X86_64" --features force-32bits
    fi
fi

echo
echo "==== all backend configurations completed"
