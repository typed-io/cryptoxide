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
#   * 32-bit ARM (target_arch=arm): all reference backends, with poly1305
#     donna32 selected from target_arch alone (no force-32bits) -- plus a
#     no_std bare-metal compile check (thumbv7m-none-eabi)
#   * RISC-V (target_arch=riscv32/riscv64): all reference backends; poly1305
#     uses donna32 on riscv32 and donna64 on riscv64

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

# ------------------------------------------------------------------
# 32-bit ARM backends (target_arch = "arm")
# ------------------------------------------------------------------
echo
echo "################ 32-bit ARM backend matrix ################"
#
# On 32-bit ARM none of the aarch64 accelerated backends apply, so every
# primitive falls back to its reference/software backend. What is unique to this
# target is that poly1305 selects the 32-bit "donna32" arithmetic from
# target_arch = "arm" alone -- a cfg branch that no other configuration in this
# matrix reaches (elsewhere it is only taken via the force-32bits feature). It
# also compiles the whole crate under a 32-bit pointer width, which is the
# environment the crate is meant to support on embedded devices.
#
# 32-bit ARM binaries cannot run on this host unless it is itself a 32-bit ARM
# machine, so both configs below are compile-checks by default. Building only the
# library (rlib) needs no linker, which is why the cross checks work without an
# ARM toolchain installed.

# 32-bit ARM Linux target (std), used for the cross build/run check.
TARGET_ARM32="armv7-unknown-linux-gnueabihf"
# Bare-metal ARMv7-M target (no_std) -- matches the crate's embedded use case.
TARGET_ARM32_BARE="thumbv7m-none-eabi"

# Can we *execute* 32-bit ARM binaries? Only on a native 32-bit ARM host.
ARM32_RUN=0
case "$ARCH" in
    armv6l | armv7l | armhf | arm) ARM32_RUN=1 ;;
esac

# (1) Bare-metal ARMv7-M, no_std. Always a compile-check: there is no test
#     harness without std. Building the library needs no linker, so this runs
#     anywhere the target is installed.
if rustup target list --installed 2>/dev/null | grep -qx "$TARGET_ARM32_BARE"; then
    run "arm32 bare-metal $TARGET_ARM32_BARE (build-only, no_std)" "" \
        build --target "$TARGET_ARM32_BARE"
else
    echo "==== SKIP: target $TARGET_ARM32_BARE not installed"
    echo "     install it with: rustup target add $TARGET_ARM32_BARE"
fi

# (2) 32-bit ARM Linux (std). Runs the full suite on a native 32-bit ARM host;
#     everywhere else it is a cross-compile check of the library.
if rustup target list --installed 2>/dev/null | grep -qx "$TARGET_ARM32"; then
    if [ $ARM32_RUN -eq 1 ]; then
        run "arm32 $TARGET_ARM32 (run)" "" test --target "$TARGET_ARM32"
    else
        echo "note: cannot execute 32-bit ARM binaries on this host -- compile-checking only."
        run "arm32 $TARGET_ARM32 (build-only)" "" build --target "$TARGET_ARM32"
    fi
else
    echo "==== SKIP: target $TARGET_ARM32 not installed"
    echo "     install it with: rustup target add $TARGET_ARM32"
fi

# ------------------------------------------------------------------
# RISC-V backends (target_arch = "riscv32" / "riscv64")
# ------------------------------------------------------------------
echo
echo "################ RISC-V backend matrix ################"
#
# RISC-V has no accelerated backends in this crate, so every primitive uses its
# reference implementation. The interesting split is poly1305's arithmetic:
# exactly like arm32, the 32-bit target (riscv32) selects the "donna32" backend
# from target_arch alone, while the 64-bit target (riscv64) uses "donna64".
# riscv32 is the only 64-bit-free way (besides force-32bits) to exercise donna32.
#
# As with ARM, RISC-V binaries only run on a native RISC-V host; elsewhere these
# are library compile-checks (rlib, no linker required).

# 32-bit RISC-V, bare-metal (no_std) -- exercises riscv32 -> donna32.
TARGET_RISCV32_BARE="riscv32imac-unknown-none-elf"
# 64-bit RISC-V Linux (std) -- exercises riscv64 -> donna64, runnable on a host.
TARGET_RISCV64="riscv64gc-unknown-linux-gnu"

# Can we *execute* riscv64 binaries? Only on a native riscv64 host.
RISCV64_RUN=0
case "$ARCH" in
    riscv64) RISCV64_RUN=1 ;;
esac

# (1) Bare-metal 32-bit RISC-V, no_std. Always a compile-check: there is no test
#     harness without std. Building the library needs no linker.
if rustup target list --installed 2>/dev/null | grep -qx "$TARGET_RISCV32_BARE"; then
    run "riscv32 bare-metal $TARGET_RISCV32_BARE (build-only, no_std)" "" \
        build --target "$TARGET_RISCV32_BARE"
else
    echo "==== SKIP: target $TARGET_RISCV32_BARE not installed"
    echo "     install it with: rustup target add $TARGET_RISCV32_BARE"
fi

# (2) 64-bit RISC-V Linux (std). Runs the full suite on a native riscv64 host;
#     everywhere else it is a cross-compile check of the library.
if rustup target list --installed 2>/dev/null | grep -qx "$TARGET_RISCV64"; then
    if [ $RISCV64_RUN -eq 1 ]; then
        run "riscv64 $TARGET_RISCV64 (run)" "" test --target "$TARGET_RISCV64"
    else
        echo "note: cannot execute RISC-V binaries on this host -- compile-checking only."
        run "riscv64 $TARGET_RISCV64 (build-only)" "" build --target "$TARGET_RISCV64"
    fi
else
    echo "==== SKIP: target $TARGET_RISCV64 not installed"
    echo "     install it with: rustup target add $TARGET_RISCV64"
fi

echo
echo "==== all backend configurations completed"
