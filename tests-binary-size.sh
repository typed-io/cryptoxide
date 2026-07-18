#!/usr/bin/env bash
#
# binary-size.sh — dump the machine-code / data size of each part of cryptoxide.
#
# cryptoxide is a library crate carved up into per-algorithm cargo features
# (see the `[features]` table in Cargo.toml). This script builds the crate once
# per feature — in isolation, with `--no-default-features --features <feat>` —
# and measures the size of the code (.text) and constant data it pulls in, so
# you can see how much each algorithm actually costs. This matters because the
# crate explicitly targets constrained environments (embedded / WASM).
#
# How it measures: each `cargo build` produces an rlib, which is an `ar` archive
# of object files. We extract the objects and sum their section sizes with the
# `size` tool. Because a feature auto-enables its dependencies (e.g. `ed25519`
# pulls in `sha2` + `curve25519`), the number reported for a feature is the
# *total* cost of turning it on from nothing — which is what you care about.
#
# The `<baseline>` row is the crate with no features at all (the always-compiled
# scaffolding: hashing framework, drg, kdf, constant_time, ...). The `Δ vs base`
# column is a feature's marginal cost over that baseline.
#
# Usage:
#   scripts/binary-size.sh [options] [feature ...]
#
# Options:
#   --target <triple>   Build for a target triple (default: host).
#                       NOTE: the section-size breakdown needs a `size` that can
#                       read the target's object format. macOS's system `size`
#                       only reads Mach-O; for ELF/WASM targets install
#                       llvm-tools (`llvm-size`) or GNU binutils (`gsize`), else
#                       the script falls back to raw rlib byte size only.
#   --opt-level <lvl>   opt-level to build with: 0 1 2 3 s z (default: z, the
#                       size-optimized level most relevant for this crate; use 3
#                       to see the speed-optimized footprint).
#   --lto               Enable fat LTO (default: off).
#   --csv               Emit CSV instead of a formatted table.
#   --keep-going        Don't stop reporting if a feature fails to build (it is
#                       marked BUILD-FAILED). This is the default; flag kept for
#                       clarity.
#   -h, --help          Show this help.
#
# Positional args: if you pass one or more feature names, only those are
# measured (plus baseline). With no positional args, every real feature from
# Cargo.toml is measured, followed by the `default` and `all` feature sets.
#
# Examples:
#   scripts/binary-size.sh                     # full report, size-optimized
#   scripts/binary-size.sh --opt-level 3       # speed-optimized footprint
#   scripts/binary-size.sh sha2 ed25519 chacha # just these three
#   scripts/binary-size.sh --csv > sizes.csv   # machine-readable

set -u

# ---------------------------------------------------------------------------
# locate repo root (script lives in <root>/scripts/)
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR" && pwd)"
cd "$ROOT" || exit 1

if [ ! -f Cargo.toml ]; then
    echo "error: Cargo.toml not found in $ROOT" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# option parsing
# ---------------------------------------------------------------------------
TARGET=""
OPT_LEVEL="z"
LTO="false"
OUTPUT="table"   # table | csv
POSITIONAL=()

while [ $# -gt 0 ]; do
    case "$1" in
        --target)     TARGET="${2:-}"; shift 2 ;;
        --target=*)   TARGET="${1#*=}"; shift ;;
        --opt-level)  OPT_LEVEL="${2:-}"; shift 2 ;;
        --opt-level=*) OPT_LEVEL="${1#*=}"; shift ;;
        --lto)        LTO="true"; shift ;;
        --csv)        OUTPUT="csv"; shift ;;
        --keep-going) shift ;;   # default behavior
        -h|--help)
            sed -n '2,/^set -u/{/^set -u/d;s/^# \{0,1\}//;p;}' "$0"
            exit 0 ;;
        --*)
            echo "error: unknown option '$1'" >&2; exit 1 ;;
        *)
            POSITIONAL+=("$1"); shift ;;
    esac
done

# ---------------------------------------------------------------------------
# where cargo drops artifacts, and helpers for the chosen target
# ---------------------------------------------------------------------------
if [ -n "$TARGET" ]; then
    DEPS_DIR="target/$TARGET/release/deps"
    TARGET_ARGS=(--target "$TARGET")
    TARGET_LABEL="$TARGET"
else
    DEPS_DIR="target/release/deps"
    TARGET_ARGS=()
    TARGET_LABEL="$(rustc -vV | awk '/^host:/{print $2}')"
fi

# stat portability: BSD/macOS vs GNU
file_size() {
    stat -f%z "$1" 2>/dev/null || stat -c%s "$1" 2>/dev/null || echo 0
}

# ---------------------------------------------------------------------------
# pick a `size` tool and figure out which output dialect it speaks.
#   - cctools (macOS):   `size -m`  (Mach-O only)  -> SIZE_MODE=mach
#   - GNU / llvm:        `size -A`  (sysv, ELF/etc) -> SIZE_MODE=sysv
# If nothing can read the objects we set SIZE_MODE=none and fall back to
# reporting only the raw rlib byte size.
# ---------------------------------------------------------------------------
SIZE_BIN=""
SIZE_MODE="none"
pick_size_tool() {
    local candidates=()
    [ -n "${SIZE:-}" ] && candidates+=("$SIZE")
    candidates+=(llvm-size gsize size)
    local c
    for c in "${candidates[@]}"; do
        command -v "$c" >/dev/null 2>&1 || continue
        SIZE_BIN="$c"
        # sysv format (`-A`) is understood by GNU and llvm size; cctools rejects it.
        if "$c" -A "$0" >/dev/null 2>&1; then
            SIZE_MODE="sysv"
        else
            SIZE_MODE="mach"
        fi
        return 0
    done
    return 1
}
pick_size_tool || true

# ---------------------------------------------------------------------------
# measure_code_data <objfile>...  -> echoes "<code_bytes> <data_bytes>"
#   code = executable machine code (.text / __text)
#   data = read-only + writable constant data (tables, strings), excluding
#          unwind/debug metadata which isn't really "algorithm size".
# ---------------------------------------------------------------------------
measure_code_data() {
    case "$SIZE_MODE" in
        mach)
            "$SIZE_BIN" -m "$@" 2>/dev/null | awk '
                /\(__TEXT, __text\)/            { code += $NF }
                /__const\)|__cstring\)|__literal|__DATA, __data\)|__bss\)|__common\)/ { data += $NF }
                END { printf "%d %d", code+0, data+0 }'
            ;;
        sysv)
            "$SIZE_BIN" -A "$@" 2>/dev/null | awk '
                $1 == ".text"                                 { code += $2 }
                $1 ~ /^\.(rodata|data|bss|data\.rel\.ro|srodata|sdata)/ { data += $2 }
                END { printf "%d %d", code+0, data+0 }'
            ;;
        *)
            echo "0 0"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# build_and_measure <feature-spec>
#   feature-spec is what goes after --features, or "" for baseline.
#   echoes: "<status> <code> <data> <rlib_bytes>"
#   status is OK or FAIL.
# ---------------------------------------------------------------------------
BUILD_LOG="$(mktemp)"
trap 'rm -f "$BUILD_LOG"' EXIT

build_and_measure() {
    local feats="$1"
    local feat_args=()
    [ -n "$feats" ] && feat_args=(--features "$feats")

    # ensure exactly one rlib exists afterwards so the glob is unambiguous
    rm -f "$DEPS_DIR"/libcryptoxide-*.rlib 2>/dev/null

    # ${arr[@]+"${arr[@]}"} expands to nothing when the array is empty — the
    # bash-3.2-safe way to splat a possibly-empty array under `set -u`.
    if ! cargo build --release --quiet --no-default-features \
            ${feat_args[@]+"${feat_args[@]}"} ${TARGET_ARGS[@]+"${TARGET_ARGS[@]}"} \
            >"$BUILD_LOG" 2>&1; then
        echo "FAIL 0 0 0"
        return
    fi

    local rlib
    rlib="$(ls -t "$DEPS_DIR"/libcryptoxide-*.rlib 2>/dev/null | head -1)"
    if [ -z "$rlib" ]; then
        echo "FAIL 0 0 0"
        return
    fi

    local rlib_bytes
    rlib_bytes="$(file_size "$rlib")"

    local code=0 data=0
    if [ "$SIZE_MODE" != "none" ]; then
        local tmp
        tmp="$(mktemp -d)"
        ( cd "$tmp" && ar x "$ROOT/$rlib" 2>/dev/null )
        local objs=("$tmp"/*.o)
        if [ -e "${objs[0]}" ]; then
            read -r code data < <(measure_code_data "${objs[@]}")
        fi
        rm -rf "$tmp"
    fi

    echo "OK $code $data $rlib_bytes"
}

# ---------------------------------------------------------------------------
# build the list of feature specs to measure
# ---------------------------------------------------------------------------
# meta / non-algorithm / known-broken features we never measure on their own
EXCLUDE_RE='^(default|with-bench|force-32bits|digest)$'

all_features() {
    awk '/^\[features\]/{f=1;next} /^\[/{f=0} f && /=/{print $1}' Cargo.toml \
        | grep -vE "$EXCLUDE_RE" | grep -v '^$'
}

declare -a SPEC_NAMES=()   # label shown in the report
declare -a SPEC_FEATS=()   # actual --features string

add_spec() { SPEC_NAMES+=("$1"); SPEC_FEATS+=("$2"); }

# baseline is always first
add_spec "<baseline>" ""

if [ "${#POSITIONAL[@]}" -gt 0 ]; then
    for f in "${POSITIONAL[@]}"; do add_spec "$f" "$f"; done
else
    while IFS= read -r f; do add_spec "$f" "$f"; done < <(all_features)
    # composite reference points
    add_spec "(default set)" "__DEFAULT__"                 # build WITH default features
    add_spec "(all features)" "$(all_features | paste -sd, -)"
fi

# ---------------------------------------------------------------------------
# run measurements
# ---------------------------------------------------------------------------
LTO_LABEL="off"; [ "$LTO" = "true" ] && LTO_LABEL="fat"

export CARGO_PROFILE_RELEASE_OPT_LEVEL="$OPT_LEVEL"
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
export CARGO_PROFILE_RELEASE_LTO="$LTO"

# arrays holding results (explicit =() so they count as "set" under `set -u`)
R_NAME=(); R_STATUS=(); R_CODE=(); R_DATA=(); R_TOTAL=(); R_RLIB=()
base_total=0

emit_progress() { [ "$OUTPUT" = "table" ] && printf '  building %-16s\r' "$1" >&2; }

i=0
while [ "$i" -lt "${#SPEC_NAMES[@]}" ]; do
    name="${SPEC_NAMES[$i]}"
    feats="${SPEC_FEATS[$i]}"
    emit_progress "$name"

    if [ "$feats" = "__DEFAULT__" ]; then
        # special-case: build WITH default features
        rm -f "$DEPS_DIR"/libcryptoxide-*.rlib 2>/dev/null
        if cargo build --release --quiet ${TARGET_ARGS[@]+"${TARGET_ARGS[@]}"} >"$BUILD_LOG" 2>&1; then
            rlib="$(ls -t "$DEPS_DIR"/libcryptoxide-*.rlib 2>/dev/null | head -1)"
            rlib_bytes="$(file_size "$rlib")"
            code=0; data=0
            if [ "$SIZE_MODE" != "none" ] && [ -n "$rlib" ]; then
                tmp="$(mktemp -d)"
                ( cd "$tmp" && ar x "$ROOT/$rlib" 2>/dev/null )
                objs=("$tmp"/*.o)
                [ -e "${objs[0]}" ] && read -r code data < <(measure_code_data "${objs[@]}")
                rm -rf "$tmp"
            fi
            result="OK $code $data $rlib_bytes"
        else
            result="FAIL 0 0 0"
        fi
    else
        result="$(build_and_measure "$feats")"
    fi

    read -r status code data rlib_bytes <<<"$result"
    total=$((code + data))

    R_NAME[$i]="$name"
    R_STATUS[$i]="$status"
    R_CODE[$i]="$code"
    R_DATA[$i]="$data"
    R_TOTAL[$i]="$total"
    R_RLIB[$i]="$rlib_bytes"

    [ "$name" = "<baseline>" ] && [ "$status" = "OK" ] && base_total="$total"

    i=$((i + 1))
done
[ "$OUTPUT" = "table" ] && printf '%*s\r' 40 '' >&2   # clear progress line

# ---------------------------------------------------------------------------
# output
# ---------------------------------------------------------------------------
human() {  # bytes -> e.g. "12.3K"
    awk -v b="$1" 'BEGIN{
        if (b<1024) printf "%dB", b;
        else if (b<1024*1024) printf "%.1fK", b/1024;
        else printf "%.2fM", b/1048576;
    }'
}

if [ "$OUTPUT" = "csv" ]; then
    echo "feature,status,code_bytes,data_bytes,total_bytes,delta_vs_base_bytes,rlib_bytes"
    i=0
    while [ "$i" -lt "${#R_NAME[@]}" ]; do
        delta=""
        if [ "${R_STATUS[$i]}" = "OK" ]; then delta=$(( R_TOTAL[$i] - base_total )); fi
        echo "${R_NAME[$i]},${R_STATUS[$i]},${R_CODE[$i]},${R_DATA[$i]},${R_TOTAL[$i]},${delta},${R_RLIB[$i]}"
        i=$((i + 1))
    done
    exit 0
fi

# ---- formatted table ----
echo
echo "cryptoxide binary size report"
echo "  target      : $TARGET_LABEL"
echo "  profile     : release  (opt-level=$OPT_LEVEL, codegen-units=1, lto=$LTO_LABEL)"
if [ "$SIZE_MODE" = "none" ]; then
    echo "  size tool   : none usable for this target — showing rlib size only"
    echo "                (install llvm-size or gsize for a code/data breakdown)"
else
    echo "  size tool   : $SIZE_BIN ($SIZE_MODE)"
fi
echo "  note        : a feature's size includes the deps it auto-enables;"
echo "                'Δ vs base' is its marginal cost over <baseline>."
echo

printf '%-18s %8s %8s %9s %11s %8s   %s\n' \
    "feature" "code" "const" "total" "Δ vs base" "rlib" ""
printf -- '%s\n' "-------------------------------------------------------------------------------"

print_row() {
    local i="$1"
    local name="${R_NAME[$i]}"
    if [ "${R_STATUS[$i]}" != "OK" ]; then
        printf '%-18s %8s %8s %9s %11s %8s\n' "$name" "-" "-" "-" "-" "BUILD-FAIL"
        return
    fi
    local d=$(( R_TOTAL[$i] - base_total ))
    local dstr
    if [ "$name" = "<baseline>" ]; then dstr="—"; else dstr="+$(human "$d")"; fi
    printf '%-18s %8s %8s %9s %11s %8s\n' \
        "$name" \
        "$(human "${R_CODE[$i]}")" \
        "$(human "${R_DATA[$i]}")" \
        "$(human "${R_TOTAL[$i]}")" \
        "$dstr" \
        "$(human "${R_RLIB[$i]}")"
}

# baseline row first, then feature rows sorted by total desc, composites last
BASE_IDX=-1
MID_IDX=(); COMP_IDX=()
i=0
while [ "$i" -lt "${#R_NAME[@]}" ]; do
    case "${R_NAME[$i]}" in
        "<baseline>")                 BASE_IDX=$i ;;
        "(default set)"|"(all features)") COMP_IDX+=("$i") ;;
        *)                            MID_IDX+=("$i") ;;
    esac
    i=$((i + 1))
done

[ "$BASE_IDX" -ge 0 ] && print_row "$BASE_IDX"

# sort middle rows by total desc (build "total<TAB>idx" then sort)
if [ "${#MID_IDX[@]}" -gt 0 ]; then
    while IFS=$'\t' read -r _ idx; do
        print_row "$idx"
    done < <(
        for idx in "${MID_IDX[@]}"; do
            printf '%d\t%d\n' "${R_TOTAL[$idx]}" "$idx"
        done | sort -rn
    )
fi

if [ "${#COMP_IDX[@]}" -gt 0 ]; then
    printf -- '%s\n' "-------------------------------------------------------------------------------"
    for idx in "${COMP_IDX[@]}"; do print_row "$idx"; done
fi

echo
echo "code = .text (machine code), const = read-only/const data (tables, strings)"
echo "rlib = raw archive size on disk (includes rust metadata; not code size)"
echo "note: features that are purely generic over a hash (hmac/hkdf/pbkdf2) show"
echo "      ~0 here — their code is only emitted once instantiated with a concrete"
echo "      hash downstream. BUILD-FAIL = the feature does not compile on its own."
