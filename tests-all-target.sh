#!/bin/sh

set -e

cargo test

for flag in force-32bits
do
    cargo test --features $flag
done

for arch in core2 nehalem sandybridge broadwell
do
    RUSTFLAGS="-C target_cpu=$arch" cargo test
done

RUSTFLAGS="-C target_cpu=native" cargo test
