#!/bin/sh

set -e

cargo test

for arch in core2 nehalem sandybridge broadwell
do
    RUSTFLAGS="-C target_cpu=$arch" cargo test
done

RUSTFLAGS="-C target_cpu=native" cargo test
