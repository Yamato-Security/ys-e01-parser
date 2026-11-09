#!/usr/bin/env bash
# Bounded local parser checks. Longer campaigns use the same checked-in targets.
set -euo pipefail
seconds=${1:-30}
toolchain=${FUZZ_TOOLCHAIN:-nightly-2026-07-16}
[[ "$seconds" =~ ^[1-9][0-9]*$ ]] || { echo 'Expected positive seconds per target' >&2; exit 2; }
# Account for sanitizer retention within the process RSS budget. Keep recent
# freed allocations quarantined and return allocator pages promptly. Explicit
# caller settings take precedence over these smoke-test defaults.
asan_options="quarantine_size_mb=32:thread_local_quarantine_size_kb=128:allocator_release_to_os_interval_ms=500${ASAN_OPTIONS:+:$ASAN_OPTIONS}"
cd "$(dirname "$0")/../fuzz"
cargo run --locked --example seeds -- corpus
for target in ewf_read ewf_catalog; do
    ASAN_OPTIONS="$asan_options" cargo +"$toolchain" fuzz run "$target" -- \
        -max_total_time="$seconds" -max_len=1048576 -rss_limit_mb=512 -timeout=10
done
