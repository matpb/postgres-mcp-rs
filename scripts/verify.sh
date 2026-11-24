#!/usr/bin/env bash
# Local proof without a database: formatting, lints, unit tests, audit and dependency policy.
set -euo pipefail

cd "$(dirname "$0")/.."

for tool in cargo-audit cargo-deny; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "verify: $tool is not installed; install it with: cargo install cargo-audit cargo-deny" >&2
        exit 1
    fi
done

step() {
    echo "==> $1"
    shift
    "$@"
}

step "cargo fmt --check" cargo fmt --check
step "cargo clippy --all-targets --locked -- -D warnings" cargo clippy --all-targets --locked -- -D warnings
step "cargo test --locked --lib --test config --test encode --test gate --test http_guard" \
    cargo test --locked --lib --test config --test encode --test gate --test http_guard
step "cargo audit" cargo audit
step "cargo deny check" cargo deny check

echo "verify: OK"
