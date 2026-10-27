#!/bin/bash
# Host/WASM decision-determinism check: the first complete host
# transaction must print identical output natively and under wasmtime.
# Usage: tools/host-wasm-check.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

echo "== native =="
cargo run -q -p rounddance-hal-host --example host_transaction > /tmp/host-txn-native.txt
head -3 /tmp/host-txn-native.txt

echo "== wasm32-wasip1 =="
cargo build -q -p rounddance-hal-host --example host_transaction --target wasm32-wasip1
wasmtime run target/wasm32-wasip1/debug/examples/host_transaction.wasm > /tmp/host-txn-wasm.txt
head -3 /tmp/host-txn-wasm.txt

echo "== diff =="
diff /tmp/host-txn-native.txt /tmp/host-txn-wasm.txt && echo "IDENTICAL: native == wasm32-wasmtime"

echo "== test suites =="
cargo test -q -p rounddance-hal-host 2>&1 | grep -E "test result" || true
cargo test -q -p rounddance-hal-host --target wasm32-wasip1 2>&1 | grep -E "test result" || true
