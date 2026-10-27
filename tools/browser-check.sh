#!/bin/bash
# Browser-path decision-determinism check: the browser-shape bundle
# (wasm32-unknown-unknown, zero imports) must report identical
# decisions to the native host transaction.
#
# Engine situation on this box (2026-10-27): no browser engine
# (chromium/firefox/webkit), no JS engine (node/deno) installed — so
# the bundle executes under wasmtime via --invoke, one pure-i32
# getter at a time. The artifact stays browser-shape (import check
# below); harness/browser/index.html is the real-browser driver for a
# box that has one. No browser claims are made for this run.
#
# Usage: tools/browser-check.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

echo "== native =="
cargo run -q -p rounddance-hal-host --example host_transaction > /tmp/browser-txn-native.txt
head -3 /tmp/browser-txn-native.txt

echo "== browser bundle (wasm32-unknown-unknown) =="
cargo build -q -p rounddance-browser --target wasm32-unknown-unknown
WASM=target/wasm32-unknown-unknown/debug/rounddance_browser.wasm
ls -l "$WASM"
cp "$WASM" harness/browser/rounddance_browser.wasm

echo "== import check (browser-shape: zero imports) =="
python3 harness/browser/check_imports.py "$WASM"

echo "== execute under $(wasmtime --version) (no browser/JS engine on box) =="
invoke() { wasmtime run --invoke "$1" "$WASM" 2>/dev/null; }
to_u32() { python3 -c "print($1 & 0xFFFFFFFF)"; }
{
  echo "digest_hi=$(to_u32 "$(invoke rd_digest_hi)")"
  echo "digest_lo=$(to_u32 "$(invoke rd_digest_lo)")"
  for g in formed tc_verified joiner_joined server_onoff reported_onoff \
      aps_security_on cmd_counter report_counter resume_next tsn trace_lines; do
    echo "$g=$(invoke "rd_$g")"
  done
} > /tmp/browser-txn-wasm.txt
cat /tmp/browser-txn-wasm.txt

echo "== decision-match =="
python3 - <<'EOF'
import re
native = open('/tmp/browser-txn-native.txt').read()
wasm = dict(line.split('=') for line in
            open('/tmp/browser-txn-wasm.txt').read().split())
m = re.search(r'DECISIONS (.*)', native)
assert m, 'native DECISIONS line missing'
dec = dict(kv.split('=') for kv in m.group(1).split())
bools = ['formed', 'tc_verified', 'joiner_joined', 'server_onoff',
          'reported_onoff', 'aps_security_on']
for key in bools:
    assert (int(wasm[key]) == 1) == (dec[key] == 'true'), \
        f'{key}: wasm={wasm[key]} native={dec[key]}'
ints = {'cmd_counter': 1024, 'report_counter': 1025, 'resume_next': 1024}
for key, want in ints.items():
    assert int(wasm[key]) == want == int(dec[key]), \
        f'{key}: wasm={wasm[key]} native={dec[key]}'
assert int(wasm['tsn']) == int(dec['tsn'], 16), 'tsn'
digest_native = re.search(r'DIGEST=(0x[0-9a-f]+)', native).group(1)
digest_wasm = (int(wasm['digest_hi']) << 32) | int(wasm['digest_lo'])
assert f'{digest_wasm:#018x}' == digest_native, \
    f'digest wasm={digest_wasm:#018x} native={digest_native}'
trace_native = int(re.search(r'TRACE_LINES=(\d+)', native).group(1))
assert int(wasm['trace_lines']) == trace_native, 'trace_lines'
print(f'DECISION-MATCH: digest {digest_native}, '
      f'trace_lines={trace_native}, all 13 getters == native')
EOF

echo "== test suites =="
cargo test -q -p rounddance-browser 2>&1 | grep -E "test result" || true
