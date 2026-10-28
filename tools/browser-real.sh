#!/bin/bash
# Real-browser decision-determinism check: runs harness/browser/index.html
# in a real JS/WASM engine (headless Chromium) and asserts every exported
# decision getter equals the native-pinned constant.
#
# This is the RD-BROWSER-04 closer: unlike tools/browser-check.sh (which
# executes the bundle under wasmtime --invoke because no browser engine
# used to exist on the box), this script executes the bundle in the real
# engine. The pinned digest 0x3ea31047e1933c90 is asserted, never re-pinned:
# a mismatch STOPS the run with a failure.
#
# Requires: chromium (apt: sudo-dev apt-get install -y chromium),
# wasm32-unknown-unknown target (rustup target add wasm32-unknown-unknown).
#
# Usage: tools/browser-real.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

PINNED_DIGEST="0x3ea31047e1933c90"

echo "== native =="
cargo run -q -p rounddance-hal-host --example host_transaction > /tmp/browser-real-native.txt
grep -E "DIGEST|TRACE" /tmp/browser-real-native.txt

echo "== browser bundle (wasm32-unknown-unknown) =="
cargo build -q -p rounddance-browser --target wasm32-unknown-unknown
WASM=target/wasm32-unknown-unknown/debug/rounddance_browser.wasm
ls -l "$WASM"
cp "$WASM" harness/browser/rounddance_browser.wasm

echo "== import check (browser-shape: zero imports) =="
python3 harness/browser/check_imports.py "$WASM"

echo "== real engine: $(chromium --version) =="
chromium --headless --disable-gpu --no-sandbox --allow-file-access-from-files \
  --virtual-time-budget=8000 \
  --dump-dom file://"$PWD"/harness/browser/index.html \
  2>/tmp/browser-real-chromium-err.log > /tmp/browser-real-dom.html
echo "chromium stderr (tail):"
tail -3 /tmp/browser-real-chromium-err.log || true

echo "== decision-match =="
python3 - "$PINNED_DIGEST" <<'EOF'
import re, sys, html
pinned = sys.argv[1]
dom = open('/tmp/browser-real-dom.html').read()
m = re.search(r'<div id="verdict"[^>]*>(.*?)</div>', dom, re.S)
verdict = html.unescape(m.group(1)).strip() if m else 'MISSING'
print(f'engine verdict div: {verdict}')
assert verdict.startswith('DECISION-MATCH'), f'engine reports: {verdict}'
rows = re.findall(
    r'<tr><td>(rd_\w+)</td><td>(\d+)</td><td>(\d+)</td><td[^>]*>(\w+)</td></tr>', dom)
assert len(rows) == 13, f'expected 13 getter rows, got {len(rows)}'
got = {sym: (int(want), int(have), flag) for sym, want, have, flag in rows}
for sym, (want, have, flag) in got.items():
    assert flag == 'ok' and want == have, f'{sym}: want={want} have={have} {flag}'
digest = (got['rd_digest_hi'][1] << 32) | got['rd_digest_lo'][1]
assert f'{digest:#018x}' == pinned, \
    f'DIGEST MISMATCH: engine={digest:#018x} pinned={pinned} — STOP, do not re-pin'
assert got['rd_trace_lines'][1] == 35, 'trace_lines'
print(f'REAL-BROWSER DECISION-MATCH: digest {pinned}, trace_lines=35, '
      f'all 13 getters == native')
EOF

echo "== test suites =="
cargo test -q -p rounddance-browser 2>&1 | grep -E "test result" || true
