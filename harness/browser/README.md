# harness/browser — first-transaction decision check in a real engine

`index.html` instantiates `rounddance_browser.wasm` (the
`wasm32-unknown-unknown` bundle of the host first transaction:
form → install-code join → secured ZCL On → report) with an **empty
import object** and asserts every exported decision getter equals the
native-pinned constant (digest `0x3ea31047e1933c90`,
`trace_lines=35`; full pins in `index.html` `EXPECTED` and
`crates/rounddance-browser/tests/browser_decisions.rs`).

## Install (Debian/Pi box; password never on the cmdline)

```sh
sudo-dev apt-get update
sudo-dev apt-get install -y chromium
rustup target add wasm32-unknown-unknown   # if missing
```

Verified engine: `Chromium 156.0.8078.47 built on Debian GNU/Linux 13
(trixie)` (wave-34, 2026-10-28).

## Run

```sh
tools/browser-real.sh
```

The script rebuilds the bundle, copies it next to `index.html`,
gates zero imports via `check_imports.py`, then runs the page in
headless Chromium (`--headless --disable-gpu
--allow-file-access-from-files --virtual-time-budget=8000
--dump-dom`) and asserts the engine verdict is `DECISION-MATCH` with
the digest exactly `0x3ea31047e1933c90`. A digest mismatch **stops the
run** — the pin is never rewritten silently.

`file://` works because the bundle needs no network: the empty-import
instantiate plus `--allow-file-access-from-files` lets the page
`fetch()` the sibling `.wasm`.

## Relationship to `tools/browser-check.sh`

`browser-check.sh` is the fallback for boxes with no browser/JS
engine: it executes the same bundle under `wasmtime --invoke`, one
getter at a time, and asserts the same pins. Both scripts must report
`DECISION-MATCH`; the real-browser run (`browser-real.sh`) is the
RD-BROWSER-04 closer.

## Files

- `index.html` — real-engine driver (empty-import instantiate +
  BigInt-safe unsigned compares + verdict div + per-getter rows).
- `check_imports.py` — zero-import browser-shape gate.
- `expected.txt` — pinned getter values for eyeball comparison.
- `rounddance_browser.wasm` — built artifact, refreshed by either
  check script (do not hand-edit).
