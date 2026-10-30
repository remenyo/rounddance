# rounddance-hal-esp — ESP 802.15.4 HAL adapter

Safe wrapper over Espressif's 802.15.4 driver, implementing the
[`rounddance-mac-sap`](../rounddance-mac-sap) traits (`MacDataSap`,
`MacMgmtSap`, `MacInterPanSap`) for C6, H2, C5, and S31. The driver
application API is identical across those targets, so one adapter
covers all four; only antenna-GPIO handling differs, and that lives in
board code, never here.

Productized from the wave-15 Rust-on-ESP spike
(`rd-frame-tx`: first rounddance frame radiated from Rust, 37/37
sniffer byte-hits against the frozen NWK vector). No hardware is needed
to build or test this crate: the host side runs entirely over
`MockDriver`.

## Layout

| Path | What |
|---|---|
| `src/lib.rs` | Crate docs + documented invariants + `unsafe` confinement rule |
| `src/driver.rs` | `Driver` seam (init/deinit, channel/power, single-flight TX, RX pump, ED scan) |
| `src/adapter.rs` | `EspAdapter<D: Driver>`: queueing, failure mapping, cap, inter-PAN |
| `src/mock.rs` | `MockDriver`: scriptable seam double (host tests, WASM) |
| `src/mac_cmd.rs` | MAC beacon/assoc command codec + coordinator responder (host vectors; radio carry below) |
| `src/ffi.rs` | `esp`-only: raw 15.4 symbols missing from `esp-idf-sys` 0.38, each with header cross-reference |
| `src/esp.rs` | `esp`-only: `EspIdfDriver` (NVS-first init, ISR-flag pumps, bounded RX mailbox) |
| `tests/adapter_mock.rs` | 26 host-side tests: queueing, mappings, cap, inter-PAN |
| `examples/esp_adapter_shape.rs` | Host runnable printing the exact on-air bytes (see below) |

Feature flags: default (host/mock, builds everywhere including
`wasm32-unknown-unknown`) and `esp` (pulls `esp-idf-sys 0.38`,
compiles `ffi` + `esp` for `riscv32imac-esp-espidf`).

## Invariants (enforced or asserted in code)

- **TX-power standing cap**: `EspAdapter::set_tx_power` rejects anything
  above `MAX_TX_POWER_DBM` (+10 dBm) before the driver sees it. Lab
  policy until human clears it.
- **NVS-init-first**: `EspIdfDriver::init` runs `nvs_flash_init`
  (erase-on-version-mismatch) before `esp_ieee802154_enable`.
- **Len+2**: air frame byte 0 = header + MSDU + 2 (the 2 trailing
  hardware-FCS octets the radio appends/checks itself).
- **Antenna LOW/LOW**: Xiao C6 onboard-ceramic select is GPIO3 LOW +
  GPIO14 LOW, driven by board code (see the `esp` firmware shape in
  `src/esp.rs` docs / the spike). Non-LOW/LOW combos are banned without
  human approval.
- **ISR discipline**: driver callbacks are ISR-context — flag-only plus
  a bounded mailbox copy, never log/lock. Every RX frame is released
  with `receive_handle_done` or the RX pool exhausts (~1 s stall).
- **Filtering default**: init programs promiscuous OFF (the driver
  defaults it TRUE) and RX-when-idle ON.
- **Retry policy**: the driver reports each transaction once (hardware
  auto-ACK + CSMA, no HAL retry); upper layers own retry.

## On-target bring-up recipe (condensed from the spike)

- Toolchain: the `esp` Rust fork under `~/.rustup/toolchains/esp`
  (`rustc 1.97-nightly -Z build-std`) with target
  `riscv32imac-esp-espidf`. Note the `A`: the `imc` target silently
  builds for C3 — C6 needs `imAC`.
- IDF v6.1 checkout + `CONFIG_IDF_TARGET="esp32c6"` in the firmware
  crate's `rust-toolchain.toml` (`[toolchain] channel = "esp"`).
- The firmware crate's `build.rs` MUST call
  `embuild::espidf::sysenv::output()` — without it the sysenv never
  materializes and the build fails.
- Dependency versions proven by the spike: `esp-idf-sys 0.38`,
  `esp-idf-hal 0.47`, `esp-idf-svc 0.53`.
- Always `--release`: dev profiles risk overflowing the 1 MB factory
  app partition; the spike's release image flashed at ~614 KB / 1 MB.
- Boot heap is ~451 KB; this adapter adds only static pools (4×128 B TX
  slots, 8-deep confirm/indication queues, 128 B RX mailbox) — no heap,
  no allocator.
- ED scan needs STA-capable init on some targets; `espflash monitor`
  needs a TTY (use pyserial otherwise).
- Crate-level ESP check (best-effort, host-run, non-blocking):
  `IDF_PATH=/home/dev/projects/esp-idf-v6 MCU=esp32c6
  RUSTFLAGS="--cfg espidf_time64" cargo +esp check -p
  rounddance-hal-esp --features esp --target
  riscv32imac-esp-espidf -Z build-std=std,panic_abort` — PASS in
  wave-25 (incl. the new `app` module; all deps `no_std`).
- Firmware shape (board code, not this crate): NVS-init-first, antenna
  GPIO3+GPIO14 LOW, role from MAC via `role_from_mac`, `SerialLog`
  over UART/USB, then the `CoordinatorApp`/`JoinerApp` loop below.

## Verifying the binary shape on host

```sh
cargo run -p rounddance-hal-esp --example esp_adapter_shape
# ESP-TX air(20B): 15 41 88 00 34 12 ff ff 01 00 48 00 34 12 00 00 0a 5c de ad
# ESP-TX confirm: handle=0 status=Delivered
```

The NWK tail (`48…ad`) is the frozen repo vector, asserted byte-equal
before framing — the same bytes the spike radiated OTA. On device,
swap the driver for `EspIdfDriver::new()` and prepend the board
antenna sequence; the MAC framing path is unchanged.

## App layer: C6-standalone coordinator + joiner (`src/app.rs`)

First-class repo productization of the wave-23 OTA run (`rd-c6join`
in scratch `~/hwscratch/c6join`): the same form → permit → admit →
install-code join → DeviceAnnce → secured ZCL Toggle sequence, now
composed from repo crates (`roles`, `commission`, `nwk`, `aps`,
`security`, `zdo`, `zcl`) over `EspAdapter`.

- Role selection: `role_from_mac` compares the full 6-octet base MAC
  against the verified lab pair (coordinator `a0:f2:62:86:7f:68`,
  healthy 7F68; joiner `a0:f2:62:85:97:a4`, 97A4 — both `esptool
  read-mac` efuse-confirmed); anything else refuses before touching
  the radio. `eui_from_mac` expands the base MAC with the proven
  `ff:fe` rule (matches `read-mac` EUI output).
- Serial-log discipline: `SerialLog` trait (`&str` lines, task
  context only) + `log_air` (bounded 512 B line with full air
  bytes). Host tests collect lines; firmware implements the trait
  over UART/USB.
- `CoordinatorApp`: formation (centralized, fixed PAN `0xC601`) →
  permit window (MAC responder permit synced via `tick`) →
  child-table + Trust-Center + MAC allow-list admit → MMO-KDF key
  exchange → secured Toggle builder → Default Response verifier; MAC
  leg via `on_mac_psdu` / `take_beacon` / `take_assoc_rsp` /
  `build_gratuitous_beacon` (gratuitous pacing
  `GRATUITOUS_BEACON_INTERVAL_MS = 2000 ms` while unassociated).
- `JoinerApp`: beacon survey → candidate → assoc (short `0x0001`
  assigned post-assoc, `0xFFFF` before) → wave-23 unsecured-vendor
  tolerance → key → verify → announced → DeviceAnnce → live On/Off
  server endpoint (real `AttrStore` + `dispatch`) → Default Response
  with `should_default_respond` triage.

## Host-side proof

```sh
cargo test -p rounddance-hal-esp --test c6_standalone
# 4 tests: role selection + full form→join→toggle over two
# EspAdapter<MockDriver>s with mock-to-mock air shuttling (Delivered
# confirms, lamp off→on, SUCCESS defrsp, replay refused both legs,
# two fresh runs radiate identical bytes + log lines).
```

## Follow-ups (not in v0)

Extended-address data frames (SAP returns `Unsupported`), SFD
timestamps (confirms carry `None`, capability honestly `false`), and
sleep scheduling. Touchlink scan bursts should call
`restore_channel()` afterwards (inter-PAN retunes per request).
MAC-association primitives: the beacon/assoc command codec plus the
coordinator pending-answer responder live in `src/mac_cmd.rs` with
OTA-pinned host vectors (`tests/mac_assoc.rs`); the join leg above
still starts at the steering survey with the coordinator's beacon
ingested. Command frames route through `EspAdapter` (MAC queue via
`poll_mac_indication`, raw TX via `transmit_mac`, promiscuous RX via
`set_promiscuous` — the rung-2 `adapter_routes_…_closed_gap` pin);
firmware (`fw/rd-coord`) drives that path with gratuitous beacons
while unassociated (`tests/coord_radiate.rs`, 7 tests).
