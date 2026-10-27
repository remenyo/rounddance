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

## Follow-ups (not in v0)

Extended-address data frames (SAP returns `Unsupported`), SFD
timestamps (confirms carry `None`, capability honestly `false`), and
sleep scheduling. Touchlink scan bursts should call
`restore_channel()` afterwards (inter-PAN retunes per request).
