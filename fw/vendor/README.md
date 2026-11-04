# fw/vendor — pinned local shims for the S31 target

These are verbatim copies of crates.io releases, with the S31 MCU
added, used via `[patch.crates-io]` **only** by the
`fw/rd-coord-s31` workspace (`fw/rd-coord-s31/Cargo.toml`). No other
workspace in this repo sees them: the C6 images resolve the
unmodified crates.io originals.

- `esp-idf-sys` 0.38.1 + `Chip::ESP32S31` (`build/native/cargo_driver/chip.rs`):
  `#[strum(serialize = "esp32s31")]`, `riscv32imac-esp-espidf` detect
  list, `riscv32-esp-elf` toolchain group. `is_xtensa` needs no change
  (RISC-V falls in the `false` arm); `ulp_gcc_toolchain` needs none
  (same `_ => None` arm as C61/H2); `cmake_toolchain_file` is generic
  and resolves to the in-tree `tools/cmake/toolchain-esp32s31.cmake`;
  the `#[cfg]`-gated `pcnt` module stays off (IDF ≥ 6.0 path, same as
  every other chip on this IDF).
- `embuild` 0.33.7: `ESP32S31` in the `riscv32imac` PIO target table
  and the MCU→triple mapping (same one-line pattern as C6/C5/H2).
- `esp-idf-hal` / `esp-idf-svc` are deliberately NOT vendored:
  `rd-coord-s31` uses no HAL drivers (our HAL lives in
  `rounddance-hal-esp` over `esp-idf-sys` FFI + NVS), so those crates
  are not dependencies and are never compiled for this target.
  A future S31 firmware that needs HAL drivers (GPIO/ADC/I2S/…)
  requires its own `esp-idf-hal` port task (13-file per-chip surface).

When upstream `esp-idf-sys` names `esp32s31`, delete this directory
and the `[patch.crates-io]` table; the fw crate is otherwise
byte-identical to an upstream build.
