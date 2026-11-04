## ESP-IDF packaging for rounddance

This directory makes the Rust stack consumable from C/IDF projects.

- `components/rounddance/` — the IDF wrapper component: stable C ABI
  (`include/rd_ffi.h`, same header as `harness/c/`), prebuilt
  `librd_ffi.a` for `riscv32imac-esp-espidf` (built by `build-lib.sh`,
  not committed), `idf_component.yml` manifest.
- `sample_toggle/` — a C6 sample app that runs the join/toggle exchange
  through the component and prints the verdict over the monitor.
  Its `main/idf_component.yml` declares `rounddance` via `path:`
  (local-development form of a `components.yaml` import; swapping the
  `path:` for a registry `version:` is the publication step).

Build (verified 2026-11-04 on Pi, fully offline):

```sh
idf/build-lib.sh            # staticlib -> components/rounddance/lib/...
cd idf/sample_toggle
idf.py set-target esp32c6
idf.py build
```

The build log proves the C app compiles and links against the Rust
staticlib through the component manager (`NOTE: Using component
placed at .../idf/components/rounddance for dependency
"rounddance"` — no registry traffic). `idf.py build` exits 0 and
emits `rd_toggle_sample.bin`. On-device run (C6, 2026-11-04):
`RD-TOGGLE-MATCH: lamp=1 defrsp=1 dup-firewalled`, single boot, no
crash. Two integration notes baked into the tree: the sample needs
`CONFIG_ESP_MAIN_TASK_STACK_SIZE=16384` (Rust overflows the 3584
default — same class as the fw images), and the component forces
`-u realpath` (Rust std references it; picolibc's archive order
would otherwise skip IDF's own implementation).
