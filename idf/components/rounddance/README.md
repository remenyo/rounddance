## rounddance ESP-IDF wrapper component

Stable C ABI over the Rounddance Zigbee stack (`rd_ffi.h`, same header
as `harness/c/` in the repo root). The implementation is the prebuilt
Rust staticlib `lib/librd_ffi.a` (`riscv32imac-esp-espidf`, built by
`idf/build-lib.sh`); this component only adapts it to the IDF build.

Registry publication: release the tag, attach the archive, and
consumers replace the `path:` dependency with a registry `version:`.
No source changes needed on either side.
