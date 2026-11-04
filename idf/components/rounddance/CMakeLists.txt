# Rounddance wrapper: headers + prebuilt Rust staticlib. The
# archive is produced by idf/build-lib.sh (cargo +esp,
# riscv32imac-esp-espidf) and is intentionally not committed.
#
# Linker note: Rust std references `realpath` (picolibc gap — IDF's
# esp_libc provides it, but archive order would otherwise skip it:
# the need only arises when the prebuilt, linked last, is scanned).
# Forcing it undefined up front makes the first esp_libc scan pull
# the real implementation in.
idf_component_register(INCLUDE_DIRS "include")
add_prebuilt_library(rd_ffi "${CMAKE_CURRENT_SOURCE_DIR}/lib/riscv32imac-esp-espidf/librounddance_ffi.a")
target_link_libraries(${COMPONENT_LIB} INTERFACE rd_ffi)
target_link_options(${COMPONENT_LIB} INTERFACE "LINKER:-u,realpath")
