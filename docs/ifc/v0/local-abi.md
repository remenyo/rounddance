# IFC v0 — local ABI (native Rust + WASM component boundary)

Two projections of the same contracts in `functions.md`. Both are
generated-from-spec, never hand-diverged: the Rust traits are the
reference, the WIT is the portable twin. Engine rule (standing grant):
the WIT MUST NOT import anything engine-specific — no Wasmtime, no
wasm3, no Deno, no custom-runtime shims. Runtimes bind the component;
the component never names the runtime.

## 1. Native Rust trait boundary rules

Every function in `functions.md` gets one Rust trait pair (data +
management where applicable), following the `rounddance-mac-sap`
shape that already proved the pattern:

1. **`no_std` + `forbid(unsafe_code)`** in all protocol crates. `unsafe`
   lives only in per-target HAL shims, each block with a SAFETY comment
   and checklist review (SCOPE.md §2).
2. **Fallible**: every allocating or queueing op returns `Result<_, E>`.
   No abort-on-OOM paths; no panics on input (panics only on internal
   logic bugs, never on peer bytes).
3. **Bounded**: all storage is fixed-capacity (`[T; N]`, ring buffers,
   preallocated tables). Queue-full is a *value* (`QueueFull`), never
   backpressure-by-allocation. Table sizes are provisioning constants,
   resized only at provisioning/reboot, never mid-transaction (D5).
4. **Poll-based, not callback-based**: `data_request / data_cancel /
   poll_confirm / poll_indication` plus `*_free / *_capacity` readouts.
   Rationale: cooperative AND multithreaded schedulers both stay
   feasible; deterministic single-threaded sim just calls polls in
   virtual-time order; no reentrancy, no ISR-context locking (the
   wave-2b C6 finding: 15.4 driver callbacks are ISR-context —
   flag-only, never log/lock).
5. **Capability discovery**: every function exposes a `capabilities()`
   struct (see `MacCapabilities`). Callers branch on flags, never probe
   behavior. Radios without HW ACK/CSMA/retries get synthesized
   behavior above the HAL, honestly flagged.
6. **Opaque handles**: confirms match requests by caller-visible handle
   (`TxHandle`-style), adapter-scoped, never reused while outstanding.
7. **Versioned types**: every trait carries `const VERSION: u8`; types
   crossing the boundary are `#[non_exhaustive]`-aware — adding a
   variant is a minor version, removing/renaming is major.
8. **No allocator dependence in decisions**: error variants and control
   flow never depend on allocator state (D5).

Reference implementation of exactly these rules: `rounddance-mac-sap`
(`crates/rounddance-mac-sap/src/lib.rs`). New functions copy its
request/confirm/indication/error/capability skeleton and cite it.

## 2. WASM component boundary (WIT-first)

The `.wit` sketches in `wit/` are the normativecross-language shape;
Rust traits are mechanistically derived from them (names lowercased,
`result<>` for fallible ops, `option<>` for timestamp-`Option`s).
Three sketches cover the three most-crossed interfaces:

- `wit/mac-driver.wit` — the MAC SAP over a component boundary
  (highest traffic: every frame crosses it twice).
- `wit/nwk-aps.wit` — the NWK/APS data path (second-highest traffic,
  plus binding/group tables shared with commissioning).
- `wit/mgmt-agent.wit` — the operator face (crosses every deployment:
  USB on standalone, loopback on host, remote on browser).

Rules for the WIT:

- `package rounddance:ifc@v0;` — version bump renames the package, so
  v0 and v1 components can coexist in one composition.
- Only WIT primitives (`u8/u16/u32/u64`, `list<u8>`, `option<>`,
  `result<_, _>`, records, variants, flags, resources). No host
  imports, no engine worlds — each sketch declares its own
  `world` with only `import`/`export` of its own interfaces.
- Bounded lists carry their budget in a comment (`// <=116`) AND in a
  `check-bounds` constructor the host must call; the component traps
  nothing on oversize — it returns `err(frame-too-long)`.
- Poll-based: `poll-confirm` / `poll-indication` return
  `option<...>`; no async, no callbacks across the boundary (engines
  differ — polling is the portable intersection).
- Capability records mirror the native `capabilities()` structs bit
  for bit; the guest reports honestly, the host adapts.

Engine-agnosticism test: the same `.wit` must compose under Wasmtime,
Deno, and wasm3/custom without editing the file — only the host-side
binding code differs. If a sketch needs an engine-specific import to
work, the sketch is wrong, not the engine.
