# Coverage annex: leftover clusters (ERL / Daily / Lighting-Linky / DeviceType)

Method: paraphrase only (D1). No spec text is quoted. These
documents were first modeled under `uncovered::{erl, dailysched,
occupancy, linky, devtype}`; the vectors below close the remaining
gaps that engine behavior already supports.

## Delta in this pass

New: `tests/coverage_aliro_leftover.rs` (8 leftover vectors).

| Document | Universe | Prior covered | New vectors | Est. now |
|---|---|---|---|---|
| ERL `17-05031-011` | 147 anchors | 83 (56.5%) | conformance over mandatory lists (`-4-06`), trigger mapping (`-4-07`) | ≈ 98 / 147 (≈ 67%) |
| Daily `17-05035-016` | 386 anchors | 240 (62.2%) | day-color/peak helpers (`-1015-06`), day-profile query + tier ceiling (`-1015-07`) | ≈ 260 / 386 (≈ 67%) |
| Lighting `15-0014-05` | 1,453 anchors | 0 | sensor-row pins (`-13-02`); lamp/controller devices deferred (`-06-01`) | ≈ 4 / 1,453 (≈ 0.3%) |
| Linky `17-05019-012` | 2,624 anchors | ≈ 64 (2.4%) | identifier ceilings (`-104-03`), mode codec (`-104-04`) | ≈ 82 / 2,624 (≈ 3.1%) |
| DeviceType `23-02016-002` | 2,285 anchors | 25 (1.1%) | registry + side coverage (`-14-06`) | ≈ 33 / 2,285 (≈ 1.4%) |

Estimates use newly cited lines modulo overlap; exact resweep is
left to the coverage owner.

## Per-document disposition

### ERL Interface Device `17-05031-011` (21 pages)

Prior gaps were the reporting-table rows, the generated-command
trigger column, and the `conforms`/`covers` helpers. The two new
vectors pin: exact mandatory sets conform while any missing
mandatory server cluster breaks conformance; the optional OTA row
and extra clusters are accepted; `covers` is the subset primitive;
every generated command names its triggering receipt (or is
explicitly unsolicited, e.g. CancelAllSchedules); the messaging
row pins cluster 0x0703 (newly modeled). Remaining ERL pages (device
format prose, base-device rows) stay covered by the prior vectors.

### Daily Schedule `17-05035-016` (21 pages)

Prior gaps were the peak-bitmap helpers and the day-profile query
shape. The two new vectors pin: the day/next/notice/on-peak bit
fields, the known color and time-reference alphabets, the schedule
count and type sentinels, the 6-octet day query codec, and the
48-tier ceiling. Remaining pages (schedule/day-profile store rules,
cancel/fetch flows) stay covered by the prior vectors.

### Lighting & Occupancy `15-0014-05` (122 pages)

The occupancy-sensor device rows (section 13) ride the modeled
`occupancy::ServerDef`: the new `-13-02` vector pins the two
required attribute rows and their ascending order. All other device
types (on/off light, dimmable, color, controllers — sections 6-12,
14+) need color/ballast/level clusters with no bounded model in
this crate and are **explicitly deferred** (pinned by
`find_device` misses in `-06-01`), never silent scope. This document
is therefore the largest honest remainder in this pass.

### Linky Metering `17-05019-012` (112 pages)

Prior coverage (mode, reasons, tier counts, day-max) is extended
with the identifier ceilings (meter/site/serial widths, 48 tiers)
and the mode codec round-trip plus shape rules. The remaining
attribute-set pages (reactive quadrants, freeze windows, tariff
schedules) stay follow-up; every defined row still resolves via
`attr_def` while unknown rows miss.

### DeviceType Library `23-02016-002` (216 pages)

The Door Lock descriptor (0x000A) is now pinned end to end:
registry lookup, revision, server/client side coverage, the
always-addressable class, and the exact required-attribute and
command table lengths (drift fails loudly). Other device types in
the library stay follow-up; the registry carries no descriptor for
them (pinned misses).

## New files (this pass)

- `crates/rounddance-zcl/tests/coverage_aliro_leftover.rs`
- (no new `src` modules: all leftover behavior already exists)
