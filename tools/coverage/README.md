# Spec annotation system (`@covers` / `@verifies` / `@na` / `@deferred`)

One rule: **coverage is derived from the source tree, never stored.**
`tools/coverage/check.py` enumerates the corpus line universe and harvests
annotations from `crates/**/*.rs`. There is no snapshot to rot — the report
is recomputed on every run, so it cannot go obsolete.

## Syntax (one tag per comment line, `//` or `//!`)

```
// @covers doc=05-3474-23 rev=R23.2 clause=3.3.1 lines=p0086-L2166-L2168 req=05-3474-23-22511-01
// @verifies req=05-3474-23-22511-01 test=tests/vectors.rs::vector_minimal_unicast_data
// @na doc=14-0563-19 lines=p0111-L600-L610 reason=figure-caption-no-normative-behavior
// @deferred doc=05-3474-23 lines=p0400-L9000-L9010 reason=needs-clock-driven-rekey-harness
```

Keys are strict `key=value`, comma-free, values contain no spaces.
`lines` is one range or comma-separated list: `p0086-L2166-L2168`,
`p0086-L2166`, `p0086-L2166-L2168,p0087-L2200-L2204`. Ranges are inclusive
and expand line-wise within the stated page.

- `@covers`: the enclosing code implements the cited lines. `req` names the
  requirement ID implemented here (repo-minted `05-3474-23-<clause>-<seq>`
  or corpus-mined ID).
- `@verifies`: a test pins `req`. `test` is `path::name` and must exist.
- `@na`: cited lines are explicitly not applicable; `reason` is a
  hyphenated cause slug (our own wording, never spec text).
- `@deferred`: parked with cause; still counts as *accounted for*, not as
  covered. Reopening the cause reopens the lines.

D1 holds everywhere: tags carry document numbers, revisions, clause
numbers and line anchors only — never spec wording.

## Doc keys

`doc` is the CSA document number: `05-3474-23`, `07-5123-08`,
`14-0563-19`, `17-05019-012`, `17-05031-011`, `17-05035-016`,
`15-0014-05`, `23-02016-002`, `23-80986-022`, `26-42802-001`,
`20-27688-041`, `22-65816-030`, `07-5356-22`, `802.15.4-2020`,
`802.15.4-2024`. The checker maps each to its corpus slug.

## Line universes (per doc, mirrors the sweep methods)

- Trailing-number docs (all `05-3474`/`07-5123`/`14-0563`/`17-05019`/
  `22-65816`/`20-27688`/`23-02016`/`07-5356`/`23-80986`): universe =
  every trailing integer on content lines of `pNNNN.txt`
  (headers, `SOURCE` banners and `Page N` footers excluded), keyed
  `pNNNN-L<int>`.
- Margin-run docs (`17-05031-011` L1–147, `17-05035-016` L1–386,
  `15-0014-05` L1–1453): universe = the global margin-number run;
  a cited line counts when its number falls in the run (page prefix
  locates, number identifies).
- `26-42802-001`: no margin numbers in extraction — page-touch only
  (`lines=p0108` counts the page).
- `802.15.4-*`: out of Zigbee scope — page-touch only, reported
  separately, never in the headline percentage.

## Checker (`check.py`)

```
python3 tools/coverage/check.py [--report out.json] [--strict]
```

1. Enumerates each universe from the private corpus (read-only).
2. Harvests `@covers`/`@verifies`/`@na`/`@deferred` plus legacy
   free-form `pNNNN-L` cites (continuity with pre-tag code).
3. Validates: known doc, resolvable anchors (unknown anchor = error),
   `@verifies` test target exists, no spec text smuggled (values match
   `[A-Za-z0-9._/+,:\-§]+`).
4. Emits per-doc `{total, covered, na, deferred, gap, pct}` and the gap
   anchor list. `--strict` exits non-zero on any validation error
   (CI uses this); coverage percentage itself is informational and
   never fails the build.

Legacy free-form cites count as `covered` so pre-tag code keeps its
numbers; convert files to `@tags` opportunistically when touched.
