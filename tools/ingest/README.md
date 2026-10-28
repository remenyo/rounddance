# tools/ingest — structured spec-ingestion pipeline

Upgraded replacement for the legacy `pypdf` page-text dump: PyMuPDF
word-box extraction clustered into visual lines with stable anchors,
pdfplumber table sidecars, and on-demand region renders.

## Layout

- `extract_structured.py` — the pipeline (`extract`, `render`,
  `render-tables`, `selftest` subcommands; see its `--help`).
- `anchors_check.py <pdf> <legacy_text_dir> <new_outdir>` — regression
  gate: every legacy (page, printed-number) anchor must resolve in the
  new output, in order. Misses are adjudicated against PDF geometry:
  a number outside the margin column is legacy-regex overcounting of
  body text (year, footer, table value — correctly excluded); a margin
  number double-counted via a same-valued "Page N" footer is a
  footer-collision (real anchor verified present). Anything else fails.

## Backends

- Lines: PyMuPDF `page.get_text("words")`, y-center clustering
  (tolerance = 0.5 × median word height), top-to-bottom then
  left-to-right. Anchor `pXXXX-Lnnnn` is a continuous per-document
  line counter, stable across runs (byte-identical JSONL).
- Trailing printed numbers: the source PDFs print margin line numbers;
  both backends preserve them as the last token. The pipeline records
  them as `printed` and strips them from `text`.
- Tables: pdfplumber `find_tables` bbox + row grid per page with
  tables, as `<outdir>/tables/pXXXX.json`.
- Renders: PyMuPDF pixmap at the requested DPI. This box has no
  poppler (`pdftoppm` absent), so the pixmap is the renderer; where
  poppler exists, `pdftoppm -png -r <dpi> -f <p> -l <p>` of the same
  page region is equivalent.

## D1 rules (binding)

- Spec PDFs are read-only inputs from private on-Pi storage, never
  copied into the repo.
- Pipeline outputs (JSONL, sidecars, PNGs) go to an evidence dir
  outside the repo (e.g. `~/hwscratch/w<N>/`), never committed.
- Published anchors cite document + page + line numbers only, never
  spec text — same rule as the legacy `text/` dumps.

## Validated

Wave-39: `selftest` green (10-line fixture, anchors stable,
3×3 ruled table, region render); end-to-end on the 21-page ERL
interface-device spec with `anchors_check.py` PASS against the legacy
dumps; corpus `coverage_gate.py` re-run PASS (docs=13,
pages=3766/3766, unresolved=0, seed=519/519, pending=0).
