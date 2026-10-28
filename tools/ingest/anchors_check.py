#!/usr/bin/env python3
"""Anchor regression gate: new structured extraction must cover old anchors.

Compares the legacy `pypdf` page dumps (`corpus/text/<slug>/pNNNN.txt`,
trailing printed line numbers as the last token of each body line)
against the upgraded `extract_structured.py` output (`lines.jsonl`).

For every legacy (page, printed-number) pair the gate requires the same
pair to exist in the new output, in document order. A pair missing from
the new output is adjudicated against the PDF geometry itself: if the
number sits in the page's printed-number margin column it is a REAL
miss (gate FAIL); if it is a body-text number the legacy regex happened
to catch (date year, page footer, section value), it is reported as
correctly excluded (INFO, gate still passes).

D1 hygiene: inputs are read, never modified; only counts and anchor
IDs are printed (no spec text).

Usage:
    anchors_check.py <pdf> <legacy_text_dir> <new_outdir>
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from extract_structured import (  # noqa: E402
    INT_RE, cluster_lines, doc_margin_x1, page_margin_x1,
)

TRAIL_RE = re.compile(r"\s+(\d{1,6})\s*$")


def legacy_anchors(textdir):
    """Yield (page, printed) in document order from legacy pNNNN.txt dumps."""
    pairs = []
    for f in sorted(Path(textdir).glob("p*.txt")):
        page = int(f.stem[1:])
        for line in f.read_text(encoding="utf-8").splitlines()[2:]:
            m = TRAIL_RE.search(line)
            if m:
                pairs.append((page, int(m.group(1)), line.strip()))
    return pairs


def new_anchors(outdir):
    pairs = []
    for line in (Path(outdir) / "lines.jsonl").read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        r = json.loads(line)
        if r.get("printed") is not None:
            pairs.append((r["page"], r["printed"]))
    return pairs


def doc_global_x1(pdf_path):
    """Document-global margin column (same vote as the extractor)."""
    import fitz

    doc = fitz.open(pdf_path)
    all_coords = []
    for page in doc:
        for w in page.get_text("words"):
            if INT_RE.match(w[4]):
                all_coords.append((w[2], (w[1] + w[3]) / 2.0))
    return doc_margin_x1(all_coords)


def margin_values(pdf_path, page_no1, global_x1):
    """Bare-integer token values sitting in the page margin column."""
    import fitz

    doc = fitz.open(pdf_path)
    page = doc[page_no1 - 1]
    lines = cluster_lines(page.get_text("words"))
    coords = []
    for ln in lines:
        yc = (ln["bbox"][1] + ln["bbox"][3]) / 2.0
        for _, x1, tok in ln["tokens"]:
            if INT_RE.match(tok):
                coords.append((x1, yc, int(tok)))
    mx = page_margin_x1(coords, global_x1)
    if mx is None:
        return set()
    return {c[2] for c in coords if abs(c[0] - mx) <= 3.0}


def main(argv):
    if len(argv) != 3:
        print(__doc__)
        return 2
    pdf, textdir, outdir = argv
    old = legacy_anchors(textdir)
    new = new_anchors(outdir)
    print("computing document-global margin column ...")
    global_x1 = doc_global_x1(pdf)
    print(f"global margin x1 = {global_x1}")
    from collections import defaultdict
    by_pair = defaultdict(list)
    for page, num, line in old:
        by_pair[(page, num)].append(line)
    new_pairs = [(p, n) for p, n in new]
    remaining = list(new_pairs)
    real_missing, excluded, collisions = [], [], []
    margin_cache = {}
    for page, num, line in old:
        try:
            i = remaining.index((page, num))
            remaining = remaining[i + 1:]
        except ValueError:
            margin_cache.setdefault(page, margin_values(pdf, page, global_x1))
            if num not in margin_cache[page]:
                excluded.append((page, num))
                continue
            # Value IS a margin number but over-consumed: the legacy side
            # counted a same-valued body token (e.g. a "Page N" footer)
            # alongside the real margin number. Confirm one of the legacy
            # occurrences is a footer/header restating the PDF page number.
            footers = [ln for ln in by_pair[(page, num)]
                       if re.search(r"Page\s+0*%d\s*$" % num, ln)]
            if footers:
                collisions.append((page, num, footers[0][:60]))
            else:
                real_missing.append((page, num))
    print(f"legacy anchors={len(old)} new printed anchors={len(new)} "
          f"real-missing={len(real_missing)} "
          f"content-numbers-excluded={len(excluded)} "
          f"footer-collisions={len(collisions)}")
    for page, num in real_missing[:20]:
        print(f"REAL MISS: p{page:04d} printed {num}")
    for page, num, line in collisions[:20]:
        print(f"info: legacy double-counts margin {num} on p{page:04d} "
              f"via footer ({line!r}); real anchor present")
    for page, num in excluded[:20]:
        print(f"info: legacy trailing {num} on p{page:04d} is body text, "
              f"not a margin number (correctly excluded)")
    if real_missing:
        print("ANCHORS GATE: FAIL")
        return 1
    print("ANCHORS GATE: PASS (no anchor regressions)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
