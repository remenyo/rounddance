#!/usr/bin/env python3
"""Structured spec-ingestion pipeline (PyMuPDF + pdfplumber).

Upgrades the corpus `pypdf` page-text extraction to line-numbered
structured extraction:

- page -> lines with stable anchors (`pXXXX-Lnnnn`, one continuous
  line counter per document), word bounding boxes, and preserved
  trailing printed line numbers where the source PDF carries them;
- table sidecars (pdfplumber bbox + row/cell grid) for pages that
  contain tables;
- on-demand table/figure region renders (PyMuPDF pixmaps; equivalent
  to what `pdftoppm -png -r <dpi> -f <p> -l <p>` would produce, used
  here because poppler is not installed on this box).

D1 hygiene: input PDFs live OUTSIDE the repo (private on-Pi storage)
and are opened read-only. Outputs written by this tool contain
structural metadata (anchors, bboxes) plus line text for the operator's
own evidence dir only -- never commit extracted text, renders, or
sidecars to the repo. The repo ships the tool, not its output.

Usage:
    extract_structured.py extract <pdf> <outdir> [--pages 1,2,5-9] [--dpi 150]
    extract_structured.py render <pdf> <outdir> --page N --bbox x0,y0,x1,y1 [--dpi 200]
    extract_structured.py render-tables <pdf> <outdir> [--dpi 150]
    extract_structured.py selftest

`extract` writes `<outdir>/lines.jsonl` (one record per line),
`<outdir>/pages.json` (per-page summary), `<outdir>/tables/*.json`
(one per page that has tables), and `<outdir>/manifest.json`.
`render` writes a single `<outdir>/pXXXX_<tag>.png` region render.
`render-tables` re-runs table detection and renders every table bbox.
`selftest` builds a synthetic fixture PDF in a temp dir and checks the
pipeline end to end (no spec PDF needed).
"""
import json
import re
import sys
import tempfile
from pathlib import Path

LINE_TOL_RATIO = 0.5  # y-center clustering tolerance as fraction of median word height


def parse_pages(spec):
    pages = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            pages.update(range(int(a), int(b) + 1))
        else:
            pages.add(int(part))
    return sorted(pages)


def cluster_lines(words):
    """Group PyMuPDF word tuples into visual lines.

    words: (x0, y0, x1, y1, text, block, lineno, wordno).
    Returns lines sorted top-to-bottom; words within a line left-to-right.
    """
    if not words:
        return []
    heights = sorted(w[3] - w[1] for w in words)
    med = heights[len(heights) // 2] or 1.0
    tol = med * LINE_TOL_RATIO
    ordered = sorted(words, key=lambda w: ((w[1] + w[3]) / 2.0, w[0]))
    lines = []
    for w in ordered:
        yc = (w[1] + w[3]) / 2.0
        if lines and abs(yc - lines[-1][0]) <= tol:
            lines[-1][1].append(w)
        else:
            lines.append([yc, [w]])
    out = []
    for _, ws in lines:
        ws.sort(key=lambda w: w[0])
        x0 = min(w[0] for w in ws)
        y0 = min(w[1] for w in ws)
        x1 = max(w[2] for w in ws)
        y1 = max(w[3] for w in ws)
        out.append({"tokens": [(w[0], w[2], w[4]) for w in ws],
                    "bbox": [x0, y0, x1, y1]})
    return out


INT_RE = re.compile(r"^\d{1,6}$")


def doc_margin_x1(all_coords):
    """Document-global margin column: the token right edge (x1) with the
    most bare-integer members document-wide. Printed numbers repeat the
    same column on every numbered page, so the global vote is immune to
    single-page table columns."""
    if not all_coords:
        return None
    best_x, best_n = all_coords[0][0], 0
    for x, _ in all_coords:
        n = sum(1 for c in all_coords if abs(c[0] - x) <= 3.0)
        if n > best_n:
            best_x, best_n = x, n
    return best_x


def page_margin_x1(coords, global_x1):
    """Per-page margin column: the global document column, or None.

    `coords` are (x1, y-center, value) of the page's bare-integer tokens.
    Only the document-global column ever counts as printed numbers --
    even a single member (one numbered prose line above a full-page
    table). A page-local integer column, however run-like (revision
    tables, years, section numbers on front matter), is body content and
    must NOT become anchors. Pages with no global-column member
    (front matter, revision history, TOC) yield None. A page whose real
    margin sits off the global column would lose anchors loudly (gate
    REAL MISS), which is the correct fail direction."""
    if not coords or global_x1 is None:
        return None
    if any(abs(c[0] - global_x1) <= 3.0 for c in coords):
        return global_x1
    return None


def split_printed_number(line, margin_x):
    """Split the margin-column number off a reconstructed line.

    Returns (body_words, printed:int|None). Only a bare-integer token
    sitting in the margin column is treated as a printed number, so
    body-text numerics (table values, clause numbers, years) are never
    misattributed. A line holding ONLY the margin number yields an
    empty body with its printed number (keeps anchor continuity).
    """
    printed = None
    rest = []
    for x0, x1, tok in line["tokens"]:
        if (printed is None and INT_RE.match(tok) and margin_x is not None
                and abs(x1 - margin_x) <= 3.0):
            printed = int(tok)
        else:
            rest.append(tok)
    return rest, printed


def extract_tables(pdf_path, page_no1, dpi=150):
    """Return (tables, note). tables: list of {bbox_pt, rows} or []."""
    import pdfplumber

    with pdfplumber.open(pdf_path) as pdf:
        page = pdf.pages[page_no1 - 1]
        found = page.find_tables()
        tables = []
        for t in found:
            try:
                rows = t.extract_text_lines() or []
            except Exception:
                rows = []
            tables.append({"bbox_pt": list(t.bbox), "rows": rows})
        return tables, "pdfplumber"


def extract_document(pdf_path, outdir, only_pages=None, dpi=150):
    import fitz

    pdf_path = Path(pdf_path)
    outdir = Path(outdir)
    (outdir / "tables").mkdir(parents=True, exist_ok=True)
    doc = fitz.open(pdf_path)
    npages = len(doc)
    pages = only_pages or list(range(1, npages + 1))
    # Pass 1: cluster lines on every page, collect integer-token coords.
    page_lines, page_coords, page_h = {}, {}, {}
    all_coords = []
    for pno in pages:
        page = doc[pno - 1]
        lines = cluster_lines(page.get_text("words"))
        page_lines[pno] = lines
        page_h[pno] = page.rect.height
        coords = []
        for ln in lines:
            yc = (ln["bbox"][1] + ln["bbox"][3]) / 2.0
            for x0, x1, tok in ln["tokens"]:
                if INT_RE.match(tok):
                    coords.append((x1, yc, int(tok)))
        page_coords[pno] = coords
        all_coords += [(c[0], c[1]) for c in coords]
    global_x1 = doc_margin_x1(all_coords)
    # Pass 2: emit with per-page guarded margin columns.
    counter = 0
    page_summaries = []
    with (outdir / "lines.jsonl").open("w", encoding="utf-8") as fh:
        for pno in pages:
            page = doc[pno - 1]
            lines = page_lines[pno]
            margin_x = page_margin_x1(page_coords[pno], global_x1)
            tables, _ = extract_tables(pdf_path, pno, dpi)
            if tables:
                (outdir / "tables" / f"p{pno:04d}.json").write_text(
                    json.dumps({"page": pno, "tables": tables}, indent=1) + "\n",
                    encoding="utf-8",
                )
            first = counter + 1
            for ln in lines:
                counter += 1
                body_words, printed = split_printed_number(ln, margin_x)
                body = " ".join(body_words)
                rec = {
                    "anchor": f"p{pno:04d}-L{counter:04d}",
                    "page": pno,
                    "line": counter,
                    "printed": printed,
                    "bbox_pt": [round(v, 1) for v in ln["bbox"]],
                    "text": body,
                }
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            page_summaries.append(
                {
                    "page": pno,
                    "lines": len(lines),
                    "first_line": first if lines else None,
                    "last_line": counter if lines else None,
                    "tables": len(tables),
                    "size_pt": [page.rect.width, page.rect.height],
                }
            )
    manifest = {
        "tool": "extract_structured.py",
        "backends": {"words": "pymupdf", "tables": "pdfplumber",
                      "renders": "pymupdf-pixmap"},
        "source": {"filename": pdf_path.name, "pages": npages},
        "extracted_pages": pages,
        "total_lines": counter,
        "anchor_scheme": "pXXXX-Lnnnn (continuous per document)",
        "margin_x1_pt": round(global_x1, 1) if global_x1 is not None else None,
    }
    (outdir / "pages.json").write_text(json.dumps(page_summaries, indent=1) + "\n",
                                       encoding="utf-8")
    (outdir / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n",
                                          encoding="utf-8")
    print(f"{pdf_path.name}: {len(pages)}/{npages} pages, "
          f"{counter} lines -> {outdir}")
    return 0


def render_region(pdf_path, outdir, page_no1, bbox, dpi=150, tag="region"):
    import fitz

    doc = fitz.open(pdf_path)
    page = doc[page_no1 - 1]
    clip = fitz.Rect(*bbox)
    pix = page.get_pixmap(clip=clip, dpi=dpi)
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    dest = outdir / f"p{page_no1:04d}_{tag}.png"
    pix.save(dest)
    print(f"page {page_no1} bbox {bbox} @ {dpi}dpi -> {dest} "
          f"({pix.width}x{pix.height})")
    return 0


def render_tables(pdf_path, outdir, dpi=150):
    import fitz

    doc = fitz.open(pdf_path)
    n = 0
    for pno in range(1, len(doc) + 1):
        tables, _ = extract_tables(pdf_path, pno, dpi)
        for i, t in enumerate(tables):
            render_region(pdf_path, outdir, pno, t["bbox_pt"], dpi,
                          tag=f"table{i}")
            n += 1
    print(f"rendered {n} table regions")
    return 0


def build_fixture(path):
    """Two-page synthetic PDF: numbered prose + a ruled table. No spec content."""
    import fitz

    doc = fitz.open()
    p1 = doc.new_page()
    y = 72.0
    words = ("one", "two", "three", "four", "five",
             "six", "seven", "eight", "nine", "ten")
    for i, w in enumerate(words, 1):
        # body text at x=72, printed number in the left margin column x=36
        # (mirrors real spec layout; body carries no bare integers so the
        # margin column is unambiguous)
        p1.insert_text((72, y), f"Fixture prose line {w}", fontsize=11)
        p1.insert_text((36, y), str(1000 + i), fontsize=11)
        y += 14.0
    p2 = doc.new_page()
    # ruled 3x3 grid so pdfplumber "lines" strategy finds it deterministically
    x0, y0, cw, chh = 72.0, 72.0, 120.0, 20.0
    for r in range(4):
        p2.draw_line((x0, y0 + r * chh), (x0 + 3 * cw, y0 + r * chh))
    for c in range(4):
        p2.draw_line((x0 + c * cw, y0), (x0 + c * cw, y0 + 3 * chh))
    for r in range(3):
        for c in range(3):
            p2.insert_text((x0 + c * cw + 4, y0 + r * chh + 14),
                           f"R{r}C{c}", fontsize=10)
    doc.save(path)
    return path


def selftest():
    import pdfplumber

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        pdf = build_fixture(tmp / "fixture.pdf")
        out1, out2 = tmp / "o1", tmp / "o2"
        assert extract_document(pdf, out1) == 0
        assert extract_document(pdf, out2) == 0
        a = (out1 / "lines.jsonl").read_bytes()
        b = (out2 / "lines.jsonl").read_bytes()
        assert a == b, "pipeline is not deterministic"
        recs = [json.loads(l) for l in a.decode().splitlines()]
        p1 = [r for r in recs if r["page"] == 1]
        assert len(p1) == 10, f"expected 10 fixture lines, got {len(p1)}"
        assert [r["anchor"] for r in p1] == [f"p0001-L{i:04d}" for i in range(1, 11)]
        assert [r["printed"] for r in p1] == list(range(1001, 1011))
        assert [r["text"] for r in p1] == [
            f"Fixture prose line {w}" for w in
            ("one", "two", "three", "four", "five",
             "six", "seven", "eight", "nine", "ten")]
        # table detection with explicit ruled-line strategy on the fixture grid
        with pdfplumber.open(pdf) as doc:
            found = doc.pages[1].find_tables()
            assert found, "ruled fixture table not detected"
            grid = found[0].extract()
            assert grid[0][0] == "R0C0" and grid[2][2] == "R2C2", grid
        # on-demand render works and is non-trivial
        assert render_region(pdf, tmp / "img", 2,
                             [72.0, 72.0, 432.0, 132.0]) == 0
        png = tmp / "img" / "p0002_region.png"
        assert png.stat().st_size > 1000, "render unexpectedly small"
        print(f"SELFTEST PASS: {len(recs)} lines, anchors stable, "
              f"table 3x3, render {png.stat().st_size} bytes")
    return 0


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    cmd = argv[0]
    if cmd == "selftest":
        return selftest()
    if cmd == "extract" and len(argv) >= 3:
        pages = parse_pages(argv[3]) if len(argv) > 3 and argv[3].startswith("--pages=") else None
        dpi = 150
        rest = argv[3:]
        for a in rest:
            if a.startswith("--pages="):
                pages = parse_pages(a.split("=", 1)[1])
            elif a.startswith("--dpi="):
                dpi = int(a.split("=", 1)[1])
        return extract_document(argv[1], argv[2], pages, dpi)
    if cmd == "render" and len(argv) >= 4:
        page = int(argv[3].split("=", 1)[1]) if argv[3].startswith("--page=") else int(argv[3])
        bbox = None
        dpi, tag = 150, "region"
        for a in argv[4:]:
            if a.startswith("--bbox="):
                bbox = [float(v) for v in a.split("=", 1)[1].split(",")]
            elif a.startswith("--dpi="):
                dpi = int(a.split("=", 1)[1])
            elif a.startswith("--tag="):
                tag = a.split("=", 1)[1]
        if bbox is None or len(bbox) != 4:
            print("render needs --bbox=x0,y0,x1,y1 (PDF points)", file=sys.stderr)
            return 2
        return render_region(argv[1], argv[2], page, bbox, dpi, tag)
    if cmd == "render-tables" and len(argv) >= 3:
        dpi = int(argv[3].split("=", 1)[1]) if len(argv) > 3 and argv[3].startswith("--dpi=") else 150
        return render_tables(argv[1], argv[2], dpi)
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
