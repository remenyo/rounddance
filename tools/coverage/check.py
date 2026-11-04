#!/usr/bin/env python3
"""Live spec-coverage checker: universe from corpus, annotations from source.

Coverage is derived, never stored. See README.md for the tag spec.
Usage: python3 tools/coverage/check.py [--report out.json] [--strict]
Exit: 0 normally; --strict exits 2 on validation errors (bad tags,
unresolvable anchors, missing @verifies targets). Coverage % is
informational and never fails.
D1: output carries doc numbers, pages, lines, req IDs, file paths only.
"""
import argparse
import json
import pathlib
import re
import sys

CORPUS = pathlib.Path("/home/dev/projects/rounddance-private/corpus/text")
REPO = pathlib.Path(__file__).resolve().parents[2]
CRATES = REPO / "crates"

DOC_SLUG = {
    "05-3474-23": "zigbee-spec-r23-05-3474-23",
    "07-5123-08": "zcl-07-5123-08",
    "14-0563-19": "green-power-basic-14-0563-19",
    "17-05019-012": "linky-metering-cluster-17-05019-012",
    "17-05031-011": "erl-interface-device-17-05031-011",
    "17-05035-016": "daily-schedule-cluster-17-05035-016",
    "15-0014-05": "lighting-occupancy-15-0014-05",
    "23-02016-002": "device-type-library-23-02016-002",
    "23-80986-022": "iot-security-pswg-23-80986-022",
    "26-42802-001": "aliro-26-42802-001",
    "20-27688-041": "zigbee-direct-20-27688-041",
    "22-65816-030": "pro-bdb-22-65816-030",
    "07-5356-22": "smart-energy-07-5356-22",
    "802.15.4-2020": "ieee-802-15-4-2020",
    "802.15.4-2024": "ieee-802-15-4-2024",
}
# Margin-run docs: universe is the global margin-number run (page locates).
MARGIN_RUN = {"17-05031-011": (1, 147), "17-05035-016": (1, 386), "15-0014-05": (1, 1453)}
# Page-touch docs: no line anchors in extraction.
PAGE_ONLY = {"26-42802-001", "802.15.4-2020", "802.15.4-2024"}

TRAIL = re.compile(r"(\d{1,5})\s*$")
FOOTER = re.compile(r"Page\s+\d+\s*$")
TAG = re.compile(r"@(\w+)\s+((?:[a-z]+=\S+\s*)+)")
KV = re.compile(r"([a-z]+)=(\S+)")
LEGACY = re.compile(r"p(\d{3,4})-L(\d+)(?:-L(\d+))?")
VAL = re.compile(r"^[A-Za-z0-9._/+,:\-§]+$")


def universe(slug):
    """Exact page-line anchor strings for trailing-number docs."""
    u = set()
    for f in sorted((CORPUS / slug).glob("p*.txt")):
        pg = "p" + f.stem[1:]
        for line in open(f, errors="ignore"):
            s = line.rstrip()
            if not s or s.startswith("SOURCE") or s.startswith("==="):
                continue
            if FOOTER.search(s):
                continue
            m = TRAIL.search(s)
            if m:
                u.add(f"{pg}-L{int(m.group(1))}")
    return u


def pages(slug):
    return sorted(p.stem for p in (CORPUS / slug).glob("p*.txt"))


def expand_lines(spec):
    """'p0086-L2166-L2168,p0087-L2200' -> ['p0086-L2166', ...]."""
    out = []
    for part in spec.split(","):
        m = re.fullmatch(r"(p\d{3,4})-L(\d+)(?:-L(\d+))?", part)
        if not m:
            return None
        pg, s, t = m.group(1), int(m.group(2)), m.group(3)
        if t:
            if int(t) < s or int(t) - s > 5000:
                return None
            out.extend(f"{pg}-L{n}" for n in range(s, int(t) + 1))
        else:
            out.append(f"{pg}-L{s}")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default=None)
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--syntax-only", action="store_true",
                    help="validate tag shape + verifies targets without the "
                         "private corpus (for CI, which has no corpus access)")
    args = ap.parse_args()
    errors = []
    # Universes (per doc). Syntax-only: skip corpus, resolve nothing.
    uni, pgs = {}, {}
    if not args.syntax_only:
        for doc, slug in DOC_SLUG.items():
            if doc in MARGIN_RUN or doc in PAGE_ONLY:
                uni[doc], pgs[doc] = set(), set(pages(slug))
            else:
                uni[doc] = universe(slug)
                pgs[doc] = {a.split("-")[0] for a in uni[doc]}
    covered, nas, deferred, legacy = {}, {}, {}, {}
    verifies = []
    # File-level doc ties for margin-run attribution: doc number in the
    # file header block or a doc-prefixed req ID anywhere in the file.
    TIENUM = re.compile(r"\b(17-05031-011|17-05035-016|15-0014-05)\b")
    REQTIENUM = re.compile(r"\b(17-05031-011|17-05035-016|15-0014-05)-\d")
    file_ties = {}
    rs_files = sorted(CRATES.rglob("*.rs"))
    for f in rs_files:
        try:
            txt = open(f, errors="ignore").read()
        except OSError:
            continue
        head = "\n".join(txt.splitlines()[:30])
        ties = set(TIENUM.findall(head)) | {m for m in REQTIENUM.findall(txt)}
        if ties:
            file_ties[str(f.relative_to(REPO))] = ties
    for f in rs_files:
        rel = str(f.relative_to(REPO))
        ties = file_ties.get(rel, set())
        for ln, line in enumerate(open(f, errors="ignore"), 1):
            for tm in TAG.finditer(line):
                kind, body = tm.group(1), tm.group(2)
                kv = dict(KV.findall(body))
                if kind not in ("covers", "verifies", "na", "deferred"):
                    errors.append(f"{rel}:{ln}: unknown tag @{kind}")
                    continue
                if kind == "verifies":
                    verifies.append((rel, ln, kv))
                    for k in ("req", "test"):
                        if k not in kv:
                            errors.append(f"{rel}:{ln}: @verifies missing {k}")
                    continue
                doc = kv.get("doc")
                if doc not in DOC_SLUG:
                    errors.append(f"{rel}:{ln}: unknown doc {doc}")
                    continue
                for v in kv.values():
                    if not VAL.match(v):
                        errors.append(f"{rel}:{ln}: bad value {v!r}")
                lines = expand_lines(kv.get("lines", ""))
                if lines is None:
                    errors.append(f"{rel}:{ln}: bad lines {kv.get('lines')!r}")
                    continue
                if args.syntax_only:
                    dest = {"covers": covered, "na": nas, "deferred": deferred}.get(
                        kind)
                    if dest is not None:
                        dest.setdefault(doc, set()).update(lines)
                    continue
                if doc in PAGE_ONLY:
                    # page-touch: keep page part only
                    touched = {a.split("-L")[0] for a in lines}
                    bad = sorted(t for t in touched if t not in pgs[doc])
                    if bad:
                        errors.append(f"{rel}:{ln}: unknown pages {bad}")
                        continue
                    store = touched
                elif doc in MARGIN_RUN:
                    lo, hi = MARGIN_RUN[doc]
                    bad = [a for a in lines
                           if not (lo <= int(a.split("-L")[1]) <= hi)]
                    if bad:
                        errors.append(f"{rel}:{ln}: out-of-run {bad[:3]}")
                        continue
                    store = lines
                else:
                    bad = [a for a in lines if a not in uni[doc]]
                    if bad:
                        errors.append(f"{rel}:{ln}: unresolvable {bad[:3]}")
                        continue
                    store = lines
                dest = {"covers": covered, "na": nas, "deferred": deferred}[kind]
                dest.setdefault(doc, set()).update(store)
            for m in LEGACY.finditer(line):
                pg, s, t = "p" + m.group(1), int(m.group(2)), m.group(3)
                rng = [f"{pg}-L{n}" for n in range(s, int(t) + 1)] if t \
                    else [f"{pg}-L{s}"]
                legacy.setdefault(pg, []).append((rel, rng, ties))
    # @verifies target existence.
    for rel, ln, kv in verifies:
        tp = kv.get("test", "")
        if "::" in tp:
            path, name = tp.split("::", 1)
            fp = REPO / path
            if not fp.exists() or name not in open(fp, errors="ignore").read():
                errors.append(f"{rel}:{ln}: verifies target missing {tp}")
        else:
            errors.append(f"{rel}:{ln}: verifies test not path::name")
    if args.syntax_only:
        print(f"syntax-only: tags parsed, {len(errors)} errors, "
              f"{len(verifies)} @verifies targets checked")
        for e in errors[:20]:
            print(" ", e)
        return 2 if errors else 0
    report = {"docs": {}, "scope_note": "802.15.4 page-touch reported separately"}
    for doc in DOC_SLUG:
        if doc in PAGE_ONLY:
            cov = {a for a in covered.get(doc, set())}
            report["docs"][doc] = {"total": len(pgs[doc]), "unit": "pages",
                                   "covered": len(cov), "na": 0, "deferred": 0,
                                   "gap": None, "pct": None,
                                   "touched": sorted(cov)}
            continue
        if doc in MARGIN_RUN:
            lo, hi = MARGIN_RUN[doc]
            total = hi - lo + 1
            cov = {int(a.split("-L")[1]) for a in covered.get(doc, set())}
            na = {int(a.split("-L")[1]) for a in nas.get(doc, set())}
            df = {int(a.split("-L")[1]) for a in deferred.get(doc, set())}
            # legacy continuity: free-form cites count only for docs the
            # citing file is tied to (doc number in header or doc-prefixed
            # req ID in file), on a page of this doc with the line inside
            # the margin run. Untied cites never count here.
            docnum = doc  # DOC_SLUG keys are already document numbers
            for pg, hits in legacy.items():
                if pg not in pgs[doc]:
                    continue
                for _, rng, ties in hits:
                    if docnum not in ties:
                        continue
                    for a in rng:
                        n = int(a.split("-L")[1])
                        if lo <= n <= hi:
                            cov.add(n)
            accounted = cov | na | df
            gap = [f"L{n}" for n in range(lo, hi + 1) if n not in accounted]
            report["docs"][doc] = {"total": total, "unit": "lines",
                                   "covered": len(cov), "na": len(na),
                                   "deferred": len(df), "gap": len(gap),
                                   "pct": round(100 * len(accounted) / total, 2),
                                   "gap_lines": gap[:50], "gap_truncated": len(gap) > 50}
            continue
        total = len(uni[doc])
        cov = set(covered.get(doc, set()))
        na = set(nas.get(doc, set()))
        df = set(deferred.get(doc, set()))
        accounted = cov | na | df
        # legacy continuity: free-form cites resolving in-universe count too
        leg = set()
        for pg, hits in legacy.items():
            for _, rng, _ in hits:
                for a in rng:
                    if a in uni[doc]:
                        leg.add(a)
        accounted |= leg
        gap = sorted(set(uni[doc]) - accounted)
        report["docs"][doc] = {"total": total, "covered": len(cov | leg),
                               "na": len(na), "deferred": len(df),
                               "gap": len(gap), "pct": round(100 * len(accounted) / max(1, total), 2),
                               "gap_sample": gap[:20]}
    if args.report:
        json.dump(report, open(args.report, "w"), indent=1)
    for d, r in report["docs"].items():
        print(f"{d}: total={r['total']} covered={r.get('covered')} "
              f"na={r.get('na')} deferred={r.get('deferred')} gap={r.get('gap')} pct={r.get('pct')}")
    if errors:
        print(f"\nERRORS ({len(errors)}):")
        for e in errors[:20]:
            print(" ", e)
        if args.strict:
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
