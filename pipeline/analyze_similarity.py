#!/usr/bin/env python3
"""
Compute NCD, TLSH, and Jaccard similarity scores for all obfuscated object
files versus their per-sample baselines, then write results/scores.csv.

Metrics:
  ncd_score    -- Normalized Compression Distance (zlib), converted to 0–100
                  similarity (100 = identical). Cilibrasi & Vitányi 2005.
  tlsh_distance -- TLSH locality-sensitive hash distance (lower = more similar).
  jaccard_score -- 4-byte n-gram Jaccard similarity, 0–100 (100 = identical).

Usage:
    python3 pipeline/analyze_similarity.py [--bin results/bin] [--out results/scores.csv]
"""

import argparse
import csv
import sys
import zlib
from itertools import combinations
from pathlib import Path

try:
    import tlsh
except ImportError:
    sys.exit("ERROR: python-tlsh not installed.  pip3 install python-tlsh")


VARIANTS = ["sub", "bcf", "fla", "sob"]


# ---------------------------------------------------------------------------
# Similarity metrics
# ---------------------------------------------------------------------------

def ncd_score(path_a: Path, path_b: Path) -> float:
    """
    Normalized Compression Distance converted to a 0–100 similarity score.
    NCD(a,b) = (C(ab) - min(C(a),C(b))) / max(C(a),C(b))
    similarity = round((1 - NCD) * 100, 1)
    Uses zlib level 9 for maximum compression sensitivity.
    """
    a = path_a.read_bytes()
    b = path_b.read_bytes()
    ca  = len(zlib.compress(a, 9))
    cb  = len(zlib.compress(b, 9))
    cab = len(zlib.compress(a + b, 9))
    ncd = (cab - min(ca, cb)) / max(ca, cb)
    return round((1.0 - ncd) * 100.0, 1)


def tlsh_distance(path_a: Path, path_b: Path):
    """TLSH distance (lower = more similar; 0 = identical).
    Returns 'n/a' when a file is too small for a valid digest."""
    ha = tlsh.hash(path_a.read_bytes())
    hb = tlsh.hash(path_b.read_bytes())
    if ha == "TNULL" or hb == "TNULL":
        return "n/a"
    return tlsh.diff(ha, hb)


def jaccard4_score(path_a: Path, path_b: Path) -> float:
    """4-byte n-gram Jaccard similarity, 0–100 (100 = identical).
    Returns -1 when either file is too short to form any 4-gram."""
    a = path_a.read_bytes()
    b = path_b.read_bytes()
    if len(a) < 4 or len(b) < 4:
        return -1.0
    mv_a = memoryview(a)
    mv_b = memoryview(b)
    set_a = {bytes(mv_a[i:i+4]) for i in range(len(a) - 3)}
    set_b = {bytes(mv_b[i:i+4]) for i in range(len(b) - 3)}
    union = set_a | set_b
    if not union:
        return 100.0
    return round(len(set_a & set_b) / len(union) * 100.0, 1)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def discover_samples(bin_dir: Path):
    samples = []
    for family_dir in sorted(bin_dir.iterdir()):
        if not family_dir.is_dir():
            continue
        for stem_dir in sorted(family_dir.iterdir()):
            if not stem_dir.is_dir():
                continue
            if not (stem_dir / "baseline.o").exists():
                print(f"  [skip] no baseline.o in {stem_dir}", file=sys.stderr)
                continue
            samples.append((family_dir.name, stem_dir.name, stem_dir))
    return samples


# ---------------------------------------------------------------------------
# Core comparison
# ---------------------------------------------------------------------------

def run_pairwise(samples) -> list[dict]:
    rows = []

    # within-sample: baseline vs each obfuscation variant
    for family, stem, d in samples:
        baseline = d / "baseline.o"
        for variant in VARIANTS:
            vpath = d / f"{variant}.o"
            if not vpath.exists():
                print(f"  [warn] missing {vpath}", file=sys.stderr)
                continue
            nc = ncd_score(baseline, vpath)
            td = tlsh_distance(baseline, vpath)
            jc = jaccard4_score(baseline, vpath)
            rows.append({
                "comparison": "obfuscated",
                "family_a": family, "stem_a": stem, "variant_a": "baseline",
                "family_b": family, "stem_b": stem, "variant_b": variant,
                "ncd_score": nc, "tlsh_distance": td, "jaccard_score": jc,
            })
            print(f"  {family}/{stem}  baseline→{variant:3s}  "
                  f"ncd={nc:5.1f}  tlsh={str(td):5s}  jaccard={jc:5.1f}")

    # cross-sample: baseline vs baseline (false-positive reference)
    baselines = [(fam, stem, d / "baseline.o") for fam, stem, d in samples]
    for (fam_a, stem_a, pa), (fam_b, stem_b, pb) in combinations(baselines, 2):
        nc = ncd_score(pa, pb)
        td = tlsh_distance(pa, pb)
        jc = jaccard4_score(pa, pb)
        rows.append({
            "comparison": "cross-sample",
            "family_a": fam_a, "stem_a": stem_a, "variant_a": "baseline",
            "family_b": fam_b, "stem_b": stem_b, "variant_b": "baseline",
            "ncd_score": nc, "tlsh_distance": td, "jaccard_score": jc,
        })
        print(f"  cross  {fam_a}/{stem_a} vs {fam_b}/{stem_b}  "
              f"ncd={nc:5.1f}  tlsh={str(td):5s}  jaccard={jc:5.1f}")

    return rows


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def print_summary(rows: list[dict]) -> None:
    print("\n" + "=" * 76)
    print(f"{'PASS':<6}  {'NCD avg':>8}  {'NCD min':>8}  "
          f"{'TLSH avg':>9}  {'TLSH max':>9}  {'Jacc avg':>9}  {'Jacc min':>9}")
    print("-" * 76)
    obf = [r for r in rows if r["comparison"] == "obfuscated"]
    for v in VARIANTS:
        vr = [r for r in obf if r["variant_b"] == v]
        nc_v = [r["ncd_score"]    for r in vr]
        td_v = [r["tlsh_distance"] for r in vr if r["tlsh_distance"] != "n/a"]
        jc_v = [r["jaccard_score"] for r in vr if r["jaccard_score"] >= 0]
        def avg(lst): return sum(lst)/len(lst) if lst else float("nan")
        def mn(lst):  return min(lst) if lst else float("nan")
        def mx(lst):  return max(lst) if lst else float("nan")
        print(f"{v:<6}  {avg(nc_v):>8.1f}  {mn(nc_v):>8.1f}  "
              f"{avg(td_v):>9.1f}  {mx(td_v):>9}  "
              f"{avg(jc_v):>9.1f}  {mn(jc_v):>9.1f}")
    print("=" * 76)

    cross = [r for r in rows if r["comparison"] == "cross-sample"]
    if cross:
        nc_c = [r["ncd_score"]    for r in cross]
        td_c = [r["tlsh_distance"] for r in cross if r["tlsh_distance"] != "n/a"]
        jc_c = [r["jaccard_score"] for r in cross if r["jaccard_score"] >= 0]
        print(f"\nCross-sample baseline pairs ({len(cross)} pairs) — false-positive floor:")
        print(f"  NCD:    avg={sum(nc_c)/len(nc_c):.1f}  max={max(nc_c):.1f}")
        if td_c:
            print(f"  TLSH:   avg={sum(td_c)/len(td_c):.1f}  min={min(td_c)}")
        if jc_c:
            print(f"  Jacc:   avg={sum(jc_c)/len(jc_c):.1f}  max={max(jc_c):.1f}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", default="results/bin",       metavar="DIR")
    parser.add_argument("--out", default="results/scores.csv", metavar="CSV")
    args = parser.parse_args()

    bin_dir  = Path(args.bin)
    out_path = Path(args.out)

    if not bin_dir.exists():
        sys.exit(f"ERROR: bin directory not found: {bin_dir}")

    print(f"Scanning {bin_dir} …")
    samples = discover_samples(bin_dir)
    if not samples:
        sys.exit("ERROR: no samples found")
    print(f"Found {len(samples)} samples: "
          + ", ".join(f"{f}/{s}" for f, s, _ in samples))
    print()

    rows = run_pairwise(samples)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["comparison", "family_a", "stem_a", "variant_a",
                  "family_b", "stem_b", "variant_b",
                  "ncd_score", "tlsh_distance", "jaccard_score"]
    with out_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)

    print(f"\nWrote {len(rows)} rows → {out_path}")
    print_summary(rows)


if __name__ == "__main__":
    main()
