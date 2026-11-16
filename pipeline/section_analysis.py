#!/usr/bin/env python3
"""
Section-level forensic similarity analysis (RQ3).

Extracts .text* and .rdata* section blobs from every COFF object file,
runs NCD, TLSH, and Jaccard on each aggregate blob, and writes
results/section_scores.csv.  Also generates fig5 and fig6.

Requires: lief, python-tlsh, matplotlib, seaborn, pandas

Usage:
    python3 pipeline/section_analysis.py [--bin results/bin] [--out results]
"""

import argparse
import csv
import sys
import zlib
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

try:
    import lief
except ImportError:
    sys.exit("ERROR: lief not installed.  pip3 install lief")

try:
    import tlsh
except ImportError:
    sys.exit("ERROR: python-tlsh not installed.  pip3 install python-tlsh")


VARIANTS     = ["sub", "bcf", "fla", "sob"]
PASS_LABEL   = {"sub": "SUB", "bcf": "BCF", "fla": "FLA", "sob": "SOB"}
SECTIONS     = [".text", ".rdata"]   # prefix keys; aggregated across all COMDAT splits
FAMILY_SHORT = {
    "DOS": "DOS", "Zeus": "Zeus", "data-thief": "DataThief",
    "fill-the-disk": "FillDisk", "ransomware": "Ransom", "worm": "Worm",
}

plt.rcParams.update({
    "font.family": "serif", "font.size": 9,
    "axes.titlesize": 10, "axes.labelsize": 9,
    "legend.fontsize": 8, "xtick.labelsize": 8, "ytick.labelsize": 8,
    "figure.dpi": 150, "savefig.dpi": 300,
    "savefig.bbox": "tight", "savefig.pad_inches": 0.05,
})


# ---------------------------------------------------------------------------
# COFF helpers
# ---------------------------------------------------------------------------

def _full_section_name(s) -> str:
    """Return the full section name, resolving COFF string-table references."""
    if s.name.startswith('/'):
        return s.coff_string.string
    return s.name


def extract_section_blob(obj_path: Path, prefix: str) -> bytes:
    """
    Parse a COFF object file and concatenate the content of all sections
    whose full name starts with `prefix` (e.g. ".text" or ".rdata").
    Returns b"" when no matching section is found.
    """
    try:
        obj = lief.parse(str(obj_path))
    except Exception as e:
        print(f"  [warn] lief failed on {obj_path}: {e}", file=sys.stderr)
        return b""
    return b"".join(
        bytes(s.content)
        for s in obj.sections
        if _full_section_name(s).startswith(prefix)
    )


# ---------------------------------------------------------------------------
# Similarity metrics (bytes → score)
# ---------------------------------------------------------------------------

def ncd_score_bytes(a: bytes, b: bytes) -> float:
    """NCD similarity 0–100 (100 = identical). Returns -1 if either blob is empty."""
    if not a or not b:
        return -1.0
    ca  = len(zlib.compress(a, 9))
    cb  = len(zlib.compress(b, 9))
    cab = len(zlib.compress(a + b, 9))
    ncd = (cab - min(ca, cb)) / max(ca, cb)
    return round((1.0 - ncd) * 100.0, 1)


def tlsh_distance_bytes(a: bytes, b: bytes):
    """TLSH distance (lower = more similar; 0 = identical). Returns 'n/a' if too small."""
    if not a or not b:
        return "n/a"
    ha = tlsh.hash(a)
    hb = tlsh.hash(b)
    if ha == "TNULL" or hb == "TNULL":
        return "n/a"
    return tlsh.diff(ha, hb)


def jaccard4_score_bytes(a: bytes, b: bytes) -> float:
    """4-byte n-gram Jaccard similarity 0–100 (100 = identical).
    Returns -1 when either blob is too short."""
    if len(a) < 4 or len(b) < 4:
        return -1.0
    set_a = {a[i:i+4] for i in range(len(a) - 3)}
    set_b = {b[i:i+4] for i in range(len(b) - 3)}
    union = set_a | set_b
    if not union:
        return 100.0
    return round(len(set_a & set_b) / len(union) * 100.0, 1)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

def discover_samples(bin_dir: Path):
    """Yield (family, stem, dir_path) for every directory containing baseline.o."""
    for family_dir in sorted(bin_dir.iterdir()):
        if not family_dir.is_dir():
            continue
        for stem_dir in sorted(family_dir.iterdir()):
            if not stem_dir.is_dir():
                continue
            if (stem_dir / "baseline.o").exists():
                yield family_dir.name, stem_dir.name, stem_dir


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def run_section_analysis(samples) -> list[dict]:
    rows = []
    for family, stem, d in samples:
        baseline = d / "baseline.o"
        for section_prefix in SECTIONS:
            blob_base = extract_section_blob(baseline, section_prefix)
            base_sz   = len(blob_base)

            for variant in VARIANTS:
                vpath     = d / f"{variant}.o"
                blob_var  = extract_section_blob(vpath, section_prefix)
                var_sz    = len(blob_var)
                overhead  = (var_sz - base_sz) / base_sz * 100 if base_sz else float("nan")

                nc = ncd_score_bytes(blob_base, blob_var)
                td = tlsh_distance_bytes(blob_base, blob_var)
                jc = jaccard4_score_bytes(blob_base, blob_var)

                section_label = section_prefix.lstrip(".")     # "text" or "rdata"
                rows.append({
                    "family":            family,
                    "stem":              stem,
                    "section":           section_label,
                    "variant":           variant,
                    "baseline_sz":       base_sz,
                    "variant_sz":        var_sz,
                    "size_overhead_pct": round(overhead, 2),
                    "ncd_score":         nc,
                    "tlsh_distance":     td,
                    "jaccard_score":     jc,
                })
                print(f"  {family:15s}/{stem:12s}  {section_label:6s}  "
                      f"{variant:3s}  ncd={nc:5.1f}  tlsh={str(td):5s}  "
                      f"jaccard={jc:5.1f}  size+{overhead:+.1f}%")
    return rows


# ---------------------------------------------------------------------------
# Figures 5-1 and 5-2 — separate heatmaps for .text* and .rdata* NCD scores
# ---------------------------------------------------------------------------

def _single_section_heatmap(df: pd.DataFrame, sec_key: str,
                             sec_title: str, out_dir: Path, stem: str) -> None:
    """Render one NCD similarity heatmap for a single section prefix."""
    sub = df[df["section"] == sec_key].copy()
    sub["fam_short"] = sub["family"].map(FAMILY_SHORT)
    pivot = sub.pivot_table(
        index="fam_short", columns="variant",
        values="ncd_score", aggfunc="mean"
    )
    pivot = pivot[[v for v in VARIANTS if v in pivot.columns]].rename(columns=PASS_LABEL)

    fig, ax = plt.subplots(figsize=(4.5, 3.0))
    sns.heatmap(
        pivot, ax=ax,
        annot=True, fmt=".0f",
        cmap="Greys_r",
        linewidths=0.5, linecolor="white",
        vmin=0, vmax=100,
        cbar_kws={"label": "NCD Similarity"},
    )
    ax.set_title(f"NCD Similarity — {sec_title} Sections\n"
                 "(Baseline → Obfuscated Variant)")
    ax.set_xlabel("Obfuscation Pass")
    ax.set_ylabel("Malware Family")
    ax.tick_params(axis="x", rotation=0)
    ax.tick_params(axis="y", rotation=0)
    fig.tight_layout()

    out_dir.mkdir(parents=True, exist_ok=True)
    for ext in ("pdf", "png"):
        p = out_dir / f"{stem}.{ext}"
        fig.savefig(p)
        print(f"  saved {p}")
    plt.close(fig)


def fig_section_heatmaps(df: pd.DataFrame, out_dir: Path) -> None:
    _single_section_heatmap(df, "text",  ".text*",  out_dir, "fig5_1_section_heatmap_text")
    _single_section_heatmap(df, "rdata", ".rdata*", out_dir, "fig5_2_section_heatmap_rdata")


# ---------------------------------------------------------------------------
# Figure 6 — size overhead by section and pass (bar chart)
# ---------------------------------------------------------------------------

def fig_section_overhead(df: pd.DataFrame, out_dir: Path) -> None:
    HATCHES = ["", "///", "xxx", "..."]
    GREYS   = ["#444444", "#888888", "#aaaaaa", "#cccccc"]

    sections = [("text", ".text*"), ("rdata", ".rdata*")]
    fig, axes = plt.subplots(1, 2, figsize=(8.0, 3.2), sharey=False)

    for ax, (sec_key, sec_title) in zip(axes, sections):
        sub = df[df["section"] == sec_key].copy()
        sub["fam_short"] = sub["family"].map(FAMILY_SHORT)
        families = sorted(sub["fam_short"].unique())
        import numpy as np
        x = np.arange(len(families))
        width = 0.18
        offsets = np.linspace(-(len(VARIANTS)-1)/2, (len(VARIANTS)-1)/2, len(VARIANTS)) * width

        for i, variant in enumerate(VARIANTS):
            vdata = sub[sub["variant"] == variant]
            vals = [
                vdata.loc[vdata["fam_short"] == f, "size_overhead_pct"].values[0]
                if f in vdata["fam_short"].values else 0
                for f in families
            ]
            ax.bar(x + offsets[i], vals, width,
                   label=PASS_LABEL[variant], color=GREYS[i], hatch=HATCHES[i],
                   edgecolor="black", linewidth=0.6)

        ax.set_title(f"Size Overhead — {sec_title}")
        ax.set_xlabel("Malware Family")
        ax.set_ylabel("Overhead (%)" if ax is axes[0] else "")
        ax.set_xticks(x)
        ax.set_xticklabels(families, rotation=15, ha="right")
        ax.grid(axis="y", linestyle=":", linewidth=0.5, alpha=0.7)
        if ax is axes[0]:
            ax.legend(title="Pass", ncol=2, fontsize=7, framealpha=0.9)

    fig.tight_layout()
    for ext in ("pdf", "png"):
        p = out_dir / f"fig6_section_overhead.{ext}"
        fig.savefig(p)
        print(f"  saved {p}")
    plt.close(fig)


# ---------------------------------------------------------------------------
# Summary table
# ---------------------------------------------------------------------------

def print_summary(rows: list[dict]) -> None:
    print("\n" + "=" * 80)
    print(f"{'SECTION':6s}  {'PASS':5s}  {'NCD avg':>8s}  {'NCD min':>8s}  "
          f"{'Jacc avg':>9s}  {'Jacc min':>9s}  {'overhead%':>10s}")
    print("-" * 80)
    for sec in ["text", "rdata"]:
        for variant in VARIANTS:
            subset = [r for r in rows if r["section"] == sec and r["variant"] == variant]
            if not subset:
                continue
            nc_v = [r["ncd_score"]     for r in subset if r["ncd_score"]     >= 0]
            jc_v = [r["jaccard_score"] for r in subset if r["jaccard_score"] >= 0]
            oh_v = [r["size_overhead_pct"] for r in subset]
            def avg(lst): return sum(lst)/len(lst) if lst else float("nan")
            def mn(lst):  return min(lst) if lst else float("nan")
            print(f"{sec:6s}  {PASS_LABEL[variant]:5s}  "
                  f"{avg(nc_v):>8.1f}  {mn(nc_v):>8.1f}  "
                  f"{avg(jc_v):>9.1f}  {mn(jc_v):>9.1f}  "
                  f"{avg(oh_v):>+10.1f}%")
        print()
    print("=" * 80)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin", default="results/bin",  metavar="DIR")
    parser.add_argument("--out", default="results",      metavar="DIR")
    args = parser.parse_args()

    bin_dir  = Path(args.bin)
    out_dir  = Path(args.out)
    csv_path = out_dir / "section_scores.csv"
    fig_dir  = out_dir / "figures"

    if not bin_dir.exists():
        sys.exit(f"ERROR: {bin_dir} not found")

    samples = list(discover_samples(bin_dir))
    if not samples:
        sys.exit("ERROR: no samples found")
    print(f"Found {len(samples)} samples\n")

    rows = run_section_analysis(samples)

    out_dir.mkdir(parents=True, exist_ok=True)
    fieldnames = ["family", "stem", "section", "variant",
                  "baseline_sz", "variant_sz", "size_overhead_pct",
                  "ncd_score", "tlsh_distance", "jaccard_score"]
    with csv_path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)
    print(f"\nWrote {len(rows)} rows → {csv_path}")

    print_summary(rows)

    print("\nGenerating figures …")
    df = pd.DataFrame(rows)
    fig_section_heatmaps(df, fig_dir)
    fig_section_overhead(df, fig_dir)
    print("Done.")


if __name__ == "__main__":
    main()
