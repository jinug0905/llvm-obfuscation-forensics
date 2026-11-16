#!/usr/bin/env python3
"""
Generate paper figures from results/scores.csv and results/manifest.csv.

Metric note: NCD is not meaningful at whole-file COFF granularity (COFF metadata
dominates; compression signal collapses). Whole-file figures use Jaccard 4-gram
similarity + TLSH. NCD is reserved for section-level analysis (section_analysis.py).

Outputs (PDF + PNG) in results/figures/:
  fig1_jaccard_by_pass.pdf/png  -- grouped bar: Jaccard similarity per pass × family
  fig2_tlsh_by_pass.pdf/png     -- grouped bar: TLSH distance per pass × family
  fig3_overhead_vs_jaccard.pdf  -- scatter: size overhead % vs Jaccard similarity
  fig4_heatmap_jaccard.pdf/png  -- heatmap: Jaccard similarity (rows=family, cols=pass)

Usage:
    python3 pipeline/plot_results.py [--scores results/scores.csv]
                                     [--manifest results/manifest.csv]
                                     [--out results/figures]
"""

import argparse
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as mticker
import numpy as np
import pandas as pd
import seaborn as sns


VARIANTS   = ["sub", "bcf", "fla", "sob"]
PASS_LABEL = {"sub": "SUB", "bcf": "BCF", "fla": "FLA", "sob": "SOB"}

FAMILY_SHORT = {
    "DOS":           "DOS",
    "Zeus":          "Zeus",
    "data-thief":    "DataThief",
    "fill-the-disk": "FillDisk",
    "ransomware":    "Ransom",
    "worm":          "Worm",
}

plt.rcParams.update({
    "font.family":        "serif",
    "font.size":          9,
    "axes.titlesize":     10,
    "axes.labelsize":     9,
    "legend.fontsize":    8,
    "xtick.labelsize":    8,
    "ytick.labelsize":    8,
    "figure.dpi":         150,
    "savefig.dpi":        300,
    "savefig.bbox":       "tight",
    "savefig.pad_inches": 0.05,
})

HATCHES      = ["", "///", "xxx", "..."]
GREY_PALETTE = ["#444444", "#888888", "#aaaaaa", "#cccccc"]


def save(fig: plt.Figure, out_dir: Path, stem: str) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for ext in ("pdf", "png"):
        fig.savefig(out_dir / f"{stem}.{ext}")
        print(f"  saved {out_dir / stem}.{ext}")
    plt.close(fig)


def _grouped_bar(obf: pd.DataFrame, metric: str,
                 ylabel: str, title: str,
                 out_dir: Path, stem: str,
                 legend_loc: str = "upper right") -> None:
    """Shared helper for grouped bar charts."""
    valid    = obf[obf[metric] >= 0] if metric != "tlsh_distance" else obf
    families = [FAMILY_SHORT.get(f, f) for f in valid["family_a"].unique()]
    x        = np.arange(len(families))
    width    = 0.18
    offsets  = np.linspace(-(len(VARIANTS)-1)/2, (len(VARIANTS)-1)/2,
                           len(VARIANTS)) * width

    fig, ax = plt.subplots(figsize=(6.5, 3.2))
    for i, variant in enumerate(VARIANTS):
        sub = valid[valid["variant_b"] == variant].copy()
        sub["fam_short"] = sub["family_a"].map(FAMILY_SHORT)
        vals = [
            float(sub.loc[sub["fam_short"] == f, metric].values[0])
            if f in sub["fam_short"].values else 0
            for f in families
        ]
        ax.bar(x + offsets[i], vals, width,
               label=PASS_LABEL[variant],
               color=GREY_PALETTE[i], hatch=HATCHES[i],
               edgecolor="black", linewidth=0.6)

    ax.set_xlabel("Malware Family")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.set_xticks(x)
    ax.set_xticklabels(families, rotation=15, ha="right")
    ax.yaxis.set_minor_locator(mticker.MultipleLocator(10))
    if metric != "tlsh_distance":
        ax.set_ylim(0, 105)
        ax.axhline(50, color="grey", linestyle="--", linewidth=0.7, alpha=0.6)
    ax.legend(title="Pass", ncol=4, loc=legend_loc, framealpha=0.9)
    ax.grid(axis="y", linestyle=":", linewidth=0.5, alpha=0.7)
    fig.tight_layout()
    save(fig, out_dir, stem)


# ---------------------------------------------------------------------------
# Figure 1 — Jaccard 4-gram similarity grouped bar
# ---------------------------------------------------------------------------
def fig_jaccard_grouped_bar(obf: pd.DataFrame, out_dir: Path) -> None:
    _grouped_bar(
        obf, "jaccard_score",
        ylabel="Jaccard 4-gram Similarity (0–100)",
        title="Jaccard Similarity: Baseline vs. Obfuscated Variant",
        out_dir=out_dir, stem="fig1_jaccard_by_pass",
    )


# ---------------------------------------------------------------------------
# Figure 2 — TLSH distance grouped bar
# ---------------------------------------------------------------------------
def fig_tlsh_grouped_bar(obf: pd.DataFrame, out_dir: Path) -> None:
    numeric = obf[obf["tlsh_distance"] != "n/a"].copy()
    numeric["tlsh_distance"] = numeric["tlsh_distance"].astype(int)
    _grouped_bar(
        numeric, "tlsh_distance",
        ylabel="TLSH Distance (lower = more similar)",
        title="TLSH Dissimilarity: Baseline vs. Obfuscated Variant",
        out_dir=out_dir, stem="fig2_tlsh_by_pass",
        legend_loc="upper left",
    )


# ---------------------------------------------------------------------------
# Figure 3 — Scatter: size overhead % vs Jaccard similarity
# ---------------------------------------------------------------------------
def fig_overhead_scatter(obf: pd.DataFrame, manifest: pd.DataFrame,
                         out_dir: Path) -> None:
    baseline_sz = (manifest[manifest["variant"] == "baseline"]
                   .set_index(["family", "stem"])["size_bytes"])

    rows = []
    for _, r in obf.iterrows():
        key = (r["family_a"], r["stem_a"])
        if key not in baseline_sz.index:
            continue
        b_sz  = baseline_sz[key]
        v_row = manifest[(manifest["family"] == r["family_a"]) &
                         (manifest["stem"]   == r["stem_a"])   &
                         (manifest["variant"] == r["variant_b"])]
        if v_row.empty:
            continue
        overhead = (v_row["size_bytes"].values[0] - b_sz) / b_sz * 100
        jc = r["jaccard_score"]
        if jc < 0:
            continue
        rows.append({
            "pass":     PASS_LABEL[r["variant_b"]],
            "overhead": overhead,
            "jaccard":  jc,
        })

    df      = pd.DataFrame(rows)
    markers = {"SUB": "o", "BCF": "s", "FLA": "^", "SOB": "D"}
    colors  = {"SUB": "#222222", "BCF": "#555555",
               "FLA": "#888888", "SOB": "#aaaaaa"}

    fig, ax = plt.subplots(figsize=(5.0, 3.5))
    for pass_name, grp in df.groupby("pass"):
        ax.scatter(grp["overhead"], grp["jaccard"],
                   marker=markers[pass_name], color=colors[pass_name],
                   s=55, label=pass_name, zorder=3,
                   edgecolors="black", linewidths=0.5)

    ax.set_xlabel("Binary Size Overhead vs. Baseline (%)")
    ax.set_ylabel("Jaccard 4-gram Similarity (0–100)")
    ax.set_title("Evasion vs. Cost Trade-off per Pass")
    ax.legend(title="Pass", framealpha=0.9)
    ax.grid(linestyle=":", linewidth=0.5, alpha=0.7)
    ax.set_ylim(-5, 105)
    fig.tight_layout()
    save(fig, out_dir, "fig3_overhead_vs_jaccard")


# ---------------------------------------------------------------------------
# Figure 4 — Heatmap: Jaccard similarity (rows = family, cols = pass)
# ---------------------------------------------------------------------------
def fig_jaccard_heatmap(obf: pd.DataFrame, out_dir: Path) -> None:
    valid = obf[obf["jaccard_score"] >= 0]
    pivot = valid.pivot_table(
        index="family_a", columns="variant_b",
        values="jaccard_score", aggfunc="mean"
    )[VARIANTS]
    pivot.index   = [FAMILY_SHORT.get(f, f) for f in pivot.index]
    pivot.columns = [PASS_LABEL[v] for v in VARIANTS]

    fig, ax = plt.subplots(figsize=(4.5, 3.0))
    sns.heatmap(
        pivot, ax=ax,
        annot=True, fmt=".0f",
        cmap="Greys_r",
        linewidths=0.5, linecolor="white",
        vmin=0, vmax=100,
        cbar_kws={"label": "Jaccard Similarity"},
    )
    ax.set_title("Jaccard Similarity Heatmap\n(Baseline → Obfuscated Variant)")
    ax.set_xlabel("Obfuscation Pass")
    ax.set_ylabel("Malware Family")
    ax.tick_params(axis="x", rotation=0)
    ax.tick_params(axis="y", rotation=0)
    fig.tight_layout()
    save(fig, out_dir, "fig4_heatmap_jaccard")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scores",   default="results/scores.csv")
    parser.add_argument("--manifest", default="results/manifest.csv")
    parser.add_argument("--out",      default="results/figures")
    args = parser.parse_args()

    scores_path   = Path(args.scores)
    manifest_path = Path(args.manifest)
    out_dir       = Path(args.out)

    if not scores_path.exists():
        sys.exit(f"ERROR: {scores_path} not found — run analyze_similarity.py first")
    if not manifest_path.exists():
        sys.exit(f"ERROR: {manifest_path} not found")

    scores   = pd.read_csv(scores_path)
    manifest = pd.read_csv(manifest_path)

    def parse_family_stem(row):
        parts = Path(row["output_path"]).parts
        try:
            idx = parts.index("bin")
            return pd.Series({"family": parts[idx + 1], "stem": parts[idx + 2]})
        except (ValueError, IndexError):
            return pd.Series({"family": "", "stem": ""})

    manifest[["family", "stem"]] = manifest.apply(parse_family_stem, axis=1)
    obf = scores[scores["comparison"] == "obfuscated"].copy()

    print("Generating figures …")
    fig_jaccard_grouped_bar(obf, out_dir)
    fig_tlsh_grouped_bar(obf, out_dir)
    fig_overhead_scatter(obf, manifest, out_dir)
    fig_jaccard_heatmap(obf, out_dir)
    print(f"\nDone — 4 figures written to {out_dir}/")


if __name__ == "__main__":
    main()
