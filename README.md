# When the Compiler Is the Adversary
### Evaluating Forensic Similarity Digests Against LLVM Obfuscation Passes

> **CSCE 712 — Digital Forensics, Texas A&M University, Fall 2026**
> Jinug Lee · jinug_lee@tamu.edu

This repository contains the full reproducible pipeline for the course project.
Everything in the pipeline is **static analysis only** — malware source files are compiled to object files (`.o`) and never linked, executed, or run in any environment. The corpus is not committed to this repository (see [Corpus](#corpus) below).

The four obfuscation passes are inspired by the original [Obfuscator-LLVM](https://github.com/obfuscator-llvm/obfuscator) project and reimplemented from scratch for the LLVM 22 new pass manager API.

Special thanks to [@aahmadnejad](https://github.com/aahmadnejad) for generously sharing the malware source samples used in this study.

---

## Research questions

| # | Question | Key finding |
|---|----------|-------------|
| RQ1 | How does each metric's similarity score degrade by obfuscation pass? | Jaccard 4-gram stays above the cross-sample floor for all passes; TLSH only breaches threshold 86 under SOB (avg distance 95.7) |
| RQ2 | What size overhead must an adversary pay per pass? | SUB ≈ 0.1 %, BCF ≈ 2 %, FLA ≈ 6 %, SOB ≈ 27 % |
| RQ3 | Does section-level granularity expose what whole-file digests suppress? | `.rdata*` NCD is near-perfect (96.7) for SUB/BCF, degrades under FLA (66.7) via jump tables, collapses under SOB (20.2) via XOR encryption |

---

## Repository layout

```
forensics-project/
├── corpus/                   ← malware source files (NOT committed — see §Corpus)
│   ├── DOS/dos1.cpp
│   ├── Zeus/zeus.cpp
│   ├── data-thief/theif.cpp
│   ├── fill-the-disk/fillTheDisk.cpp
│   ├── ransomware/ransome.cpp
│   └── worm/worm1.cpp
│
├── passes/                   ← LLVM IR pass plugins (see passes/README.md)
│   ├── README.md
│   ├── sub/sub_pass.cpp      ← Pass 1: Instruction Substitution
│   ├── bcf/bcf_pass.cpp      ← Pass 2: Bogus Control Flow
│   ├── fla/fla_pass.cpp      ← Pass 3: Control-Flow Flattening
│   └── sob/sob_pass.cpp      ← Pass 4: String/Constant Obfuscation
│
├── pipeline/                 ← Python analysis scripts
│   ├── compile_matrix.py     ← Step 1: compile corpus × 5 variants → results/bin/
│   ├── analyze_similarity.py ← Step 2: whole-file Jaccard + TLSH + NCD → scores.csv
│   ├── section_analysis.py   ← Step 3: section-level NCD/TLSH/Jaccard → section_scores.csv + fig5–6
│   └── plot_results.py       ← Step 4: whole-file figures → fig1–4
│
├── results/                  ← generated output (NOT committed)
│   ├── bin/<family>/<stem>/  ← baseline.o, sub.o, bcf.o, fla.o, sob.o
│   ├── ir/<family>/<stem>/   ← .ll IR dumps
│   ├── manifest.csv          ← one row per compilation (source, variant, size, status)
│   ├── scores.csv            ← whole-file similarity scores (39 rows)
│   ├── section_scores.csv    ← section-level scores (48 rows)
│   └── figures/              ← PDF + PNG figures (fig1–fig6)
│
├── main.tex                  ← paper source (IEEEtran)
├── references.bib            ← bibliography
└── .gitignore
```

---

## Prerequisites

| Tool | Tested version | Notes |
|------|---------------|-------|
| Clang / LLVM | 22.0.0git | `https://github.com/llvm/llvm-project` |
| Python | 3.9+ | `install python` |
| MinGW | mingw-w64 | `install mingw-w64 or equivlanet` |
| lief | 0.15 | `pip3 install lief` |
| python-tlsh | latest | `pip3 install python-tlsh` |
| matplotlib / seaborn / pandas / numpy | latest | `pip3 install matplotlib seaborn pandas numpy` |

---

## Corpus

The malware source files are **not committed** to this repository. They are
open-source C++ programs representing common malware archetypes (DoS flooder,
banking trojan, data thief, disk filler, ransomware stub, network worm),
obtained from credible security researchers for academic study.

**Usage restriction.** This project uses the corpus strictly for static
analysis — compiling to object files and measuring compiler output. The
compiled object files are never linked, never executed, and never deployed.

To replicate the study you need the same six source files. Place them in the
corpus layout shown above and run `python3 pipeline/compile_matrix.py` to
generate `results/bin/`.

---

## Key results at a glance

### Whole-file Jaccard 4-gram similarity (higher = more similar to baseline)

| Family | SUB | BCF | FLA | SOB |
|--------|-----|-----|-----|-----|
| DOS | 56.9 | 48.8 | 37.7 | 46.5 |
| Zeus | 54.1 | 44.9 | 43.7 | 44.3 |
| DataThief | 78.9 | 59.0 | 58.6 | 32.8 |
| FillDisk | 73.3 | 65.3 | 63.4 | 57.3 |
| Ransom | 73.6 | 61.9 | 63.1 | 35.6 |
| Worm | 73.8 | 61.9 | 65.5 | 47.1 |
| **Avg** | **68.4** | **57.0** | **55.3** | **43.9** |

Cross-sample false-positive floor: avg 24.2, max 31.7.
No obfuscated variant falls below this floor.

### TLSH distance (lower = more similar; threshold 86)

| | SUB | BCF | FLA | SOB |
|---|-----|-----|-----|-----|
| **Avg** | 11 | 23 | 28 | **96** ✗ |

Only SOB crosses the operational threshold of 86
([Oliver et al. 2014](https://doi.org/10.1007/978-3-662-45670-5_15)).

### Section-level NCD similarity (higher = more similar to baseline)

| Section | SUB | BCF | FLA | SOB |
|---------|-----|-----|-----|-----|
| `.text*` | 90.9 | 64.8 | 57.1 | 27.0 |
| `.rdata*` | **96.7** | **96.7** | 66.7 | **20.2** |

`.rdata*` NCD is a near-perfect oracle for distinguishing code-only
obfuscation (SUB/BCF ≈ 97) from string obfuscation (SOB ≈ 20).

---

## Figures

All figures are in `results/figures/`

| File | Description |
|------|-------------|
| `fig1_jaccard_by_pass` | Grouped bar: Jaccard similarity per family × pass |
| `fig2_tlsh_by_pass` | Grouped bar: TLSH distance per family × pass |
| `fig3_overhead_vs_jaccard` | Scatter: size overhead % vs Jaccard similarity |
| `fig4_heatmap_jaccard` | Heatmap: Jaccard (rows = family, cols = pass) |
| `fig5_1_section_heatmap_text` | Heatmap: `.text*` NCD similarity |
| `fig5_2_section_heatmap_rdata` | Heatmap: `.rdata*` NCD similarity |
| `fig6_section_overhead` | Grouped bar: section size overhead per pass |
---

## Metric design notes

**Why not ssdeep?** ssdeep's context-triggered piecewise hashing (CTPH) is
offset-sensitive. COFF symbol tables and relocation entries create many
boundary triggers; any file-size change that shifts the adaptive block size
collapses all chunk boundaries and drives scores to zero — this happened for
more than half the corpus even under the minimal SUB pass. See
[Pagani et al. 2018](https://doi.org/10.1145/3176258.3176306) for a broader
discussion of ssdeep's limitations on binaries.

**Why NCD only at section level?** At whole-file COFF granularity, metadata
(headers, symbol table, relocations) dominates the file. The compressed
concatenation `C(a‖b) ≈ C(a) ≈ C(b)`, making NCD collapse to noise near 0
regardless of actual code change. At section granularity the signal is clean
because each blob contains only code or data bytes.

**Metric summary:**

| Metric | Granularity | Range | Used for |
|--------|------------|-------|---------|
| Jaccard 4-gram | Whole file | 0–100 (100 = identical) | Primary whole-file similarity (RQ1) |
| TLSH distance | Whole file | 0–∞ (0 = identical) | Secondary whole-file; threshold 86 (RQ1/RQ2) |
| NCD (zlib level 9) | Section (`.text*`, `.rdata*`) | 0–100 (100 = identical) | Section-level discrimination (RQ3) |
