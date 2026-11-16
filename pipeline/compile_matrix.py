#!/usr/bin/env python3
"""compile_matrix.py -- step 5 of the forensics-project pipeline.

Compiles every source file found under the corpus once as an unobfuscated BASELINE object
file, and once per obfuscation pass (sub, bcf, fla, sob), recording every attempt in a CSV
manifest. This script only ever COMPILES. It never links a runnable executable and never
executes anything it produces -- everything it writes is a relocatable object file (.o),
which is not something you can accidentally run.

Why object files instead of linked executables: a corpus sample might be one file out of a
larger project, with calls to functions this script never sees. Compiling to .o never needs
those symbols resolved (that is a LINK-time concern; generating an object file never invokes
the linker), so every source file compiles independently, correctly, with no bookkeeping about
which files belong to the same program. It also means the digest comparison in the next step
(step 6) is of just THIS translation unit's own compiled code, not diluted by whatever
identical libc/runtime startup code a full executable would also contain.

Usage (from anywhere; paths default to the project layout this script lives in):
    python3 compile_matrix.py
    python3 compile_matrix.py --corpus ../corpus --out ../results --only zeus
    python3 compile_matrix.py --passes sub,sob   # skip bcf/fla for a quick run
    python3 compile_matrix.py --target native    # skip Windows cross-compilation entirely

Requires clang/clang++/opt/llvm-config on PATH, from the same LLVM build the passes were
built against (see ../../LLVM_SETUP.md). Each pass plugin is rebuilt automatically if its
.dylib is missing or older than its .cpp source.

Target: this corpus is Windows-flavored C++ (windows.h, Win32 API calls), so the default
target is x86_64-w64-mingw32 -- a cross-compile, using headers from `brew install mingw-w64`,
not an emulator or a real Windows machine. Since this pipeline never links or runs anything
(see above), we only ever need the HEADERS to make these files parse, never the import
libraries that would be needed to resolve calls like CreateFileA at link time. Pass
`--target native` for a future portable (POSIX-compilable) sample.
"""

import argparse
import csv
import shutil
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent

SOURCE_EXTENSIONS = {".c", ".cpp", ".cc", ".cxx"}
CXX_EXTENSIONS = {".cpp", ".cc", ".cxx"}  # these need clang++, not clang

# short code (folder name, CLI value, manifest "variant") -> (cpp source, built plugin),
# both relative to PROJECT_ROOT
PASSES = {
    "sub": (Path("passes/sub/sub_pass.cpp"), Path("passes/sub/sub_pass.dylib")),
    "bcf": (Path("passes/bcf/bcf_pass.cpp"), Path("passes/bcf/bcf_pass.dylib")),
    "fla": (Path("passes/fla/fla_pass.cpp"), Path("passes/fla/fla_pass.dylib")),
    "sob": (Path("passes/sob/sob_pass.cpp"), Path("passes/sob/sob_pass.dylib")),
}

# short code -> the name the pass actually registers with registerPipelineParsingCallback
# (what belongs after -passes=). Only sub_pass.cpp's registered name ("subst") differs from
# its short code; kept as an explicit table rather than assuming they always match.
PASS_PIPELINE_NAME = {"sub": "subst", "bcf": "bcf", "fla": "fla", "sob": "sob"}

COMPILE_TIMEOUT_SEC = 60
DEFAULT_TARGET = "x86_64-w64-mingw32"

# Headers some corpus samples call without including -- MinGW's windows.h, unlike some MSVC
# configurations, does not pull these in for you. Force-included (in this order -- windows.h
# MUST come first, since psapi.h itself assumes windows.h's types like WINBOOL already exist)
# so we never have to touch the sample's own source to fix a missing #include. Extend this
# list if another sample needs a different header; it costs nothing for samples that do not.
FORCE_INCLUDES_FOR_MINGW = ["windows.h", "psapi.h"]


def error_summary(log):
    """The one line worth putting in the manifest. clang's own last line is often just a
    count ("1 error generated."), not the actual diagnostic -- prefer the last line that
    looks like a real error or LLVM abort message, and fall back to the literal last line
    (or the fatal signal/abort line for a process that crashed outright) if nothing matches."""
    lines = log.strip().splitlines()
    if not lines:
        return ""
    for line in reversed(lines):
        if "error:" in line.lower() or "LLVM ERROR" in line:
            return line.strip()
    return lines[-1].strip()


def run(cmd, timeout=COMPILE_TIMEOUT_SEC):
    """Runs one subprocess, never raising: returns (ok, stdout+stderr combined)."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        ok = result.returncode == 0
        return ok, (result.stdout + result.stderr)
    except subprocess.TimeoutExpired:
        return False, f"timed out after {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError as e:
        return False, f"tool not found: {e}"


def target_flags(target):
    """-target is needed whenever compiling for this target, whether from source or from
    already-expanded .ll (an .ll's own embedded `target triple` would cover that case too,
    but passing it explicitly here as well costs nothing and does not rely on that)."""
    return ["-target", target] if target and target != "native" else []


_mingw_header_flags_cache = {}


def mingw_header_flags(target):
    """Extra -isystem/-include flags needed only when compiling REAL C/C++ source (not .ll)
    for a mingw target: windows.h, the MinGW-bundled libstdc++ headers, and the force-included
    headers in FORCE_INCLUDES_FOR_MINGW. Not needed when compiling .ll -- there are no more
    #include directives left to resolve by then."""
    if not target or target == "native" or "mingw32" not in target:
        return []
    if target in _mingw_header_flags_cache:
        return _mingw_header_flags_cache[target]

    ok, prefix = run(["brew", "--prefix", "mingw-w64"])
    if not ok:
        sys.exit("error: mingw-w64 not found via `brew --prefix mingw-w64` -- "
                  "run: brew install mingw-w64 (or pass --target native)")
    arch = target.split("-")[0]  # x86_64-w64-mingw32 -> x86_64
    sysroot = Path(prefix.strip()) / f"toolchain-{arch}" / target

    flags = []
    cxx_inc = sysroot / "include" / "c++"
    for version_dir in sorted(cxx_inc.glob("*")):
        flags += ["-isystem", str(version_dir), "-isystem", str(version_dir / target)]
    flags += ["-isystem", str(sysroot / "include")]
    for header in FORCE_INCLUDES_FOR_MINGW:
        flags += ["-include", header]

    _mingw_header_flags_cache[target] = flags
    return flags


def check_toolchain():
    for tool in ("clang", "clang++", "opt", "llvm-config"):
        if shutil.which(tool) is None:
            sys.exit(f"error: '{tool}' not found on PATH -- see ../../LLVM_SETUP.md, then "
                      f"add llvm-project/build/bin to PATH before running this script.")
    ok, out = run(["llvm-config", "--version"])
    print(f"Using LLVM {out.strip()} ({shutil.which('clang')})")


def ensure_pass_built(name):
    """Builds passes/<name>/<name>_pass.dylib if missing or older than its .cpp source."""
    cpp_rel, dylib_rel = PASSES[name]
    cpp_path = PROJECT_ROOT / cpp_rel
    dylib_path = PROJECT_ROOT / dylib_rel

    if dylib_path.exists() and dylib_path.stat().st_mtime >= cpp_path.stat().st_mtime:
        return True, None

    ok, out = run(["llvm-config", "--cxxflags"])
    if not ok:
        return False, f"llvm-config --cxxflags failed: {out}"
    cxxflags = out.split()

    cmd = ["clang++", *cxxflags, "-fPIC", "-shared", "-undefined", "dynamic_lookup",
           str(cpp_path), "-o", str(dylib_path)]
    ok, out = run(cmd, timeout=120)
    if ok:
        print(f"  built {dylib_rel}")
    return ok, (None if ok else out)


def find_sources(corpus_dir):
    return sorted(p for p in corpus_dir.rglob("*") if p.suffix in SOURCE_EXTENSIONS)


def compiler_for(src):
    return "clang++" if src.suffix in CXX_EXTENSIONS else "clang"


def compile_baseline(src, out_obj, target):
    out_obj.parent.mkdir(parents=True, exist_ok=True)
    cmd = [compiler_for(src), *target_flags(target), *mingw_header_flags(target),
           "-c", str(src), "-o", str(out_obj)]
    ok, log = run(cmd)
    return ok, log


def emit_ir(src, out_ll, target):
    """clang -S -emit-llvm, with the flags every pass in this project assumes (see
    sub_pass.cpp's QUICK NOTES): -disable-O0-optnone so function passes are not silently
    skipped, -fno-discard-value-names so the IR stays readable if you open out_ll yourself."""
    out_ll.parent.mkdir(parents=True, exist_ok=True)
    cmd = [compiler_for(src), *target_flags(target), *mingw_header_flags(target),
           "-S", "-emit-llvm", "-O0", "-Xclang", "-disable-O0-optnone",
           "-fno-discard-value-names", str(src), "-o", str(out_ll)]
    ok, log = run(cmd)
    return ok, log


def run_pass(pass_name, in_ll, out_ll):
    dylib = PROJECT_ROOT / PASSES[pass_name][1]
    pipeline_name = PASS_PIPELINE_NAME[pass_name]
    cmd = ["opt", f"-load-pass-plugin={dylib}", f"-passes={pipeline_name}", "-verify-each",
           "-S", str(in_ll), "-o", str(out_ll)]
    ok, log = run(cmd)
    return ok, log


def compile_ll_to_obj(ll_path, out_obj, target):
    out_obj.parent.mkdir(parents=True, exist_ok=True)
    # No mingw_header_flags here: a .ll file has no #include directives left to resolve, only
    # -target matters (the .ll also carries its own `target triple` line from emit_ir, but
    # passing it again here too is harmless and does not rely on that alone).
    cmd = ["clang", *target_flags(target), "-c", str(ll_path), "-o", str(out_obj)]
    ok, log = run(cmd)
    return ok, log


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--corpus", type=Path, default=PROJECT_ROOT / "corpus")
    ap.add_argument("--out", type=Path, default=PROJECT_ROOT / "results")
    ap.add_argument("--passes", default=",".join(PASSES), help="comma-separated subset, e.g. sub,sob")
    ap.add_argument("--only", default=None, help="only sources whose path contains this substring")
    ap.add_argument("--target", default=DEFAULT_TARGET,
                     help=f"compiler target triple, or 'native' to skip cross-compilation (default: {DEFAULT_TARGET})")
    args = ap.parse_args()

    wanted_passes = [p.strip() for p in args.passes.split(",") if p.strip()]
    for p in wanted_passes:
        if p not in PASSES:
            sys.exit(f"error: unknown pass '{p}' (known: {', '.join(PASSES)})")

    check_toolchain()

    print("Building pass plugins...")
    for name in wanted_passes:
        ok, err = ensure_pass_built(name)
        if not ok:
            sys.exit(f"error: failed to build pass '{name}':\n{err}")

    sources = find_sources(args.corpus)
    if args.only:
        sources = [s for s in sources if args.only in str(s)]
    if not sources:
        sys.exit(f"no {sorted(SOURCE_EXTENSIONS)} files found under {args.corpus}")
    print(f"Found {len(sources)} source file(s) under {args.corpus}")
    print(f"Target: {args.target}")

    rows = []
    bin_dir = args.out / "bin"
    ir_dir = args.out / "ir"

    for src in sources:
        key = src.relative_to(args.corpus).with_suffix("")  # e.g. Zeus/zeus
        print(f"\n[{key}]")

        # Baseline: straight to an object file, no IR step, no passes involved.
        baseline_obj = bin_dir / key / "baseline.o"
        ok, log = compile_baseline(src, baseline_obj, args.target)
        size = baseline_obj.stat().st_size if ok else None
        rows.append({"source": str(src), "variant": "baseline", "status": "ok" if ok else "compile_failed",
                     "output_path": str(baseline_obj) if ok else "", "size_bytes": size or "",
                     "error": "" if ok else error_summary(log)})
        print(f"  baseline: {'ok, ' + str(size) + ' bytes' if ok else 'COMPILE FAILED'}")
        if not ok:
            print(f"    {log.strip()[:300]}")
            continue  # no point trying obfuscated variants if the plain source does not even compile

        # One shared pre-pass IR dump, reused for every requested pass.
        pre_ll = ir_dir / key / "pre.ll"
        ok, log = emit_ir(src, pre_ll, args.target)
        if not ok:
            for pass_name in wanted_passes:
                rows.append({"source": str(src), "variant": pass_name, "status": "ir_failed",
                             "output_path": "", "size_bytes": "", "error": error_summary(log)})
            print(f"  emit-llvm FAILED (skipping all passes for this file): {log.strip()[:300]}")
            continue

        for pass_name in wanted_passes:
            post_ll = ir_dir / key / f"{pass_name}.ll"
            ok, log = run_pass(pass_name, pre_ll, post_ll)
            if not ok:
                rows.append({"source": str(src), "variant": pass_name, "status": "pass_failed",
                             "output_path": "", "size_bytes": "", "error": error_summary(log)})
                print(f"  {pass_name}: PASS FAILED: {log.strip()[:300]}")
                continue

            obj_path = bin_dir / key / f"{pass_name}.o"
            ok, log = compile_ll_to_obj(post_ll, obj_path, args.target)
            size = obj_path.stat().st_size if ok else None
            rows.append({"source": str(src), "variant": pass_name, "status": "ok" if ok else "compile_failed",
                         "output_path": str(obj_path) if ok else "", "size_bytes": size or "",
                         "error": "" if ok else error_summary(log)})
            print(f"  {pass_name}: {'ok, ' + str(size) + ' bytes' if ok else 'COMPILE FAILED'}")

    manifest_path = args.out / "manifest.csv"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    with manifest_path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["source", "variant", "status", "output_path", "size_bytes", "error"])
        writer.writeheader()
        writer.writerows(rows)

    ok_count = sum(1 for r in rows if r["status"] == "ok")
    print(f"\n{ok_count}/{len(rows)} compilations succeeded. Manifest written to {manifest_path}")


if __name__ == "__main__":
    main()
