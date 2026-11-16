# passes/

Four LLVM IR obfuscation passes used in the paper
*"When the Compiler Is the Adversary: Evaluating Forensic Similarity Digests Against LLVM Obfuscation Passes"* (CSCE 712, Texas A&M, Fall 2026).

Each pass is a self-contained LLVM plugin: one `.cpp` file, built into a shared library with `clang++`, and loaded at transform time by `opt -load-pass-plugin`. No CMake or external build system is needed.

---

## Directory layout

```
passes/
├── README.md          ← this file
├── sub/               ← Pass 1: Instruction Substitution (SUB)
│   ├── sub_pass.cpp
│   ├── sub_pass.dylib   (compiled output, not committed)
│   ├── sub_test.c       (self-contained smoke-test program)
│   ├── sub_test.ll      (baseline IR)
│   └── sub_test_out.ll  (IR after the pass)
├── bcf/               ← Pass 2: Bogus Control Flow (BCF)
│   └── ...
├── fla/               ← Pass 3: Control-Flow Flattening (FLA)
│   └── ...
└── sob/               ← Pass 4: String/Constant Obfuscation (SOB)
    └── ...
```

---

## Quick reference

| Pass | Folder | `opt` name | Collberg class | What it changes |
|------|--------|-----------|---------------|-----------------|
| SUB | `sub/` | `subst` | Instruction layout | Rewrites arithmetic/logic instructions; CFG unchanged |
| BCF | `bcf/` | `bcf` | Control | Adds dead blocks guarded by an opaque predicate; `.rdata` unchanged |
| FLA | `fla/` | `fla` | Control | Replaces all CFG edges with a state-variable dispatcher; inflates `.rdata` with jump tables |
| SOB | `sob/` | `sob` | Data | XOR-encrypts string literals; inserts inline decode loops; empties `.rdata` of plaintext strings |

---

## Building and running a pass

Each pass follows the same three-step pattern. Run from inside the pass's own folder (e.g. `passes/sub/`).

**1. Build the plugin:**
```bash
clang++ `llvm-config --cxxflags` -fPIC -shared -undefined dynamic_lookup <pass>_pass.cpp -o <pass>_pass.dylib
```

**2. Emit baseline IR from the test program:**
```bash
clang -S -emit-llvm -O0 -Xclang -disable-O0-optnone -fno-discard-value-names <pass>_test.c -o <pass>_test.ll
```

**3. Run the pass:**
```bash
opt -load-pass-plugin=./<pass>_pass.dylib -passes=<opt-name> -S <pass>_test.ll -o <pass>_test_out.ll
```

**4. Compile the obfuscated IR to an object file:**
```bash
clang -c <pass>_test_out.ll -o <pass>_test_out.o
```

For the COFF cross-compilation target used in the paper's pipeline:
```bash
clang --target=x86_64-w64-mingw32 -c <pass>_test_out.ll -o <pass>_test_out.o
```

Substituting the pass-specific values:

| Pass | `<pass>` | `<opt-name>` |
|------|---------|-------------|
| SUB | `sub` | `subst` |
| BCF | `bcf` | `bcf` |
| FLA | `fla` | `fla` |
| SOB | `sob` | `sob` |

> **Note (macOS):** `-undefined dynamic_lookup` tells the linker to defer LLVM symbol resolution to load time. On Linux, replace it with `-Wl,--allow-shlib-undefined`.

---

## Pass 1 — Instruction Substitution (`sub/`)

**What it does.** Replaces every arithmetic or logical integer instruction with a longer sequence that computes the exact same value. Each rule turns one instruction into two to four. The control-flow graph and all data constants are left completely untouched — only the instructions inside each block change.

| Original | Replacement | Identity |
|----------|-------------|---------|
| `a + b` | `a - (0 - b)` | negation |
| `a - b` | `a + (0 - b)` | negation |
| `a ^ b` | `(a \| b) - (a & b)` | set algebra |
| `a & b` | `~(~a \| ~b)` | De Morgan |
| `a \| b` | `~(~a & ~b)` | De Morgan |

**Why it matters for forensics.** The binary grows by only ~0.1% on average, so the attacker pays almost nothing. The code bytes change enough to shift 4-gram patterns, but the overall structure is preserved — which is why section-level NCD still scores high (90.9 average) even though whole-file Jaccard drops to 68.4.

**Forensic effect.** Size overhead ~0.1%. Jaccard 4-gram similarity: avg 68.4. TLSH distance: avg 11 (well below the match threshold of 86). Code-section NCD: avg 90.9.

---

## Pass 2 — Bogus Control Flow (`bcf/`)

**What it does.** Adds a fake branch after each eligible basic block. The branch condition is based on the fact that `x * (x + 1)` is always even — so the low bit is always 0, making the condition always true and the "bogus" path never actually taken at runtime. A static analyser reading the binary sees a more complex control-flow graph with extra blocks, but the program behaves identically.

```
BEFORE                          AFTER

BB:                             BB:
  ...code...                      ...code...
  br label %Succ                  %prod = mul i32 %x, (add %x, 1)  ; always even
                                  %bit  = and i32 %prod, 1          ; always 0
                                  %cond = icmp eq i32 %bit, 0       ; always true
                                  br i1 %cond, %Succ, %BB.bogus

                                BB.bogus:            ; dead — never reached
                                  %junk = add i32 %x, 1
                                  br label %Succ
```

**Why it matters for forensics.** The extra dead blocks bulk up the code section and shift byte patterns. Read-only data (`.rdata`) is untouched because BCF never introduces new constants.

**Forensic effect.** Size overhead ~2%. Jaccard 4-gram similarity: avg 57.0. TLSH distance: avg 23. Code-section NCD: avg 64.8. `.rdata` NCD: avg 96.7 (unchanged from baseline).

---

## Pass 3 — Control-Flow Flattening (`fla/`)

**What it does.** Completely hides a function's original structure. All basic blocks are removed from their natural positions and placed under a single "dispatcher" block. A state variable decides which block runs next, so the control flow at runtime is the same as before — but the CFG visible in the binary looks like one hub connected to every block, with no if/else or loop shape visible at all.

As a side effect, the state-transition table (which block comes after which) is stored as a constant array in `.rdata`, so the read-only data section grows too.

**Before — natural control flow:**

```llvm
entry:
  %cond = icmp sgt i32 %x, 0
  br i1 %cond, label %if.then, label %if.else

if.then:
  ...
  br label %if.end

if.else:
  ...
  br label %if.end

if.end:
  ret i32 %result
```

**After — all edges replaced by a central dispatcher:**

```llvm
fla.entry:
  store i32 1, i32* %state          ; 1 = block ID for "entry"
  br label %fla.dispatch

fla.dispatch:                       ; every block jumps back here
  %s = load i32, i32* %state
  switch i32 %s, label %fla.entry [
    i32 1, label %entry
    i32 2, label %if.then
    i32 3, label %if.else
    i32 4, label %if.end
  ]

entry:
  %cond = icmp sgt i32 %x, 0
  %next = select i1 %cond, i32 2, i32 3
  store i32 %next, i32* %state      ; pick next block ID
  br label %fla.dispatch

if.then:
  ...
  store i32 4, i32* %state
  br label %fla.dispatch

if.else:
  ...
  store i32 4, i32* %state
  br label %fla.dispatch

if.end:
  ret i32 %result
```

The block ID constants (1–4) and the `switch` jump table are emitted as a constant array in `.rdata` — this is what causes `.rdata*` NCD to degrade under FLA even though no string literals are added.

**Why it matters for forensics.** FLA is the most structurally invasive pass. Code bytes are rearranged significantly, and `.rdata` picks up new content (jump tables) that wasn't there before — which is exactly why section-level NCD on `.rdata` drops to ~67 for FLA, distinguishing it from the code-only passes SUB and BCF.

**Forensic effect.** Size overhead ~6%. Jaccard 4-gram similarity: avg 55.3. TLSH distance: avg 28. Code-section NCD: avg 57.1. `.rdata` NCD: avg 66.7 (degraded by jump-table injection).

---

## Pass 4 — String/Constant Obfuscation (`sob/`)

**What it does.** Targets the data section rather than the code. Every string literal in the program (C2 domains, API names, mutex names, file paths — whatever a real malware sample would carry) is XOR-encrypted with a random key before the binary is written, so the plaintext never appears in `.rdata`. Wherever the string is used, a small inline decoder is inserted into the code that reconstructs the original bytes on the stack at runtime, right before they are needed.

The key is stored as a mutable (non-constant) global so the compiler cannot fold the XOR back at compile time and undo the encryption.

**`.rdata` section — before and after:**

| String | Baseline (`.rdata`) | After SOB (`.rdata`) |
|--------|--------------------|--------------------|
| `"kernel32.dll\0"` | readable plaintext | `\x61\x06\x09\x00\x0e\x11\x1d\x1f\x08\x1b\x1b\x00` (ciphertext) |
| `"C2-server.example.com\0"` | readable plaintext | `\x41\x72\x2b\x64\x1a\x09...` (ciphertext) |
| (all string literals) | strings visible in `strings` | no recognisable strings |

**`.text` section — decode loop inserted at every call site:**

```llvm
; BEFORE — single pointer load and call
%ptr = getelementptr [14 x i8], [14 x i8]* @str, i32 0, i32 0
call void @LoadLibraryA(i8* %ptr)

; AFTER — per-byte XOR decode into a stack buffer, then call
%key = load i8, i8* @xor_key         ; runtime key (never a compile-time constant)
%buf = alloca [14 x i8]
%e0  = load i8, [14 x i8]* @str_enc, 0  ; load encrypted byte
%b0  = xor i8 %e0, %key                 ; decrypt
store i8 %b0, [14 x i8]* %buf, 0
; ... one xor + store per byte (14 total) ...
%ptr = getelementptr [14 x i8], [14 x i8]* %buf, i32 0, i32 0
call void @LoadLibraryA(i8* %ptr)
```

Every string use gets its own copy of this decode sequence — this is what inflates the code section and pushes TLSH distance above the threshold of 86.

**Why it matters for forensics.** This is the only pass in the study that empties `.rdata` of recognisable content. The code section also grows significantly because every string use gets its own decode sequence. This makes SOB the only pass that pushes TLSH distance above the standard match threshold of 86 — and `.rdata` NCD collapsing to near zero is the clearest indicator that this class of obfuscation was applied.

**Forensic effect.** Size overhead ~27% on average (up to 41% for string-heavy samples). Jaccard 4-gram similarity: avg 43.9. TLSH distance: avg 95.7 — **the only pass that exceeds the match threshold of 86**. Code-section NCD: avg 27.0. `.rdata` NCD: avg 20.2 (collapsed from 96.7 for SUB/BCF).
