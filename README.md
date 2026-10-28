# Limitations of Automated Binary Vulnerability Analysis

Milestone pipeline: reproduce Khare et al.'s source-level LLM vulnerability
detection on Juliet C/C++, then measure how far it degrades on decompiled
binaries, isolating compiler optimization from symbol stripping.

## Layout
```
targets/       Juliet-derived jNNNN.c (bad+good variants) + labels.csv
               (juliet_manifest.csv maps each back to its Juliet file;
                hand-written t01-t08 kept in targets/handwritten/)
scripts/       compile / verify / decompile / run / score / fill_report
build/         compiled binaries + build_matrix.csv (generated)
decompiled/    model-input text per binary + source/ corpus (generated)
results/       JSONL runs, metrics_by_condition.csv, summary.json (generated)
report/        milestone.tex -> milestone.pdf
```

## Run order (on your machine, with Ollama + the GPU)

```bash
# 0. one-time: pull the model (paper's best Juliet C/C++ model was Qwen-2.5-14B)
ollama pull qwen2.5-coder:14b

# 0b. fetch Juliet C/C++ v1.3 from NIST and generate targets/ (cached in build/juliet_cache)
bash scripts/fetch_juliet.sh --limit 18   # balanced: 6 per class; omit --limit for all 223

# 1. build the 2x2 matrix (needs gcc)
bash scripts/compile.sh

# 2. verify: stripped==kept code, and every bug survives compilation
bash scripts/verify_builds.sh

# 3. decompile. With Ghidra (preferred):
GHIDRA_HOME=/opt/ghidra_11.x bash scripts/decompile.sh
#    or without Ghidra (objdump fallback, works out of the box):
bash scripts/decompile.sh

# 4. run the model (CWE-specific prompt, temp 0)
python3 scripts/run_pipeline.py --model qwen2.5-coder:14b --prompt cwe
#    sanity-test the plumbing with no GPU:
python3 scripts/run_pipeline.py --model qwen2.5-coder:14b --prompt cwe --dry-run

# 5. score
python3 scripts/score.py

# 6. drop numbers into the report, then compile
python3 scripts/fill_report.py
cd report && pdflatex milestone_filled.tex && pdflatex milestone_filled.tex
```

## Notes
- Stripping is applied to a *copy* of each compiled binary, so kept/stripped
  pairs share identical `.text`; symbols are the only difference.
- `-U_FORTIFY_SOURCE -fno-stack-protector` keep `-O3` from changing the bug
  (no `__strcpy_chk`, no canaries).
- `verify_builds.sh` flags any target whose bug it cannot trigger at `-O0`/`-O3`
  (class read from `labels.csv`; payload sent on argv and stdin).
- The report's baseline table holds the real published Khare et al. numbers;
  red `[placeholders]` are your results, filled by `fill_report.py`.
- For exact-format submission, swap `neuripslike.sty` for the official
  `neurips_2024.sty` and change `\usepackage{neuripslike}` to `\usepackage{neurips_2024}`.
