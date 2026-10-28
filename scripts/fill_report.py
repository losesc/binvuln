#!/usr/bin/env python3
import json, os, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUMMARY = os.path.join(ROOT, "results", "summary.json")
TEX = os.path.join(ROOT, "report", "milestone.tex")
OUT = os.path.join(ROOT, "report", "milestone_filled.tex")
COND = ["source", "O0/kept", "O0/stripped", "O3/kept", "O3/stripped"]

def main():
    s = json.load(open(SUMMARY))
    per = s["per_condition"]
    tex = open(TEX).read()

    def cells(c):
        m = per[c]
        return [f"{m[k]:.3f}" for k in ("accuracy", "precision", "recall", "f1", "cwe_match", "hallucination")]
    rows = {"source": "source", "O0/kept": "O0 / kept", "O0/stripped": "O0 / stripped",
            "O3/kept": "O3 / kept", "O3/stripped": "O3 / stripped"}
    for ckey, label in rows.items():
        if ckey not in per:
            continue
        vals = cells(ckey)
        pat = re.compile(r"(" + re.escape(label) + r"\s*&)" + r"(\s*\\placeholder\{\}\s*&){5}\s*\\placeholder\{\}\s*\\\\")
        repl = label + " & " + " & ".join(vals) + r" \\"
        tex = pat.sub(lambda _m: repl, tex)

    if "source" in per:
        m = per["source"]
        tex = tex.replace(
            r"\placeholder{model} source & \placeholder{acc} & \placeholder{prec} & \placeholder{rec} & \placeholder{f1}",
            f"this model, source & {m['accuracy']:.3f} & {m['precision']:.3f} & {m['recall']:.3f} & {m['f1']:.3f}")

    open(OUT, "w").write(tex)
    remaining = tex.count(r"\placeholder")
    print(f"Wrote {OUT}")
    print(f"Remaining placeholders (model name / repo link, fill by hand): {remaining}")

if __name__ == "__main__":
    main()
