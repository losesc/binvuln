import json, os, sys, csv, collections, glob

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(ROOT, "results")
COND_ORDER = ["source", "O0/kept", "O0/stripped", "O3/kept", "O3/stripped"]

def load(path):
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows

def cwe_norm(x):
    if not x:
        return None
    return x.upper().replace(" ", "").replace("CWE-", "CWE-")

def metrics_for(rows):
    tp = fp = tn = fn = 0
    cwe_right = cwe_total = 0
    halluc = 0; good_n = 0
    errors = 0
    for r in rows:
        if r.get("error") or r.get("pred_vuln") is None:
            errors += 1
            continue
        pred = bool(r["pred_vuln"]); true = bool(r["true_vuln"])
        if true and pred: tp += 1
        elif true and not pred: fn += 1
        elif not true and pred: fp += 1
        else: tn += 1
        if true and pred:  
            cwe_total += 1
            if cwe_norm(r.get("pred_cwe")) == cwe_norm(r.get("true_cwe")):
                cwe_right += 1
        if not true:  
            good_n += 1
            if pred: halluc += 1
    acc = (tp + tn) / max(1, tp + tn + fp + fn)
    prec = tp / max(1, tp + fp)
    rec = tp / max(1, tp + fn)
    f1 = 2 * prec * rec / max(1e-9, prec + rec)
    return {
        "n": len(rows), "errors": errors,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "accuracy": round(acc, 3), "precision": round(prec, 3),
        "recall": round(rec, 3), "f1": round(f1, 3),
        "cwe_match": round(cwe_right / max(1, cwe_total), 3), "cwe_match_n": cwe_total,
        "hallucination": round(halluc / max(1, good_n), 3), "good_n": good_n,
    }

def main():
    files = sys.argv[1:] or sorted(glob.glob(os.path.join(RESULTS, "runs_*.jsonl")))
    if not files:
        print("no runs_*.jsonl found in results/", file=sys.stderr); sys.exit(1)
    rows = []
    for f in files:
        rows += load(f)
    by_cond = collections.defaultdict(list)
    for r in rows:
        by_cond[r["condition"]].append(r)

    per = {c: metrics_for(by_cond[c]) for c in by_cond}

    # write CSV
    os.makedirs(RESULTS, exist_ok=True)
    csv_path = os.path.join(RESULTS, "metrics_by_condition.csv")
    cols = ["condition", "n", "accuracy", "precision", "recall", "f1",
            "cwe_match", "hallucination", "tp", "fp", "tn", "fn", "errors"]
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for c in COND_ORDER:
            if c in per:
                w.writerow({"condition": c, **{k: per[c][k] for k in cols if k != "condition"}})

    def g(c, k):
        return per[c][k] if c in per else float("nan")

    # factor isolation 
    summary = {
        "per_condition": {c: per[c] for c in COND_ORDER if c in per},
        "factor_effects": {},
        "files": files,
    }
    if all(c in per for c in ["O0/kept", "O3/kept", "O0/stripped", "O3/stripped"]):
        summary["factor_effects"] = {
            "optimization_effect_f1_symbols_kept": round(g("O0/kept", "f1") - g("O3/kept", "f1"), 3),
            "optimization_effect_f1_stripped": round(g("O0/stripped", "f1") - g("O3/stripped", "f1"), 3),
            "stripping_effect_f1_O0": round(g("O0/kept", "f1") - g("O0/stripped", "f1"), 3),
            "stripping_effect_f1_O3": round(g("O3/kept", "f1") - g("O3/stripped", "f1"), 3),
            "combined_effect_f1": round(g("O0/kept", "f1") - g("O3/stripped", "f1"), 3),
            "cwe_match_O0kept": g("O0/kept", "cwe_match"),
            "cwe_match_O3stripped": g("O3/stripped", "cwe_match"),
        }
    with open(os.path.join(RESULTS, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    # human table
    print(f"{'condition':14s} {'n':>3} {'acc':>5} {'prec':>5} {'rec':>5} {'F1':>5} {'cweM':>5} {'halluc':>6} {'err':>3}")
    for c in COND_ORDER:
        if c in per:
            m = per[c]
            print(f"{c:14s} {m['n']:>3} {m['accuracy']:>5} {m['precision']:>5} "
                  f"{m['recall']:>5} {m['f1']:>5} {m['cwe_match']:>5} {m['hallucination']:>6} {m['errors']:>3}")
    fe = summary.get("factor_effects")
    if fe:
        print("\nFactor isolation (F1 drop, positive = performance got worse):")
        print(f"  optimization  (O0->O3, symbols kept):     {fe['optimization_effect_f1_symbols_kept']:+.3f}")
        print(f"  optimization  (O0->O3, stripped):         {fe['optimization_effect_f1_stripped']:+.3f}")
        print(f"  stripping     (kept->stripped, at O0):    {fe['stripping_effect_f1_O0']:+.3f}")
        print(f"  stripping     (kept->stripped, at O3):    {fe['stripping_effect_f1_O3']:+.3f}")
        print(f"  combined      (O0/kept -> O3/stripped):   {fe['combined_effect_f1']:+.3f}")
    print(f"\nWrote {csv_path}")
    print(f"Wrote {os.path.join(RESULTS,'summary.json')}")

if __name__ == "__main__":
    main()
