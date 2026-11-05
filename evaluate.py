#!/usr/bin/env python3
"""
Combine all saved runs in results/*.json into ONE overall confusion matrix.
Usage:  python evaluate.py
"""
import glob
import json

from rich.console import Console
from rich.table import Table

from scanner.metrics import confusion, scores

console = Console()


def main():
    files = sorted(f for f in glob.glob("results/*.json") if not f.endswith("summary.json"))
    all_rows = []
    runs = Table(title="Per-run results")
    for col in ["Run", "Endpoints", "Ours: TP/FP/FN/TN", "Naive: TP/FP/FN/TN"]:
        runs.add_column(col)
    for f in files:
        data = json.load(open(f))
        rows = [r for r in data["rows"] if r.get("truth")]
        if not rows:
            continue
        all_rows += rows
        o = confusion(rows, "verdict")
        n = confusion(rows, "naive")
        runs.add_row(data.get("labels") or data["target"], str(len(rows)),
                     "/".join(map(str, o)), "/".join(map(str, n)))
    console.print(runs)

    t = Table(title="OVERALL (all runs combined)")
    for col in ["Detector", "TP", "FP", "FN", "TN", "Precision", "Recall", "Accuracy", "FP rate"]:
        t.add_column(col)
    summary = {}
    for label, key in [("Naive (status code only)", "naive"), ("Ours (response + state checks)", "verdict")]:
        s = scores(*confusion(all_rows, key))
        summary[key] = s
        t.add_row(label, *[str(s[k]) for k in ["TP", "FP", "FN", "TN", "precision", "recall", "accuracy", "false_positive_rate"]])
    console.print(t)
    json.dump(summary, open("results/summary.json", "w"), indent=2)
    console.print("Saved: results/summary.json")


if __name__ == "__main__":
    main()
