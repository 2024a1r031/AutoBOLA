#!/usr/bin/env python3
"""
BOLA scanner - command line entry point.

Example:
    python scan.py --config configs/own_api.yaml --base-url http://127.0.0.1:8000 --labels own-api/vulnerable
"""
import argparse
import json
import os
from urllib.parse import urlparse

import yaml
from rich.console import Console
from rich.table import Table
from rich.text import Text

from scanner.client import Target
from scanner.detector import Detector
from scanner.metrics import confusion, scores
from scanner.spec_parser import load_spec, list_operations

console = Console()
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", "host.docker.internal"}


def main():
    ap = argparse.ArgumentParser(description="Automated BOLA/IDOR scanner (prototype)")
    ap.add_argument("--config", required=True, help="target config yaml")
    ap.add_argument("--base-url", help="override base_url from the config")
    ap.add_argument("--labels", help="key in labels.yaml, e.g. own-api/vulnerable (enables evaluation)")
    ap.add_argument("--labels-file", default="labels.yaml")
    ap.add_argument("--out", help="where to save JSON results (default: results/<labels>.json)")
    ap.add_argument("--i-have-permission", action="store_true",
                    help="required to scan anything that is not localhost")
    args = ap.parse_args()

    with open(args.config) as f:
        cfg = yaml.safe_load(f)
    base = (args.base_url or cfg["base_url"]).rstrip("/")

    # ETHICS GUARD: only local targets unless the operator explicitly confirms permission
    host = urlparse(base).hostname
    if host not in LOCAL_HOSTS and not args.i_have_permission:
        console.print(f"[red]Refusing to scan {host}: not a local target.[/red] "
                      "Only scan systems you own or have written permission to test "
                      "(then add --i-have-permission).")
        raise SystemExit(2)

    console.rule(f"[bold]Scanning {cfg['name']} at {base}")
    spec_src = cfg["spec"]
    spec_src = base + spec_src if spec_src.startswith("/") else spec_src
    ops = list_operations(load_spec(spec_src))
    console.print(f"Step 1: read API spec -> found [bold]{len(ops)}[/bold] object-level operations")

    target = Target(cfg, base)
    target.run_setup()
    console.print("Step 2-3: creating victim/attacker users and running tests...\n")
    results, uncovered = Detector(target, ops, cfg).run()

    truth = {}
    if args.labels:
        with open(args.labels_file) as f:
            truth = yaml.safe_load(f)[args.labels]

    rows = []
    for r in results:
        rows.append({
            "resource": r.resource, "endpoint": r.key, "skipped": r.skipped,
            "verdict": r.vulnerable, "naive": r.naive, "status": r.status,
            "truth": truth.get(r.key), "evidence": r.evidence,
        })

    show_findings(rows, bool(truth))
    if uncovered:
        console.print("\n[dim]Spec operations not tested (no resource config or filtered out): " +
                      ", ".join(f"{o['method']} {o['path']}" for o in uncovered) + "[/dim]")

    summary = None
    if truth:
        summary = show_metrics(rows)

    out = args.out or os.path.join("results", (args.labels or cfg["name"]).replace("/", "_") + ".json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump({"target": cfg["name"], "base_url": base, "labels": args.labels,
                   "rows": rows, "metrics": summary}, f, indent=2)
    console.print(f"\nSaved: {out}")


def yes_no(v):
    if v is None:
        return Text("skipped", style="dim")
    return Text("VULNERABLE", style="bold red") if v else Text("secure", style="green")


def show_findings(rows, has_truth):
    t = Table(show_lines=True)
    t.add_column("Endpoint")
    t.add_column("Our verdict")
    t.add_column("Naive (status only)")
    if has_truth:
        t.add_column("Truth")
    t.add_column("Evidence", overflow="fold")
    for r in rows:
        cells = [Text(r["endpoint"]), yes_no(r["verdict"]), yes_no(r["naive"])]
        if has_truth:
            cells.append(Text(r["truth"] or "-"))
        cells.append(Text(r["evidence"]))
        t.add_row(*cells)
    console.print(t)


def show_metrics(rows):
    out = {}
    t = Table(title="Detection accuracy vs ground truth")
    for col in ["Detector", "TP", "FP", "FN", "TN", "Precision", "Recall", "Accuracy", "FP rate"]:
        t.add_column(col)
    for label, key in [("Naive (status code only)", "naive"), ("Ours (response + state checks)", "verdict")]:
        s = scores(*confusion(rows, key))
        out[key] = s
        t.add_row(label, *[str(s[k]) for k in ["TP", "FP", "FN", "TN", "precision", "recall", "accuracy", "false_positive_rate"]])
    console.print(t)
    return out


if __name__ == "__main__":
    main()
