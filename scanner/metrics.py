"""Compare the scanner's verdicts with the ground-truth labels (labels.yaml)."""


def confusion(rows, verdict_key):
    """rows: list of dicts with 'truth' ('vulnerable'/'secure') and a boolean verdict_key."""
    tp = fp = fn = tn = 0
    for r in rows:
        if r.get("truth") is None or r.get(verdict_key) is None:
            continue
        actual = r["truth"] == "vulnerable"
        predicted = bool(r[verdict_key])
        if actual and predicted:
            tp += 1
        elif not actual and predicted:
            fp += 1
        elif actual and not predicted:
            fn += 1
        else:
            tn += 1
    return tp, fp, fn, tn


def scores(tp, fp, fn, tn):
    def div(a, b):
        return round(a / b, 3) if b else None
    return {
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "precision": div(tp, tp + fp),
        "recall": div(tp, tp + fn),
        "accuracy": div(tp + tn, tp + fp + fn + tn),
        "false_positive_rate": div(fp, fp + tn),
    }
