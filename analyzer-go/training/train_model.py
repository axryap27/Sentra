"""Train the Random Forest and export it to internal/engine/model.json.

Training data:
  1. training_data.json            synthetic samples (generate_dataset.py), all classes
  2. owasp_train_features.jsonl    real candidates from the OWASP Benchmark *train* split,
                                   dumped by `go run ./cmd/sentra-eval -subset train -dump ...`

The OWASP *test* split is never read here. Per-rule probability thresholds are
tuned on out-of-fold predictions over the OWASP train split (GroupKFold by test
case, so no file is in both a fold's training and validation side), choosing the
threshold that maximizes case-level F0.5 (precision weighted 2x over recall).
Thresholds are applied to Java only, the language they were tuned on. Everywhere
else (and for rules with no real data) the threshold is 0: findings are reported
whenever the deterministic gates pass and the model only supplies a confidence.

Usage (from analyzer-go/):
    python training/generate_dataset.py      # writes training/training_data.json
    go run ./cmd/sentra-eval -owasp $OWASP -subset train -no-model -dump training/owasp_train_features.jsonl
    python training/train_model.py           # writes internal/engine/model.json, training/report.json
"""

import json
import os
import time
from collections import defaultdict

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import GroupKFold, cross_val_score

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

FEATURE_NAMES = [
    "dangerous_func_category", "arg_count", "has_string_concat_in_args", "has_user_input_source",
    "is_in_comment", "is_in_try_catch", "is_in_conditional", "has_sanitization_nearby",
    "node_depth", "is_in_loop", "has_format_string", "is_public_function", "uses_weak_crypto",
    "has_hardcoded_secret", "language_id", "arg_from_user_input", "arg_from_param",
    "arg_built_with_concat", "args_constant", "weak_algorithm_arg",
]
REAL_WEIGHT = 3.0   # a real sample counts as this many synthetic ones
BETA = 0.5          # F-beta for threshold selection; < 1 favors precision
SEED = 42


def make_forest():
    return RandomForestClassifier(
        n_estimators=30,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=3,
        random_state=SEED,
        n_jobs=-1,
    )


def load_synthetic():
    with open(os.path.join(HERE, "training_data.json")) as f:
        data = json.load(f)
    assert data["num_features"] == len(FEATURE_NAMES)
    X = np.array([s["features"] for s in data["samples"]])
    y = np.array([s["label"] for s in data["samples"]])
    return X, y, data["class_names"]


def load_real(class_names):
    rows = [json.loads(l) for l in open(os.path.join(HERE, "owasp_train_features.jsonl"))]
    X = np.array([r["features"] for r in rows])
    # A vulnerable case's sink is labeled with its rule's class; a safe case's sink is "safe" (0).
    y = np.array([class_names.index(r["rule"]) if r["label"] else 0 for r in rows])
    return X, y, [r["case"] for r in rows], [r["rule"] for r in rows]


def load_split_cases():
    with open(os.path.join(ROOT, "eval", "owasp_split.json")) as f:
        cases = json.load(f)["cases"]
    return {n: c for n, c in cases.items() if c["split"] == "train"}


def fbeta(tp, fp, fn, beta=BETA):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    if p + r == 0:
        return 0.0, p, r
    b2 = beta * beta
    return (1 + b2) * p * r / (b2 * p + r), p, r


def case_level(probs_by_case, cases, rule, t):
    """Case flagged iff any of its same-rule candidates has P >= t (no candidate: not flagged)."""
    tp = fp = tn = fn = 0
    for name, c in cases.items():
        if c["rule"] != rule:
            continue
        flagged = any(p >= t for p in probs_by_case.get(name, []))
        if c["vulnerable"]:
            tp, fn = tp + flagged, fn + (not flagged)
        else:
            fp, tn = fp + flagged, tn + (not flagged)
    return tp, fp, tn, fn


def tune_thresholds(Xs, ys, Xr, yr, groups, rules, class_names, cases):
    """Out-of-fold P(rule) for every real candidate, then the best threshold per rule."""
    oof = np.zeros(len(yr))
    for train_idx, val_idx in GroupKFold(n_splits=5).split(Xr, yr, groups):
        clf = make_forest()
        X = np.vstack([Xs, Xr[train_idx]])
        y = np.concatenate([ys, yr[train_idx]])
        w = np.concatenate([np.ones(len(ys)), np.full(len(train_idx), REAL_WEIGHT)])
        clf.fit(X, y, sample_weight=w)
        proba = clf.predict_proba(Xr[val_idx])
        col = {c: i for i, c in enumerate(clf.classes_)}
        for k, i in enumerate(val_idx):
            ci = class_names.index(rules[i])
            oof[i] = proba[k][col[ci]] if ci in col else 0.0

    thresholds, curves = {}, {}
    for rule in sorted(set(rules)):
        by_case = defaultdict(list)
        for i, r in enumerate(rules):
            if r == rule:
                by_case[groups[i]].append(oof[i])
        grid = [0.0] + sorted({round(float(p), 3) for ps in by_case.values() for p in ps})
        curve = []
        for t in grid:
            tp, fp, tn, fn = case_level(by_case, cases, rule, t)
            f, p, r = fbeta(tp, fp, fn)
            curve.append({"threshold": t, "precision": round(p, 3), "recall": round(r, 3),
                          "fpr": round(fp / (fp + tn), 3) if fp + tn else 0.0, "f0.5": round(f, 3)})
        best = max(curve, key=lambda c: (c["f0.5"], -c["threshold"]))
        thresholds[rule] = best["threshold"]
        curves[rule] = curve
    return thresholds, curves


def export_tree(est):
    t = est.tree_
    classes = [int(c) for c in est.classes_]
    out = {"f": [], "t": [], "l": [], "r": [], "v": []}
    for i in range(t.node_count):
        leaf = t.children_left[i] == -1
        out["f"].append(-1 if leaf else int(t.feature[i]))
        out["t"].append(0.0 if leaf else round(float(t.threshold[i]), 6))
        out["l"].append(int(t.children_left[i]))
        out["r"].append(int(t.children_right[i]))
        if leaf:
            v = t.value[i][0]
            v = v / v.sum() if v.sum() > 0 else v
            out["v"].append([[classes[k], round(float(p), 4)] for k, p in enumerate(v) if p > 0])
        else:
            out["v"].append([])
    return out


def main():
    Xs, ys, class_names = load_synthetic()
    Xr, yr, groups, rules = load_real(class_names)
    cases = load_split_cases()
    print(f"synthetic: {len(ys)} samples; OWASP train: {len(yr)} candidates from {len(set(groups))} cases")

    # Reported for continuity with v0.2. Synthetic-only, so not a real-world accuracy.
    syn_cv = cross_val_score(make_forest(), Xs, ys, cv=5, scoring="accuracy")
    print(f"5-fold CV accuracy on synthetic data only: {syn_cv.mean():.3f} (+/- {syn_cv.std():.3f})")

    thresholds, curves = tune_thresholds(Xs, ys, Xr, yr, groups, rules, class_names, cases)
    for rule, t in thresholds.items():
        best = next(c for c in curves[rule] if c["threshold"] == t)
        print(f"  threshold {rule:18s} {t:.3f}  (train OOF: precision {best['precision']:.3f}, recall {best['recall']:.3f}, FPR {best['fpr']:.3f})")

    clf = make_forest()
    clf.fit(np.vstack([Xs, Xr]), np.concatenate([ys, yr]),
            sample_weight=np.concatenate([np.ones(len(ys)), np.full(len(yr), REAL_WEIGHT)]))

    model = {
        "version": 2,
        "description": "30-tree Random Forest; leaves store class distributions (predict_proba).",
        "trained_on": f"{len(ys)} synthetic samples + {len(yr)} OWASP Benchmark v1.2 train-split candidates",
        "features": FEATURE_NAMES,
        "class_names": class_names,
        "num_classes": len(class_names),
        # Tuned on Java only, so applied to Java only (see EVAL.md).
        "thresholds": {"java": thresholds},
        "trees": [export_tree(e) for e in clf.estimators_],
    }
    path = os.path.join(ROOT, "internal", "engine", "model.json")
    with open(path, "w") as f:
        json.dump(model, f, separators=(",", ":"))
    size = os.path.getsize(path)
    nodes = sum(len(t["f"]) for t in model["trees"])

    # sklearn inference time per candidate, for reference (the Go engine is measured separately).
    t0 = time.perf_counter()
    for _ in range(5):
        clf.predict_proba(Xr)
    sk_us = (time.perf_counter() - t0) / (5 * len(Xr)) * 1e6

    importances = sorted(zip(FEATURE_NAMES, clf.feature_importances_), key=lambda x: -x[1])
    report = {
        "synthetic_cv_accuracy_mean": round(float(syn_cv.mean()), 4),
        "synthetic_cv_accuracy_std": round(float(syn_cv.std()), 4),
        "synthetic_samples": int(len(ys)),
        "owasp_train_candidates": int(len(yr)),
        "owasp_train_cases": len(set(groups)),
        "thresholds": thresholds,
        "threshold_curves_train_oof": curves,
        "model_bytes": size,
        "trees": len(model["trees"]),
        "nodes": nodes,
        "sklearn_batch_predict_us_per_candidate": round(sk_us, 2),
        "feature_importances": {n: round(float(v), 4) for n, v in importances},
    }
    with open(os.path.join(HERE, "report.json"), "w") as f:
        json.dump(report, f, indent=1)
    print(f"model: {path} ({size / 1024:.1f} KB, {len(model['trees'])} trees, {nodes} nodes)")
    print("top features:", ", ".join(f"{n} {v:.3f}" for n, v in importances[:6]))


if __name__ == "__main__":
    main()
