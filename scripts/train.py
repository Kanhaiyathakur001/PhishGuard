"""Train and evaluate the phishing URL classifier.

* Features: phishguard.features (37 lexical/host features)
* Split: 80/20, grouped by registered domain, so the same domain never appears
  in both train and test (prevents leakage and over-optimistic numbers)
* Compares Logistic Regression, Decision Tree, Random Forest, Gradient Boosting
* Saves the best model (by ROC-AUC; ties in F1 are common, AUC is threshold-free) to models/model.joblib and metrics/plots to reports/

Usage:  python scripts/train.py
"""

import csv
import json
import sys
import time
from pathlib import Path

import joblib
import matplotlib
import numpy as np

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier  # noqa: E402
from sklearn.linear_model import LogisticRegression  # noqa: E402
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score,  # noqa: E402
                             precision_score, recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import GroupShuffleSplit  # noqa: E402
from sklearn.pipeline import make_pipeline  # noqa: E402
from sklearn.preprocessing import StandardScaler  # noqa: E402
from sklearn.tree import DecisionTreeClassifier  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from phishguard.features import FEATURE_NAMES, feature_vector  # noqa: E402
from phishguard.rules import parse, refang, registered_domain, run_rules  # noqa: E402

SEED = 42


def load(path):
    X, y, groups, rule_scores = [], [], [], []
    with open(path, encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            url = refang(row["url"])
            try:
                X.append(feature_vector(url))
                rule_scores.append(run_rules(url)["score"])
                groups.append(registered_domain(parse(url)[2]))
            except ValueError:
                continue
            y.append(int(row["label"]))
    return np.array(X), np.array(y), np.array(groups), np.array(rule_scores)


def metrics(y_true, y_pred, y_prob):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    return {
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred), 4),
        "recall": round(recall_score(y_true, y_pred), 4),
        "f1": round(f1_score(y_true, y_pred), 4),
        "roc_auc": round(roc_auc_score(y_true, y_prob), 4),
        "false_positive_rate": round(fp / (fp + tn), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def main():
    data_path = ROOT / "data" / "dataset.csv"
    print(f"Loading {data_path} ...")
    X, y, groups, rule_scores = load(data_path)
    print(f"{len(y)} URLs, {len(set(groups))} distinct domains, {X.shape[1]} features")

    gss = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=SEED)
    tr, te = next(gss.split(X, y, groups))
    Xtr, Xte, ytr, yte = X[tr], X[te], y[tr], y[te]
    assert not set(groups[tr]) & set(groups[te]), "domain leakage between splits"
    print(f"train={len(tr)} test={len(te)} (no shared domains)")

    candidates = {
        "Logistic Regression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, random_state=SEED)),
        "Decision Tree": make_pipeline(DecisionTreeClassifier(max_depth=12, random_state=SEED)),
        "Random Forest": make_pipeline(RandomForestClassifier(n_estimators=300, min_samples_leaf=2, n_jobs=-1, random_state=SEED)),
        "Gradient Boosting": make_pipeline(GradientBoostingClassifier(n_estimators=250, max_depth=4, random_state=SEED)),
    }

    results, fitted, probs = {}, {}, {}
    for name, pipe in candidates.items():
        t0 = time.time()
        pipe.fit(Xtr, ytr)
        p = pipe.predict_proba(Xte)[:, 1]
        results[name] = metrics(yte, (p >= 0.5).astype(int), p)
        results[name]["train_seconds"] = round(time.time() - t0, 1)
        fitted[name], probs[name] = pipe, p
        print(f"{name:20s} acc={results[name]['accuracy']:.4f} f1={results[name]['f1']:.4f} "
              f"auc={results[name]['roc_auc']:.4f} fpr={results[name]['false_positive_rate']:.4f}")

    # rule-engine-only baseline (original project), medium+ (score>=25) counts as phishing
    rs = rule_scores[te]
    base_pred = (rs >= 25).astype(int)
    results["Rules only (baseline, score>=25)"] = metrics(yte, base_pred, rs / 100.0)
    print(f"{'Rules only baseline':20s} acc={results['Rules only (baseline, score>=25)']['accuracy']:.4f}")

    ml_names = list(candidates)
    best = max(ml_names, key=lambda n: results[n]["roc_auc"])
    print(f"\nBest model: {best}")

    # hybrid score on the test set, exactly as the app computes it
    hybrid = np.round(0.7 * probs[best] * 100 + 0.3 * rs)
    hybrid_pred = (hybrid >= 25).astype(int)
    results["Hybrid (ML + rules, score>=25)"] = metrics(yte, hybrid_pred, hybrid / 100.0)
    print("Hybrid:", results["Hybrid (ML + rules, score>=25)"]["accuracy"])

    # stricter operating point: only HIGH (>=50) counts as phishing
    hy_hi = (hybrid >= 50).astype(int)
    results["Hybrid (HIGH only, score>=50)"] = metrics(yte, hy_hi, hybrid / 100.0)

    joblib.dump(fitted[best], ROOT / "models" / "model.joblib", compress=3)

    out = {
        "dataset": {"rows": int(len(y)), "phishing": int(y.sum()), "legitimate": int((1 - y).sum()),
                    "train_rows": int(len(tr)), "test_rows": int(len(te)),
                    "split": "80/20 grouped by registered domain", "seed": SEED},
        "best_model": best,
        "results": results,
    }
    (ROOT / "reports").mkdir(exist_ok=True)
    (ROOT / "reports" / "metrics.json").write_text(json.dumps(out, indent=2))

    # ---- plots
    clf = fitted[best][-1]
    cm = results[best]["confusion_matrix"]
    fig, ax = plt.subplots(figsize=(4.2, 3.8))
    arr = np.array([[cm["tn"], cm["fp"]], [cm["fn"], cm["tp"]]])
    ax.imshow(arr, cmap="Blues")
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{arr[i, j]:,}", ha="center", va="center",
                    color="white" if arr[i, j] > arr.max() / 2 else "black", fontsize=13)
    ax.set_xticks([0, 1], ["Legit", "Phishing"])
    ax.set_yticks([0, 1], ["Legit", "Phishing"])
    ax.set_xlabel("Predicted")
    ax.set_ylabel("Actual")
    ax.set_title(f"Confusion matrix: {best}")
    fig.tight_layout()
    fig.savefig(ROOT / "reports" / "confusion_matrix.png", dpi=150)
    plt.close(fig)

    fig, ax = plt.subplots(figsize=(5.5, 4.2))
    for name in ml_names:
        fpr, tpr, _ = roc_curve(yte, probs[name])
        ax.plot(fpr, tpr, label=f"{name} (AUC {results[name]['roc_auc']:.3f})")
    ax.plot([0, 1], [0, 1], "k--", lw=0.8)
    ax.set_xlabel("False positive rate")
    ax.set_ylabel("True positive rate")
    ax.set_title("ROC curves (held-out domains)")
    ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout()
    fig.savefig(ROOT / "reports" / "roc_curve.png", dpi=150)
    plt.close(fig)

    imps = getattr(clf, "feature_importances_", None)
    if imps is not None:
        order = np.argsort(imps)[::-1][:15][::-1]
        fig, ax = plt.subplots(figsize=(6, 4.6))
        ax.barh([FEATURE_NAMES[i] for i in order], imps[order], color="#3b6fb6")
        ax.set_title(f"Top 15 feature importances: {best}")
        fig.tight_layout()
        fig.savefig(ROOT / "reports" / "feature_importance.png", dpi=150)
        plt.close(fig)
        out["top_features"] = [(FEATURE_NAMES[i], round(float(imps[i]), 4)) for i in order[::-1]]
        (ROOT / "reports" / "metrics.json").write_text(json.dumps(out, indent=2))

    print("Saved models/model.joblib and reports/*")


if __name__ == "__main__":
    main()
