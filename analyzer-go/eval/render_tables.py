"""Render the markdown tables in EVAL.md from the eval/*.json result files."""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
load = lambda n: json.load(open(os.path.join(HERE, n)))
RULES = ["command_injection", "path_traversal", "sql_injection", "weak_crypto", "weak_randomness", "xss", "_overall"]


def per_class(path):
    m = load(path)["metrics"]
    print("| rule | cases | TP | FP | TN | FN | precision | recall | F1 | FPR | OWASP score |")
    print("|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|")
    for r in RULES:
        x = m[r]
        name = "**overall**" if r == "_overall" else f"`{r}`"
        print(f"| {name} | {x['cases']} | {x['TP']} | {x['FP']} | {x['TN']} | {x['FN']} | {x['precision']:.3f} | {x['recall']:.3f} | {x['f1']:.3f} | {x['fpr']:.3f} | {x['owasp_score']:+.3f} |")
    print()


def comparison():
    rows = [("v0.2 engine (before)", "results-v0.2-test.json"),
            ("v0.3 gates only (model disabled)", "results-v0.3-gates-test.json"),
            ("v0.3 gates + model (shipped)", "results-v0.3-test.json")]
    print("| engine | precision | recall | F1 | FPR | OWASP score |")
    print("|---|--:|--:|--:|--:|--:|")
    for label, f in rows:
        x = load(f)["metrics"]["_overall"]
        print(f"| {label} | {x['precision']:.3f} | {x['recall']:.3f} | {x['f1']:.3f} | {x['fpr']:.3f} | {x['owasp_score']:+.3f} |")
    print()


def tradeoff():
    curve = load("curve-v0.3-test.json")
    thr = json.load(open(os.path.join(HERE, "..", "training", "report.json")))["thresholds"]
    show = [0.0, 0.3, 0.4, 0.45, 0.5, 0.6, 0.7]
    print("| rule | chosen (train) | " + " | ".join(f"t={t:g}" for t in show) + " |")
    print("|---|--:|" + "--:|" * len(show))
    for r in RULES[:-1]:
        pts = {round(p["threshold"], 2): p for p in curve[r]}
        cells = [f"{pts[t]['precision']:.2f} / {pts[t]['recall']:.2f}" for t in show]
        print(f"| `{r}` | {thr[r]:.3f} | " + " | ".join(cells) + " |")
    print()


if __name__ == "__main__":
    print("## Comparison\n"); comparison()
    print("## Shipped engine, per class\n"); per_class("results-v0.3-test.json")
    print("## v0.2 per class\n"); per_class("results-v0.2-test.json")
    print("## Gates only per class\n"); per_class("results-v0.3-gates-test.json")
    print("## Tradeoff (precision / recall on test)\n"); tradeoff()
