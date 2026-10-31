"""Deterministic train/test split of OWASP Benchmark v1.2 test cases, by file.

Every OWASP test case is one Java file, so splitting by test case is splitting by
source file: no file contributes samples to both sides. Stratified by
(category, real vulnerability) so both sides have the same class balance.

    python eval/owasp_split.py <BenchmarkJava dir> > eval/owasp_split.json
"""
import csv
import json
import random
import sys
from collections import defaultdict

# OWASP category -> Sentra rule. Other categories (ldapi, xpathi, trustbound,
# securecookie) have no corresponding Sentra rule and are excluded.
CATEGORY_TO_RULE = {
    "cmdi": "command_injection",
    "sqli": "sql_injection",
    "xss": "xss",
    "pathtraver": "path_traversal",
    "weakrand": "weak_randomness",
    "crypto": "weak_crypto",
    "hash": "weak_crypto",
}
TEST_FRACTION = 0.4
SEED = 42


def main(root):
    groups = defaultdict(list)
    with open(f"{root}/expectedresults-1.2.csv") as f:
        for row in csv.reader(f):
            if row[0].startswith("#"):
                continue
            name, cat, real = row[0], row[1], row[2].strip() == "true"
            if cat in CATEGORY_TO_RULE:
                groups[(cat, real)].append(name)

    rng = random.Random(SEED)
    cases = {}
    for (cat, real), names in sorted(groups.items()):
        names.sort()
        rng.shuffle(names)
        n_test = round(len(names) * TEST_FRACTION)
        for i, name in enumerate(names):
            cases[name] = {
                "category": cat,
                "rule": CATEGORY_TO_RULE[cat],
                "vulnerable": real,
                "split": "test" if i < n_test else "train",
            }
    json.dump({"source": "OWASP Benchmark v1.2", "seed": SEED, "test_fraction": TEST_FRACTION,
               "cases": dict(sorted(cases.items()))}, sys.stdout, indent=1)


if __name__ == "__main__":
    main(sys.argv[1])
