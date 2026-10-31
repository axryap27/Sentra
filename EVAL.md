# Sentra accuracy evaluation

Every number below comes from a committed script (`scripts/eval.sh`) and a committed
result file under `analyzer-go/eval/`. Nothing is hand-entered.

## TL;DR

On a held-out split of **OWASP Benchmark v1.2** (981 real, labeled Java test cases that
were never used for training, rule design or threshold tuning):

| engine | precision | recall | F1 | FPR | OWASP score |
|---|--:|--:|--:|--:|--:|
| v0.2 engine (before) | 0.486 | 0.172 | 0.254 | 0.190 | -0.018 |
| v0.3 gates only (model disabled) | 0.640 | 0.916 | 0.754 | 0.537 | +0.379 |
| v0.3 gates + model (shipped) | **0.718** | 0.776 | 0.746 | **0.319** | **+0.458** |

*OWASP score* is the benchmark's own metric, TPR − FPR: 0 is what random guessing scores and
+1 is perfect. The v0.2 engine scored slightly *below* random on real code.

The ~93% figure quoted for v0.2 was 5-fold cross-validation **on synthetic data** produced by
`generate_dataset.py`. It is still reproduced (now 0.926 ± 0.019) but it is not a measure of
real-world accuracy: synthetic labels are almost a function of feature 0 (which sink matched),
so the forest mostly learns to read that feature back.

## Dataset and split

- **Source:** [OWASP Benchmark v1.2](https://github.com/OWASP-Benchmark/BenchmarkJava) at commit
  `f40c618`, `expectedresults-1.2.csv`. Each test case is one Java servlet file with one CWE
  category and a ground-truth label (really vulnerable, or a deliberately safe look-alike).
- **In scope:** the 6 categories that map to a Sentra rule, 2,453 cases: `cmdi` → command_injection,
  `sqli` → sql_injection, `xss` → xss, `pathtraver` → path_traversal, `weakrand` → weak_randomness,
  `crypto` + `hash` → weak_crypto. (`ldapi`, `xpathi`, `trustbound` and `securecookie` have no
  Sentra rule.)
- **Split by source file:** `eval/owasp_split.py` assigns whole test cases (= whole files) to
  train (60%, 1,472 cases) or test (40%, 981 cases), stratified by (category, label), seed 42.
  No file contributes samples to both sides.
- **What used the train split:** reading example code to design sinks/gates, the training
  candidates for the model, and 5-fold `GroupKFold` (grouped by test case) out-of-fold
  predictions for threshold tuning. **The test split was used only to produce the tables in
  this file**, after all choices were frozen. In particular, the per-class thresholds were not
  revisited after seeing that command_injection gets worse with the model (below).

**Scoring** follows the OWASP scorecard: a case counts as *flagged* if Sentra reports any
finding of that case's rule anywhere in the file; TP/FP/TN/FN are counted per case.

## Per-class results, held-out test split (shipped engine)

| rule | cases | TP | FP | TN | FN | precision | recall | F1 | FPR | OWASP score |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| `command_injection` | 100 | 20 | 25 | 25 | 30 | 0.444 | 0.400 | 0.421 | 0.500 | -0.100 |
| `path_traversal` | 107 | 27 | 23 | 31 | 26 | 0.540 | 0.509 | 0.524 | 0.426 | +0.084 |
| `sql_injection` | 202 | 93 | 62 | 31 | 16 | 0.600 | 0.853 | 0.705 | 0.667 | +0.187 |
| `weak_crypto` | 193 | 87 | 0 | 89 | 17 | 1.000 | 0.837 | 0.911 | 0.000 | +0.837 |
| `weak_randomness` | 197 | 87 | 0 | 110 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | +1.000 |
| `xss` | 182 | 75 | 43 | 41 | 23 | 0.636 | 0.765 | 0.694 | 0.512 | +0.253 |
| **overall** | 981 | 389 | 153 | 327 | 112 | 0.718 | 0.776 | 0.746 | 0.319 | +0.458 |

Ablations on the same split: [v0.2](analyzer-go/eval/results-v0.2-test.json),
[gates only](analyzer-go/eval/results-v0.3-gates-test.json).

<details><summary>v0.2 engine, per class</summary>

| rule | cases | TP | FP | TN | FN | precision | recall | F1 | FPR | OWASP score |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| `command_injection` | 100 | 13 | 7 | 43 | 37 | 0.650 | 0.260 | 0.371 | 0.140 | +0.120 |
| `path_traversal` | 107 | 0 | 0 | 54 | 53 | 0.000 | 0.000 | 0.000 | 0.000 | +0.000 |
| `sql_injection` | 202 | 0 | 0 | 93 | 109 | 0.000 | 0.000 | 0.000 | 0.000 | +0.000 |
| `weak_crypto` | 193 | 52 | 43 | 46 | 52 | 0.547 | 0.500 | 0.523 | 0.483 | +0.017 |
| `weak_randomness` | 197 | 21 | 41 | 69 | 66 | 0.339 | 0.241 | 0.282 | 0.373 | -0.131 |
| `xss` | 182 | 0 | 0 | 84 | 98 | 0.000 | 0.000 | 0.000 | 0.000 | +0.000 |
| **overall** | 981 | 86 | 91 | 389 | 415 | 0.486 | 0.172 | 0.254 | 0.190 | -0.018 |

</details>

<details><summary>v0.3 gates only (model disabled), per class</summary>

| rule | cases | TP | FP | TN | FN | precision | recall | F1 | FPR | OWASP score |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| `command_injection` | 100 | 50 | 50 | 0 | 0 | 0.500 | 1.000 | 0.667 | 1.000 | +0.000 |
| `path_traversal` | 107 | 39 | 29 | 25 | 14 | 0.574 | 0.736 | 0.645 | 0.537 | +0.199 |
| `sql_injection` | 202 | 106 | 92 | 1 | 3 | 0.535 | 0.972 | 0.691 | 0.989 | -0.017 |
| `weak_crypto` | 193 | 87 | 8 | 81 | 17 | 0.916 | 0.837 | 0.874 | 0.090 | +0.747 |
| `weak_randomness` | 197 | 87 | 0 | 110 | 0 | 1.000 | 1.000 | 1.000 | 0.000 | +1.000 |
| `xss` | 182 | 90 | 79 | 5 | 8 | 0.533 | 0.918 | 0.674 | 0.940 | -0.022 |
| **overall** | 981 | 459 | 258 | 222 | 42 | 0.640 | 0.916 | 0.754 | 0.537 | +0.379 |

</details>

## What changed between v0.2 and v0.3

1. **Sinks the v0.2 engine did not know.** It had no Java servlet XSS sinks
   (`response.getWriter().print/format/write`), no JDBC/Spring sinks beyond `executeQuery`/`execute`,
   no `java.io.File*`/`Paths.get` sinks and no `java.util.Random`, which is why it found **zero**
   SQLi, XSS and path traversal cases. Sinks are now a language-scoped table (`internal/engine/sinks.go`).
2. **Light intra-procedural taint** (`internal/engine/taint.go`). While walking a function in source
   order, each local variable records whether its value traces to a user-input source, a function
   parameter, string concatenation/formatting, a weak algorithm literal, or only constants; for-each
   loop variables and mutators (`list.add`, `sb.append`, `map.put`) propagate facts; assignments
   nested deeper in branches than the variable's definition are weak updates. Five new features
   (15–19) expose this to the model. This is what lets `statement.executeUpdate(sql)` be flagged
   when `sql` was built from `request.getParameter(...)` two lines earlier.
3. **Deterministic precision gates** (`passesGates` in `analyze.go`): algorithm-taking APIs
   (`MessageDigest.getInstance`, `Cipher.getInstance`, `hashlib.new`, `crypto.createHash`) only fire
   on a weak algorithm argument; SQL sinks need a dynamically built argument; injection sinks with
   only constant arguments do not fire; `regex.exec()` is no longer "code injection"; `free()` is no
   longer a finding and `malloc` only fires when the function never calls `free`;
   `yaml.load(..., Loader=SafeLoader)` and `pickle.loads(pickle.dumps(x))` are not flagged.
4. **A model that actually gates findings.** In v0.2 the Random Forest's output only changed the
   "(High/Medium/Low confidence)" suffix; the category came from a lookup table and every match
   was reported. Now leaves store class distributions (`predict_proba`), and a finding is reported
   only if P(rule) ≥ that rule's threshold.
5. **Bug fixes that affected accuracy:** string-concatenation detection treated `'` inside `"..."`
   as a string delimiter (missing most SQL built like `"... '" + x + "'"`); a fallback line scanner
   flagged words like "query" in docstrings; "des" matched inside "describe".

## Precision vs. recall: per-class thresholds

False positives are what make developers uninstall a linter, so thresholds were chosen to
maximize **F0.5** (precision weighted twice as much as recall) on out-of-fold train predictions.
The table shows the tradeoff on the held-out test split at fixed thresholds (precision / recall).
"chosen" is the threshold selected on the train split and shipped in `model.json`.

| rule | chosen (train) | t=0 | t=0.3 | t=0.4 | t=0.45 | t=0.5 | t=0.6 | t=0.7 |
|---|--:|--:|--:|--:|--:|--:|--:|--:|
| `command_injection` | 0.409 | 0.50 / 1.00 | 0.54 / 0.96 | 0.43 / 0.40 | 0.45 / 0.34 | 0.54 / 0.26 | 0.62 / 0.20 | 0.50 / 0.10 |
| `path_traversal` | 0.430 | 0.57 / 0.74 | 0.57 / 0.74 | 0.54 / 0.51 | 0.54 / 0.51 | 0.52 / 0.26 | 0.40 / 0.11 | 0.00 / 0.00 |
| `sql_injection` | 0.440 | 0.54 / 0.97 | 0.54 / 0.95 | 0.58 / 0.88 | 0.60 / 0.85 | 0.63 / 0.77 | 0.86 / 0.06 | 0.00 / 0.00 |
| `weak_crypto` | 0.577 | 0.92 / 0.84 | 0.92 / 0.84 | 0.92 / 0.84 | 0.92 / 0.84 | 0.92 / 0.84 | 1.00 / 0.84 | 1.00 / 0.84 |
| `weak_randomness` | 0.000 | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 |
| `xss` | 0.466 | 0.53 / 0.92 | 0.53 / 0.92 | 0.60 / 0.80 | 0.63 / 0.77 | 0.68 / 0.74 | 0.66 / 0.28 | 0.00 / 0.00 |

Reading it honestly:

- **weak_crypto and weak_randomness are solved by the deterministic gates** (weak algorithm literal;
  `java.util.Random` vs `SecureRandom`). The model removes the remaining 8 weak-crypto false positives.
- **SQLi and XSS**: the model trades recall for precision as intended (SQLi 0.535 → 0.600, XSS
  0.533 → 0.636 precision; FPR 0.99 → 0.67 and 0.94 → 0.51).
- **command_injection: the model makes it worse** (OWASP score 0.000 → −0.100). The threshold picked
  on train (precision 0.57 out-of-fold) did not transfer. Per the protocol it was not retuned on
  test data. Its features carry little signal for this category (see limitations).
- Precision on the injection categories tops out around 0.6 because most OWASP "safe" cases differ
  from vulnerable ones only in ways this analysis cannot see (next section).

## Limitations

- **The OWASP false cases need deeper analysis than Sentra does.** On the train split, ~70% of
  injection cases route data through an inner-class helper (`doSomething(request, param)`), which
  needs inter-procedural analysis, and many others rely on constant-folded conditions
  (`(7 * 18) + num > 200 ? "safe" : param`), `switch` on a constant, or reading a different index of
  a list/map than the one the tainted value was put in. The same templates appear in both
  vulnerable and safe variants, so no feature of a single sink separates them. Sentra deliberately
  does not special-case these benchmark idioms.
- **The model may partly learn OWASP's code style** (`is_in_try_catch` and `node_depth` carry
  importance). The test split shares those templates, so it is an *in-distribution* held-out set.
  Expect real-world precision on the injection classes to be no better than reported here.
- **Thresholds apply to Java only.** They were tuned on Java, so other languages (and rules with no
  real labeled data: buffer_overflow, code_injection, unsafe_deserialization, hardcoded_secret,
  memory_leak) are reported whenever the deterministic gates pass, and the model only supplies the
  confidence value. Those rules have **no real-world accuracy measurement yet**.
- **Noise check on non-benchmark code** (not a precision measurement; there is no ground truth):
  on django 5.1 (2,899 files) the v0.2 engine reported 873 findings and v0.3 reports 272, of which
  160 are outside `tests/` (excluded by default in the extension).
- Next steps: Juliet C/C++ (CWE-121/122/78/401) for the C rules, and CVEfixes for Python/JavaScript.

## Model size and speed

From `training/report.json` and `go test -bench Proba ./internal/engine`:

| | |
|---|---|
| trees / nodes | 30 / 4,614 |
| `model.json` (embedded in the binary) | 121,647 bytes (v0.2: 205,966) |
| inference per candidate (Go, one core) | 543 ns, 0 allocations |
| training data | 1,680 synthetic samples + 1,257 OWASP train-split candidates (1,094 cases) |
| synthetic-only 5-fold CV accuracy | 0.926 ± 0.019 (for continuity with v0.2; not a real-world metric) |

## Reproduce

```bash
pip install -r analyzer-go/training/requirements.txt
scripts/eval.sh
```

The script clones OWASP Benchmark at the pinned commit, rebuilds the split, regenerates synthetic
data, dumps train-split features, retrains (deterministic, seed 42), and re-evaluates.
