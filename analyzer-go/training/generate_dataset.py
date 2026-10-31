"""
Generate labeled training dataset for the vulnerability classifier.

Each sample is a feature vector (matching the 20 features in
internal/engine/features.go) with a class label (0=safe, 1..N=CWE categories).

NOTE: this data is synthetic. Feature values are drawn from hand-written
distributions per class, so cross-validation accuracy on it mostly measures how
well the model recovers feature 0 (the sink category). Real-world accuracy is
measured separately on OWASP Benchmark; see EVAL.md.

Classes:
  0  = safe
  1  = CWE-94/95  code injection (eval, exec)
  2  = CWE-79     XSS (innerHTML, document.write)
  3  = CWE-120    buffer overflow (strcpy, gets, sprintf)
  4  = CWE-327    weak crypto (MD5, SHA1)
  5  = CWE-502    unsafe deserialization (pickle, yaml.load)
  6  = CWE-798    hardcoded secrets
  7  = CWE-78     command injection (system, os.system)
  8  = CWE-22     path traversal
  9  = CWE-401    memory leak (malloc/free)
  10 = CWE-330    weak randomness (Math.random, rand)
  11 = CWE-89     SQL injection
"""

import json
import os
import random

random.seed(42)

CLASS_NAMES = [
    "safe",
    "code_injection",
    "xss",
    "buffer_overflow",
    "weak_crypto",
    "unsafe_deserialization",
    "hardcoded_secret",
    "command_injection",
    "path_traversal",
    "memory_leak",
    "weak_randomness",
    "sql_injection",
]

SEVERITIES = [
    "Low",    # safe
    "High",   # code injection
    "High",   # xss
    "High",   # buffer overflow
    "Medium", # weak crypto
    "High",   # unsafe deserialization
    "High",   # hardcoded secret
    "High",   # command injection
    "High",   # path traversal
    "Medium", # memory leak
    "Medium", # weak randomness
    "High",   # sql injection
]

# Feature indices:
#  0: dangerous_func_category
#  1: arg_count
#  2: has_string_concat_in_args
#  3: has_user_input_source
#  4: is_in_comment
#  5: is_in_try_catch
#  6: is_in_conditional
#  7: has_sanitization_nearby
#  8: node_depth
#  9: is_in_loop
# 10: has_format_string
# 11: is_public_function
# 12: uses_weak_crypto
# 13: has_hardcoded_secret
# 14: language_id
# 15: arg_from_user_input
# 16: arg_from_param
# 17: arg_built_with_concat
# 18: args_constant
# 19: weak_algorithm_arg
NUM_FEATURES = 20


def make_sample(label, **kwargs):
    """Create a feature vector with defaults, overridden by kwargs."""
    features = [0.0] * NUM_FEATURES
    features[14] = kwargs.get("language_id", random.randint(0, 9))
    features[8] = kwargs.get("node_depth", random.randint(2, 8))
    features[1] = kwargs.get("arg_count", random.randint(0, 4))

    for key, idx in {
        "dangerous_func_category": 0,
        "arg_count": 1,
        "has_string_concat_in_args": 2,
        "has_user_input_source": 3,
        "is_in_comment": 4,
        "is_in_try_catch": 5,
        "is_in_conditional": 6,
        "has_sanitization_nearby": 7,
        "node_depth": 8,
        "is_in_loop": 9,
        "has_format_string": 10,
        "is_public_function": 11,
        "uses_weak_crypto": 12,
        "has_hardcoded_secret": 13,
        "language_id": 14,
        "arg_from_user_input": 15,
        "arg_from_param": 16,
        "arg_built_with_concat": 17,
        "args_constant": 18,
        "weak_algorithm_arg": 19,
    }.items():
        if key in kwargs:
            features[idx] = float(kwargs[key])

    # Dataflow features (15-19) default to values consistent with the line-level ones.
    if "arg_from_user_input" not in kwargs:
        features[15] = features[3]
    if "arg_from_param" not in kwargs:
        features[16] = float(random.random() < 0.5)
    if "arg_built_with_concat" not in kwargs:
        features[17] = float(features[2] == 1.0 or features[10] == 1.0)
    if "weak_algorithm_arg" not in kwargs:
        features[19] = features[12]
    return {"features": features, "label": label}


def generate_dataset():
    samples = []

    # ==================== SAFE SAMPLES (class 0) ====================
    # Regular function calls - no dangerous patterns
    for _ in range(300):
        samples.append(make_sample(0,
            dangerous_func_category=0,
            has_string_concat_in_args=0,
            has_user_input_source=0,
            is_in_comment=0,
            has_sanitization_nearby=random.choice([0, 1]),
            uses_weak_crypto=0,
            has_hardcoded_secret=0,
        ))

    # Dangerous function name but inside a comment (false positive)
    for cat in [1, 2, 3, 4, 5, 7, 9, 10, 11]:
        for _ in range(20):
            samples.append(make_sample(0,
                dangerous_func_category=cat,
                is_in_comment=1,
                has_user_input_source=random.choice([0, 1]),
            ))

    # Dangerous function name but with sanitization nearby (mitigated)
    for cat in [1, 2, 7, 8, 11]:
        for _ in range(15):
            samples.append(make_sample(0,
                dangerous_func_category=cat,
                has_sanitization_nearby=1,
                has_user_input_source=1,
                is_in_comment=0,
            ))

    # ==================== CODE INJECTION (class 1) ====================
    # eval/exec with user input
    for _ in range(80):
        samples.append(make_sample(1,
            dangerous_func_category=1,
            has_user_input_source=random.choice([0, 1]),
            is_in_comment=0,
            has_sanitization_nearby=0,
            arg_count=random.randint(1, 3),
        ))

    # eval with string concat
    for _ in range(40):
        samples.append(make_sample(1,
            dangerous_func_category=1,
            has_string_concat_in_args=1,
            is_in_comment=0,
            has_sanitization_nearby=0,
        ))

    # ==================== XSS (class 2) ====================
    for _ in range(70):
        samples.append(make_sample(2,
            dangerous_func_category=2,
            has_user_input_source=random.choice([0, 1]),
            is_in_comment=0,
            has_sanitization_nearby=0,
            language_id=random.choice([1, 2]),  # JS/TS
        ))

    # XSS with format string
    for _ in range(30):
        samples.append(make_sample(2,
            dangerous_func_category=2,
            has_format_string=1,
            has_user_input_source=1,
            is_in_comment=0,
            has_sanitization_nearby=0,
        ))

    # ==================== BUFFER OVERFLOW (class 3) ====================
    for _ in range(80):
        samples.append(make_sample(3,
            dangerous_func_category=3,
            is_in_comment=0,
            has_sanitization_nearby=0,
            language_id=random.choice([4, 5]),  # C/C++
            arg_count=random.randint(1, 4),
        ))

    # Buffer overflow with user input (most dangerous)
    for _ in range(40):
        samples.append(make_sample(3,
            dangerous_func_category=3,
            has_user_input_source=1,
            is_in_comment=0,
            language_id=random.choice([4, 5]),
        ))

    # ==================== WEAK CRYPTO (class 4) ====================
    for _ in range(70):
        samples.append(make_sample(4,
            dangerous_func_category=4,
            uses_weak_crypto=1,
            is_in_comment=0,
        ))

    # ==================== UNSAFE DESERIALIZATION (class 5) ====================
    for _ in range(70):
        samples.append(make_sample(5,
            dangerous_func_category=5,
            is_in_comment=0,
            has_sanitization_nearby=0,
            has_user_input_source=random.choice([0, 1]),
        ))

    # ==================== HARDCODED SECRETS (class 6) ====================
    for _ in range(80):
        samples.append(make_sample(6,
            dangerous_func_category=0,  # not a function call
            has_hardcoded_secret=1,
            is_in_comment=0,
        ))

    # Variable named "token" but value from env (safe)
    for _ in range(30):
        samples.append(make_sample(0,
            dangerous_func_category=0,
            has_hardcoded_secret=0,
            is_in_comment=0,
        ))

    # ==================== COMMAND INJECTION (class 7) ====================
    for _ in range(80):
        samples.append(make_sample(7,
            dangerous_func_category=7,
            is_in_comment=0,
            has_sanitization_nearby=0,
            has_user_input_source=random.choice([0, 1]),
        ))

    # system() with string concat (very dangerous)
    for _ in range(40):
        samples.append(make_sample(7,
            dangerous_func_category=7,
            has_string_concat_in_args=1,
            has_user_input_source=1,
            is_in_comment=0,
        ))

    # ==================== PATH TRAVERSAL (class 8) ====================
    for _ in range(60):
        samples.append(make_sample(8,
            dangerous_func_category=8,
            has_user_input_source=1,
            is_in_comment=0,
            has_sanitization_nearby=0,
        ))

    # open() without user input (safe)
    for _ in range(40):
        samples.append(make_sample(0,
            dangerous_func_category=8,
            has_user_input_source=0,
            is_in_comment=0,
            has_sanitization_nearby=0,
        ))

    # ==================== MEMORY LEAK (class 9) ====================
    for _ in range(60):
        samples.append(make_sample(9,
            dangerous_func_category=9,
            is_in_comment=0,
            language_id=random.choice([4, 5]),  # C/C++
        ))

    # ==================== WEAK RANDOMNESS (class 10) ====================
    for _ in range(60):
        samples.append(make_sample(10,
            dangerous_func_category=10,
            is_in_comment=0,
        ))

    # ==================== SQL INJECTION (class 11) ====================
    # query() with string concat and user input
    for _ in range(60):
        samples.append(make_sample(11,
            dangerous_func_category=11,
            has_string_concat_in_args=1,
            has_user_input_source=random.choice([0, 1]),
            is_in_comment=0,
            has_sanitization_nearby=0,
        ))

    # query() with format string
    for _ in range(30):
        samples.append(make_sample(11,
            dangerous_func_category=11,
            has_format_string=1,
            is_in_comment=0,
            has_sanitization_nearby=0,
        ))

    # query() with parameterized (safe)
    for _ in range(30):
        samples.append(make_sample(0,
            dangerous_func_category=11,
            has_string_concat_in_args=0,
            has_format_string=0,
            is_in_comment=0,
            has_sanitization_nearby=1,
        ))

    # Sinks called with only constant arguments (e.g. os.system("clear")) are safe.
    for cat in [1, 2, 7, 8, 11]:
        for _ in range(15):
            samples.append(make_sample(0,
                dangerous_func_category=cat,
                args_constant=1,
                has_user_input_source=0,
                arg_from_user_input=0,
                arg_from_param=0,
                has_string_concat_in_args=0,
                arg_built_with_concat=0,
            ))

    # Add noise: vary node_depth, is_in_loop, is_public_function, is_in_conditional
    for sample in samples:
        if "is_in_loop" not in str(sample):
            sample["features"][9] = random.choice([0.0, 0.0, 0.0, 1.0])
        if sample["features"][11] == 0.0:
            sample["features"][11] = random.choice([0.0, 1.0])
        if sample["features"][6] == 0.0:
            sample["features"][6] = random.choice([0.0, 0.0, 1.0])

    random.shuffle(samples)

    return {
        "samples": samples,
        "class_names": CLASS_NAMES,
        "severities": SEVERITIES,
        "num_features": NUM_FEATURES,
        "num_classes": len(CLASS_NAMES),
    }


if __name__ == "__main__":
    dataset = generate_dataset()
    print(f"Generated {len(dataset['samples'])} samples across {dataset['num_classes']} classes")
    for i, name in enumerate(CLASS_NAMES):
        count = sum(1 for s in dataset["samples"] if s["label"] == i)
        print(f"  {name}: {count}")

    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "training_data.json"), "w") as f:
        json.dump(dataset, f, indent=2)
    print("\nSaved to training_data.json")
