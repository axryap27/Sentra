"""
Train a Random Forest classifier on the generated vulnerability dataset
and export the model to model.json for the Go binary.

Usage:
    python generate_dataset.py   # first, generate training data
    python train_model.py        # then, train and export model

Requirements:
    pip install scikit-learn numpy
"""

import json
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score

def load_dataset(path="training_data.json"):
    with open(path) as f:
        data = json.load(f)

    X = np.array([s["features"] for s in data["samples"]])
    y = np.array([s["label"] for s in data["samples"]])
    return X, y, data["class_names"], data["severities"]


def train_model(X, y):
    """Train a Random Forest and return it."""
    clf = RandomForestClassifier(
        n_estimators=30,       # 30 trees — good balance of accuracy vs model size
        max_depth=10,          # prevent overfitting, keep trees small
        min_samples_split=5,
        min_samples_leaf=3,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X, y)
    return clf


def export_tree(tree, class_names):
    """Convert a sklearn DecisionTreeClassifier to our JSON format."""
    t = tree.tree_
    nodes = []

    for i in range(t.node_count):
        if t.feature[i] == -2:  # leaf node (sklearn uses -2 for leaves)
            # Get the class with most samples at this leaf
            class_counts = t.value[i][0]
            pred_class = int(np.argmax(class_counts))
            total = float(np.sum(class_counts))
            confidence = float(class_counts[pred_class] / total) if total > 0 else 0.0

            nodes.append({
                "f": -1,            # -1 = leaf
                "t": 0.0,
                "l": -1,
                "r": -1,
                "p": pred_class,
                "c": round(confidence, 3),
            })
        else:
            nodes.append({
                "f": int(t.feature[i]),
                "t": round(float(t.threshold[i]), 6),
                "l": int(t.children_left[i]),
                "r": int(t.children_right[i]),
                "p": 0,
                "c": 0.0,
            })

    return {"nodes": nodes}


def export_model(clf, class_names, severities, output_path="../internal/engine/model.json"):
    """Export the full random forest to JSON."""
    trees = []
    for estimator in clf.estimators_:
        trees.append(export_tree(estimator, class_names))

    model = {
        "trees": trees,
        "class_names": class_names,
        "severities": severities,
        "num_classes": len(class_names),
    }

    with open(output_path, "w") as f:
        json.dump(model, f)

    # Report size
    size_kb = len(json.dumps(model)) / 1024
    print(f"Model exported to {output_path} ({size_kb:.1f} KB)")
    print(f"  {len(trees)} trees, {sum(len(t['nodes']) for t in trees)} total nodes")


def main():
    print("Loading dataset...")
    X, y, class_names, severities = load_dataset()
    print(f"  {X.shape[0]} samples, {X.shape[1]} features, {len(class_names)} classes")

    print("\nTraining Random Forest...")
    clf = train_model(X, y)

    # Cross-validation accuracy
    print("\nCross-validation (5-fold)...")
    scores = cross_val_score(clf, X, y, cv=5, scoring="accuracy")
    print(f"  Accuracy: {scores.mean():.3f} (+/- {scores.std():.3f})")

    # Per-class accuracy
    from sklearn.metrics import classification_report
    y_pred = clf.predict(X)
    print("\nTraining classification report:")
    print(classification_report(y, y_pred, target_names=class_names))

    # Feature importances
    print("Feature importances:")
    feature_names = [
        "dangerous_func_category", "arg_count", "has_string_concat_in_args",
        "has_user_input_source", "is_in_comment", "is_in_try_catch",
        "is_in_conditional", "has_sanitization_nearby", "node_depth",
        "is_in_loop", "has_format_string", "is_public_function",
        "uses_weak_crypto", "has_hardcoded_secret", "language_id",
    ]
    importances = clf.feature_importances_
    for name, imp in sorted(zip(feature_names, importances), key=lambda x: -x[1]):
        bar = "#" * int(imp * 50)
        print(f"  {name:35s} {imp:.3f} {bar}")

    print("\nExporting model...")
    export_model(clf, class_names, severities)
    print("Done!")


if __name__ == "__main__":
    main()
