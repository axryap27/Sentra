package engine

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"
)

//go:embed model.json
var modelJSON []byte

// TreeNode represents a single node in a decision tree.
type TreeNode struct {
	FeatureIndex int     `json:"f"` // index into feature vector (-1 for leaf)
	Threshold    float64 `json:"t"` // split threshold
	Left         int     `json:"l"` // index of left child node
	Right        int     `json:"r"` // index of right child node
	Prediction   int     `json:"p"` // class label (only valid for leaves where f == -1)
	Confidence   float64 `json:"c"` // prediction confidence at this leaf
}

// DecisionTree is a flattened decision tree (array of nodes, root at index 0).
type DecisionTree struct {
	Nodes []TreeNode `json:"nodes"`
}

// RandomForestModel is the full model containing multiple decision trees.
type RandomForestModel struct {
	Trees      []DecisionTree `json:"trees"`
	ClassNames []string       `json:"class_names"` // maps class index → label (e.g., "CWE-78")
	Severities []string       `json:"severities"`  // maps class index → severity
	NumClasses int            `json:"num_classes"`
}

// Prediction is the output of the classifier.
type Prediction struct {
	ClassIndex int
	ClassName  string
	Severity   string
	Confidence float64
}

// RandomForestClassifier performs inference with an embedded model.
type RandomForestClassifier struct {
	model *RandomForestModel
}

var (
	classifierInstance *RandomForestClassifier
	classifierOnce     sync.Once
	classifierErr      error
)

// GetClassifier returns a singleton classifier loaded from the embedded model.
func GetClassifier() (*RandomForestClassifier, error) {
	classifierOnce.Do(func() {
		var model RandomForestModel
		if err := json.Unmarshal(modelJSON, &model); err != nil {
			classifierErr = fmt.Errorf("failed to load model: %w", err)
			return
		}
		classifierInstance = &RandomForestClassifier{model: &model}
	})
	return classifierInstance, classifierErr
}

// Predict classifies a single feature vector.
func (rf *RandomForestClassifier) Predict(features []float64) Prediction {
	if len(rf.model.Trees) == 0 {
		return Prediction{ClassIndex: 0, ClassName: "safe", Severity: "Low", Confidence: 0}
	}

	// Collect votes from all trees
	votes := make([]int, rf.model.NumClasses)
	totalConfidence := make([]float64, rf.model.NumClasses)

	for _, tree := range rf.model.Trees {
		classIdx, confidence := rf.traverseTree(&tree, features)
		if classIdx >= 0 && classIdx < rf.model.NumClasses {
			votes[classIdx]++
			totalConfidence[classIdx] += confidence
		}
	}

	// Find majority vote
	bestClass := 0
	bestVotes := 0
	for i, v := range votes {
		if v > bestVotes {
			bestVotes = v
			bestClass = i
		}
	}

	confidence := float64(bestVotes) / float64(len(rf.model.Trees))
	if bestVotes > 0 {
		confidence = totalConfidence[bestClass] / float64(bestVotes)
	}

	className := "safe"
	severity := "Low"
	if bestClass < len(rf.model.ClassNames) {
		className = rf.model.ClassNames[bestClass]
	}
	if bestClass < len(rf.model.Severities) {
		severity = rf.model.Severities[bestClass]
	}

	return Prediction{
		ClassIndex: bestClass,
		ClassName:  className,
		Severity:   severity,
		Confidence: confidence,
	}
}

// traverseTree walks a single decision tree and returns (classIndex, confidence).
func (rf *RandomForestClassifier) traverseTree(tree *DecisionTree, features []float64) (int, float64) {
	if len(tree.Nodes) == 0 {
		return 0, 0
	}

	nodeIdx := 0
	for {
		if nodeIdx < 0 || nodeIdx >= len(tree.Nodes) {
			return 0, 0
		}
		node := tree.Nodes[nodeIdx]

		// Leaf node
		if node.FeatureIndex == -1 {
			return node.Prediction, node.Confidence
		}

		// Interior node: compare feature against threshold
		featureVal := 0.0
		if node.FeatureIndex >= 0 && node.FeatureIndex < len(features) {
			featureVal = features[node.FeatureIndex]
		}

		if featureVal <= node.Threshold {
			nodeIdx = node.Left
		} else {
			nodeIdx = node.Right
		}
	}
}
