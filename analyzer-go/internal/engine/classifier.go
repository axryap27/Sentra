package engine

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sync"
)

//go:embed model.json
var modelJSON []byte

// modelFile is the on-disk format written by training/train_model.py.
type modelFile struct {
	Version     int                           `json:"version"`
	Features    []string                      `json:"features"`
	ClassNames  []string                      `json:"class_names"`
	NumClasses  int                           `json:"num_classes"`
	Thresholds  map[string]map[string]float64 `json:"thresholds"` // language -> rule -> threshold
	Trees       []treeFile                    `json:"trees"`
	TrainedOn   string                        `json:"trained_on"`
	Description string                        `json:"description"`
}

type treeFile struct {
	// Parallel arrays, root at index 0. Feature[i] == -1 marks a leaf, whose
	// class distribution is Value[i] as sparse [class, probability] pairs.
	Feature   []int          `json:"f"`
	Threshold []float64      `json:"t"`
	Left      []int          `json:"l"`
	Right     []int          `json:"r"`
	Value     [][][2]float64 `json:"v"`
}

// RandomForestClassifier runs inference with the embedded Random Forest.
type RandomForestClassifier struct {
	trees      []treeFile
	numClasses int
	classIndex map[string]int
	thresholds map[string]map[string]float64
}

var (
	classifierInstance *RandomForestClassifier
	classifierOnce     sync.Once
	classifierErr      error
)

// GetClassifier returns the classifier loaded from the embedded model.
func GetClassifier() (*RandomForestClassifier, error) {
	classifierOnce.Do(func() {
		classifierInstance, classifierErr = loadClassifier(modelJSON)
	})
	return classifierInstance, classifierErr
}

func loadClassifier(data []byte) (*RandomForestClassifier, error) {
	var m modelFile
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse model: %w", err)
	}
	if m.Version != 2 {
		return nil, fmt.Errorf("model version %d, want 2", m.Version)
	}
	if len(m.Features) != NumFeatures {
		return nil, fmt.Errorf("model has %d features, engine has %d", len(m.Features), NumFeatures)
	}
	for i, name := range m.Features {
		if name != FeatureNames[i] {
			return nil, fmt.Errorf("model feature %d is %q, engine expects %q", i, name, FeatureNames[i])
		}
	}
	rf := &RandomForestClassifier{trees: m.Trees, numClasses: m.NumClasses, classIndex: map[string]int{}, thresholds: m.Thresholds}
	for i, n := range m.ClassNames {
		rf.classIndex[n] = i
	}
	for ti, t := range m.Trees {
		n := len(t.Feature)
		if n == 0 || len(t.Threshold) != n || len(t.Left) != n || len(t.Right) != n || len(t.Value) != n {
			return nil, fmt.Errorf("tree %d is malformed", ti)
		}
	}
	return rf, nil
}

// Proba returns P(class) averaged over the forest, like sklearn's predict_proba.
func (rf *RandomForestClassifier) Proba(features []float64, class string) float64 {
	if rf == nil {
		return 1 // no model: rely on the deterministic gates alone
	}
	ci, ok := rf.classIndex[class]
	if !ok || len(rf.trees) == 0 {
		return 0
	}
	sum := 0.0
	for ti := range rf.trees {
		t := &rf.trees[ti]
		i := 0
		for t.Feature[i] >= 0 {
			v := 0.0
			if f := t.Feature[i]; f < len(features) {
				v = features[f]
			}
			if v <= t.Threshold[i] {
				i = t.Left[i]
			} else {
				i = t.Right[i]
			}
		}
		for _, cp := range t.Value[i] {
			if int(cp[0]) == ci {
				sum += cp[1]
				break
			}
		}
	}
	return sum / float64(len(rf.trees))
}

// Threshold is the minimum probability at which a rule's finding is reported in
// lang. Thresholds exist only where they were tuned on real labeled code (Java,
// OWASP Benchmark); elsewhere it is 0 and the deterministic gates decide alone.
func (rf *RandomForestClassifier) Threshold(lang Language, rule string) float64 {
	if rf == nil {
		return 0
	}
	return rf.thresholds[string(lang)][rule]
}
