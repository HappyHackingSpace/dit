package vectorizer

import (
	"fmt"
	"sort"
)

// DictVectorizer converts feature dicts to sparse vectors.
type DictVectorizer struct {
	FeatureNames []string       `json:"feature_names"`
	FeatureIndex map[string]int `json:"feature_index"`
}

// NewDictVectorizer creates an empty DictVectorizer.
func NewDictVectorizer() *DictVectorizer {
	return &DictVectorizer{}
}

// Fit builds the feature mapping from a list of feature dicts.
func (dv *DictVectorizer) Fit(data []map[string]any) {
	featureSet := make(map[string]bool)
	for _, d := range data {
		for k, v := range d {
			key := dv.featureKey(k, v)
			featureSet[key] = true
		}
	}

	dv.FeatureNames = make([]string, 0, len(featureSet))
	for f := range featureSet {
		dv.FeatureNames = append(dv.FeatureNames, f)
	}
	sort.Strings(dv.FeatureNames)

	dv.FeatureIndex = make(map[string]int, len(dv.FeatureNames))
	for i, f := range dv.FeatureNames {
		dv.FeatureIndex[f] = i
	}
}

// FitTransform fits and transforms the data.
func (dv *DictVectorizer) FitTransform(data []map[string]any) []SparseVector {
	dv.Fit(data)
	result := make([]SparseVector, len(data))
	for i, d := range data {
		result[i] = dv.Transform(d)
	}
	return result
}

// Transform converts a feature dict to a sparse vector.
func (dv *DictVectorizer) Transform(d map[string]any) SparseVector {
	dim := len(dv.FeatureNames)
	sv := NewSparseVector(dim)

	for k, v := range d {
		key := dv.featureKey(k, v)
		if idx, ok := dv.FeatureIndex[key]; ok {
			sv.Set(idx, dv.featureValue(v))
		}
	}
	return sv
}

// VocabSize returns the number of features.
func (dv *DictVectorizer) VocabSize() int {
	return len(dv.FeatureNames)
}

// featureKey returns the feature key for a given name-value pair.
// For string values, it creates compound keys like "name=value".
// For numeric and bool values, it uses the key directly.
func (dv *DictVectorizer) featureKey(name string, value any) string {
	switch v := value.(type) {
	case string:
		return fmt.Sprintf("%s=%s", name, v)
	case bool, int, int64, float64:
		return name
	default:
		return name
	}
}

// featureValue returns the numeric value for a feature.
func (dv *DictVectorizer) featureValue(value any) float64 {
	switch v := value.(type) {
	case bool:
		if v {
			return 1.0
		}
		return 0.0
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case float64:
		return v
	case string:
		return 1.0
	default:
		return 1.0
	}
}
