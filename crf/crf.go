// Package crf implements a linear-chain Conditional Random Field.
package crf

// Alphabet maps between string labels/attributes and integer IDs.
type Alphabet struct {
	ToID  map[string]int `json:"to_id"`
	ToStr []string       `json:"to_str"`
}

// NewAlphabet creates an empty alphabet.
func NewAlphabet() *Alphabet {
	return &Alphabet{
		ToID: make(map[string]int),
	}
}

// Add adds a string to the alphabet if not already present, returns its ID.
func (a *Alphabet) Add(s string) int {
	if id, ok := a.ToID[s]; ok {
		return id
	}
	id := len(a.ToStr)
	a.ToID[s] = id
	a.ToStr = append(a.ToStr, s)
	return id
}

// Get returns the ID for a string, or -1 if not found.
func (a *Alphabet) Get(s string) int {
	if id, ok := a.ToID[s]; ok {
		return id
	}
	return -1
}

// Size returns the number of entries.
func (a *Alphabet) Size() int {
	return len(a.ToStr)
}

// Model holds the CRF parameters.
type Model struct {
	Labels     *Alphabet `json:"labels"`
	Attributes *Alphabet `json:"attributes"`
	Weights    []float64 `json:"weights"`
	NumLabels  int       `json:"num_labels"`
	// Weight layout: [state_features... | transition_features...]
	// State feature index: attrID * numLabels + labelID
	// Transition feature index: transOffset + fromLabelID * numLabels + toLabelID
}

// NewModel creates a new empty model.
func NewModel() *Model {
	return &Model{
		Labels:     NewAlphabet(),
		Attributes: NewAlphabet(),
	}
}

// TransOffset returns the offset where transition features start in the weight vector.
func (m *Model) TransOffset() int {
	return m.Attributes.Size() * m.NumLabels
}

// NumWeights returns the total number of weights.
func (m *Model) NumWeights() int {
	return m.TransOffset() + m.NumLabels*m.NumLabels
}

// StateFeatureIndex returns the weight index for a state feature.
func (m *Model) StateFeatureIndex(attrID, labelID int) int {
	return attrID*m.NumLabels + labelID
}

// TransFeatureIndex returns the weight index for a transition feature.
func (m *Model) TransFeatureIndex(fromLabelID, toLabelID int) int {
	return m.TransOffset() + fromLabelID*m.NumLabels + toLabelID
}

// TrainingSequence represents a labeled sequence for training.
type TrainingSequence struct {
	Features []map[string]float64 // per-position feature dicts
	Labels   []string             // gold labels
	Group    int                  // for grouped cross-validation
}

// Sequence represents an unlabeled sequence for prediction.
type Sequence struct {
	Features []map[string]float64 // per-position feature dicts
}

// ComputeStateScores computes state feature scores for each position and label.
// Returns [T][L] matrix where T is sequence length and L is number of labels.
func (m *Model) ComputeStateScores(features []map[string]float64) [][]float64 {
	T := len(features)
	L := m.NumLabels
	scores := make([][]float64, T)
	for t := range T {
		scores[t] = make([]float64, L)
		for attr, val := range features[t] {
			attrID := m.Attributes.Get(attr)
			if attrID < 0 {
				continue
			}
			for y := range L {
				idx := m.StateFeatureIndex(attrID, y)
				if idx < len(m.Weights) {
					scores[t][y] += m.Weights[idx] * val
				}
			}
		}
	}
	return scores
}

// ComputeTransScores returns the [L][L] transition score matrix.
func (m *Model) ComputeTransScores() [][]float64 {
	L := m.NumLabels
	trans := make([][]float64, L)
	for i := range L {
		trans[i] = make([]float64, L)
		for j := range L {
			idx := m.TransFeatureIndex(i, j)
			if idx < len(m.Weights) {
				trans[i][j] = m.Weights[idx]
			}
		}
	}
	return trans
}
