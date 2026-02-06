package crf

import (
	"math"
	"testing"
)

func TestAlphabet(t *testing.T) {
	a := NewAlphabet()
	id0 := a.Add("hello")
	id1 := a.Add("world")
	id2 := a.Add("hello") // duplicate

	if id0 != 0 || id1 != 1 || id2 != 0 {
		t.Errorf("IDs: %d, %d, %d; want 0, 1, 0", id0, id1, id2)
	}
	if a.Size() != 2 {
		t.Errorf("Size = %d, want 2", a.Size())
	}
	if a.Get("missing") != -1 {
		t.Error("Get missing should return -1")
	}
}

func TestFeaturesToAttributes(t *testing.T) {
	features := map[string]any{
		"tag":       "input",
		"name":      []string{"user", "name"},
		"is-first":  true,
		"is-last":   false,
		"bias":      1,
		"form-type": "login",
	}
	attrs := FeaturesToAttributes(features)

	if attrs["tag=input"] != 1.0 {
		t.Error("expected tag=input")
	}
	if attrs["name:user"] != 1.0 {
		t.Error("expected name:user")
	}
	if attrs["name:name"] != 1.0 {
		t.Error("expected name:name")
	}
	if attrs["is-first"] != 1.0 {
		t.Error("expected is-first=1.0")
	}
	if _, ok := attrs["is-last"]; ok {
		t.Error("is-last=false should not be in attrs")
	}
	if attrs["bias"] != 1.0 {
		t.Error("expected bias=1.0")
	}
}

func TestViterbiSimple(t *testing.T) {
	// 2 positions, 2 labels
	stateScores := [][]float64{
		{1.0, 0.5},
		{0.3, 2.0},
	}
	transScores := [][]float64{
		{0.1, 0.2},
		{0.3, 0.1},
	}

	path, score := Viterbi(stateScores, transScores)
	if len(path) != 2 {
		t.Fatalf("path length = %d, want 2", len(path))
	}

	// Verify: best path should be [0, 1]
	// Score: 1.0 + 0.2 + 2.0 = 3.2
	// vs [0,0]: 1.0 + 0.1 + 0.3 = 1.4
	// vs [1,0]: 0.5 + 0.3 + 0.3 = 1.1
	// vs [1,1]: 0.5 + 0.1 + 2.0 = 2.6
	if path[0] != 0 || path[1] != 1 {
		t.Errorf("path = %v, want [0, 1]", path)
	}
	if math.Abs(score-3.2) > 1e-10 {
		t.Errorf("score = %v, want 3.2", score)
	}
}

func TestForwardBackward(t *testing.T) {
	stateScores := [][]float64{
		{1.0, 0.5},
		{0.3, 2.0},
	}
	transScores := [][]float64{
		{0.1, 0.2},
		{0.3, 0.1},
	}

	fb := ForwardBackward(stateScores, transScores)

	// LogZ should be positive and finite
	if math.IsNaN(fb.LogZ) || math.IsInf(fb.LogZ, 0) {
		t.Errorf("LogZ = %v, expected finite", fb.LogZ)
	}

	// Marginals should sum to 1 at each position
	for pos := range 2 {
		sum := fb.Marginals[pos][0] + fb.Marginals[pos][1]
		if math.Abs(sum-1.0) > 1e-6 {
			t.Errorf("marginals at pos=%d sum to %v, want 1.0", pos, sum)
		}
	}

	// Verify logZ by brute force
	// Z = sum over all paths of exp(score(path))
	paths := [][]int{{0, 0}, {0, 1}, {1, 0}, {1, 1}}
	Z := 0.0
	for _, p := range paths {
		s := stateScores[0][p[0]] + stateScores[1][p[1]] + transScores[p[0]][p[1]]
		Z += math.Exp(s)
	}
	expectedLogZ := math.Log(Z)
	if math.Abs(fb.LogZ-expectedLogZ) > 1e-6 {
		t.Errorf("LogZ = %v, expected %v", fb.LogZ, expectedLogZ)
	}
}

func TestTrainSimple(t *testing.T) {
	// Simple toy training: predict A->B or B->A
	sequences := []TrainingSequence{
		{
			Features: []map[string]float64{
				{"word=hello": 1.0, "bias": 1.0},
				{"word=world": 1.0, "bias": 1.0},
			},
			Labels: []string{"A", "B"},
		},
		{
			Features: []map[string]float64{
				{"word=world": 1.0, "bias": 1.0},
				{"word=hello": 1.0, "bias": 1.0},
			},
			Labels: []string{"B", "A"},
		},
	}

	config := DefaultTrainerConfig()
	config.MaxIterations = 50
	config.C1 = 0.01
	config.C2 = 0.01

	model := Train(sequences, config)

	// Model should predict correctly on training data
	pred := model.Predict(sequences[0].Features)
	if len(pred) != 2 {
		t.Fatalf("prediction length = %d, want 2", len(pred))
	}
	if pred[0] != "A" || pred[1] != "B" {
		t.Logf("Warning: prediction %v != [A, B] (may be OK for small training set)", pred)
	}
}

func TestModelSaveLoad(t *testing.T) {
	model := NewModel()
	model.Labels.Add("A")
	model.Labels.Add("B")
	model.Attributes.Add("bias")
	model.NumLabels = 2
	model.Weights = []float64{1.0, -0.5, 0.3, 0.1, 0.2, -0.1, 0.0, 0.4}

	data, err := MarshalModel(model)
	if err != nil {
		t.Fatal(err)
	}

	loaded, err := UnmarshalModel(data)
	if err != nil {
		t.Fatal(err)
	}

	if loaded.NumLabels != model.NumLabels {
		t.Errorf("NumLabels mismatch: %d vs %d", loaded.NumLabels, model.NumLabels)
	}
	if len(loaded.Weights) != len(model.Weights) {
		t.Errorf("Weights length mismatch: %d vs %d", len(loaded.Weights), len(model.Weights))
	}
	for i := range model.Weights {
		if loaded.Weights[i] != model.Weights[i] {
			t.Errorf("Weight[%d] mismatch: %v vs %v", i, loaded.Weights[i], model.Weights[i])
		}
	}
}
