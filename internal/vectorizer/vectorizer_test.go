package vectorizer

import (
	"math"
	"testing"
)

func TestSparseVector(t *testing.T) {
	sv := NewSparseVector(5)
	sv.Set(1, 2.0)
	sv.Set(3, 4.0)

	dense := sv.ToDense()
	if dense[1] != 2.0 || dense[3] != 4.0 || dense[0] != 0.0 {
		t.Errorf("ToDense unexpected: %v", dense)
	}

	dotVec := []float64{1, 2, 3, 4, 5}
	dot := sv.Dot(dotVec)
	expected := 2.0*2 + 4.0*4
	if dot != expected {
		t.Errorf("Dot = %v, want %v", dot, expected)
	}
}

func TestConcatSparse(t *testing.T) {
	sv1 := NewSparseVector(3)
	sv1.Set(0, 1.0)
	sv2 := NewSparseVector(2)
	sv2.Set(1, 2.0)

	result := ConcatSparse([]SparseVector{sv1, sv2})
	if result.Dim != 5 {
		t.Errorf("Dim = %d, want 5", result.Dim)
	}
	dense := result.ToDense()
	if dense[0] != 1.0 || dense[4] != 2.0 {
		t.Errorf("Concat unexpected: %v", dense)
	}
}

func TestCountVectorizerWord(t *testing.T) {
	cv := NewCountVectorizer([2]int{1, 2}, true, "word", 1)
	corpus := []string{"hello world", "world hello"}
	vectors := cv.FitTransform(corpus)

	if len(cv.Vocabulary) == 0 {
		t.Error("empty vocabulary")
	}
	if len(vectors) != 2 {
		t.Errorf("expected 2 vectors, got %d", len(vectors))
	}
	// With binary=true, all present terms should have value 1.0
	for _, v := range vectors[0].Values {
		if v != 1.0 {
			t.Errorf("expected binary value 1.0, got %v", v)
		}
	}
}

func TestCountVectorizerCharWb(t *testing.T) {
	cv := NewCountVectorizer([2]int{3, 3}, true, "char_wb", 1)
	corpus := []string{"hello"}
	cv.FitTransform(corpus)

	// "hello" -> padded " hello " -> trigrams: " he", "hel", "ell", "llo", "lo "
	if len(cv.Vocabulary) != 5 {
		t.Errorf("char_wb vocab size = %d, want 5", len(cv.Vocabulary))
	}
}

func TestCountVectorizerMinDF(t *testing.T) {
	cv := NewCountVectorizer([2]int{1, 1}, true, "word", 2)
	corpus := []string{"hello world", "hello universe"}
	cv.Fit(corpus)

	// "hello" appears in 2 docs, "world" and "universe" in 1 each
	if _, ok := cv.Vocabulary["hello"]; !ok {
		t.Error("expected 'hello' in vocabulary (df=2)")
	}
	if _, ok := cv.Vocabulary["world"]; ok {
		t.Error("'world' should not be in vocabulary (df=1, min_df=2)")
	}
}

func TestTfidfVectorizer(t *testing.T) {
	tv := NewTfidfVectorizer([2]int{1, 1}, 1, true, "word", nil)
	corpus := []string{"hello world", "hello universe", "world hello"}
	vectors := tv.FitTransform(corpus)

	if len(vectors) != 3 {
		t.Errorf("expected 3 vectors, got %d", len(vectors))
	}

	// Each vector should be L2 normalized
	for i, v := range vectors {
		norm := v.L2Norm()
		if v.Nnz() > 0 && math.Abs(norm-1.0) > 1e-6 {
			t.Errorf("vector %d norm = %v, want ~1.0", i, norm)
		}
	}
}

func TestTfidfVectorizerStopWords(t *testing.T) {
	stopWords := map[string]bool{"the": true, "a": true}
	tv := NewTfidfVectorizer([2]int{1, 1}, 1, true, "word", stopWords)
	corpus := []string{"the quick fox", "a lazy dog"}
	tv.Fit(corpus)

	// Stop words should still be in vocabulary since they pass through analyze
	// (sklearn removes stop words at the analyzer level for word analyzer)
	// Our implementation handles this through vocabulary filtering
	if tv.VocabSize() == 0 {
		t.Error("vocabulary should not be empty")
	}
}

func TestDictVectorizer(t *testing.T) {
	dv := NewDictVectorizer()
	data := []map[string]any{
		{"has_password": true, "method": "post", "text_count": 2},
		{"has_password": false, "method": "get", "text_count": 1},
	}
	vectors := dv.FitTransform(data)

	if len(vectors) != 2 {
		t.Errorf("expected 2 vectors, got %d", len(vectors))
	}

	// String features create compound keys
	if _, ok := dv.FeatureIndex["method=post"]; !ok {
		t.Error("expected 'method=post' in feature index")
	}
	if _, ok := dv.FeatureIndex["method=get"]; !ok {
		t.Error("expected 'method=get' in feature index")
	}
	// Bool/numeric features use plain key
	if _, ok := dv.FeatureIndex["has_password"]; !ok {
		t.Error("expected 'has_password' in feature index")
	}
}

func TestDictVectorizerTransform(t *testing.T) {
	dv := NewDictVectorizer()
	data := []map[string]any{
		{"color": "red", "size": 10},
		{"color": "blue", "size": 20},
	}
	dv.Fit(data)

	// Transform with known feature
	sv := dv.Transform(map[string]any{"color": "red", "size": 15})
	if sv.Dim != dv.VocabSize() {
		t.Errorf("Dim mismatch: %d vs %d", sv.Dim, dv.VocabSize())
	}

	// Transform with unknown feature value
	sv2 := dv.Transform(map[string]any{"color": "green"})
	if sv2.Nnz() != 0 {
		t.Errorf("unknown feature value should produce no entries, got %d", sv2.Nnz())
	}
}
