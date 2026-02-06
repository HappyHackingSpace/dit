package vectorizer

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/happyhackingspace/dit/internal/textutil"
)

// CountVectorizer converts text to token count vectors.
type CountVectorizer struct {
	Vocabulary map[string]int `json:"vocabulary"`
	NgramRange [2]int         `json:"ngram_range"`
	Binary     bool           `json:"binary"`
	Analyzer   string         `json:"analyzer"` // "word" or "char_wb"
	MinDF      int            `json:"min_df"`
}

// NewCountVectorizer creates a CountVectorizer with default settings.
func NewCountVectorizer(ngramRange [2]int, binary bool, analyzer string, minDF int) *CountVectorizer {
	if analyzer == "" {
		analyzer = "word"
	}
	if minDF < 1 {
		minDF = 1
	}
	return &CountVectorizer{
		NgramRange: ngramRange,
		Binary:     binary,
		Analyzer:   analyzer,
		MinDF:      minDF,
	}
}

// analyze extracts features from text based on the analyzer type.
func (cv *CountVectorizer) analyze(text string) []string {
	text = strings.ToLower(text)
	if cv.Analyzer == "char_wb" {
		return charWbNgrams(text, cv.NgramRange[0], cv.NgramRange[1])
	}
	// word analyzer
	tokens := textutil.Tokenize(text)
	return textutil.TokenNgrams(tokens, cv.NgramRange[0], cv.NgramRange[1])
}

// charWbNgrams extracts character n-grams within word boundaries.
// Each word is padded with spaces, and n-grams are extracted from padded words.
func charWbNgrams(text string, minN, maxN int) []string {
	tokens := textutil.Tokenize(text)
	var result []string
	for _, token := range tokens {
		padded := " " + token + " "
		result = append(result, textutil.Ngrams(padded, minN, maxN)...)
	}
	return result
}

// Fit builds the vocabulary from a corpus.
func (cv *CountVectorizer) Fit(corpus []string) {
	// Count document frequency for each term
	dfCounts := make(map[string]int)
	for _, doc := range corpus {
		seen := make(map[string]bool)
		features := cv.analyze(doc)
		for _, f := range features {
			if !seen[f] {
				dfCounts[f]++
				seen[f] = true
			}
		}
	}

	// Build vocabulary filtered by min_df
	cv.Vocabulary = make(map[string]int)
	// Sort terms for deterministic ordering
	terms := make([]string, 0, len(dfCounts))
	for term, count := range dfCounts {
		if count >= cv.MinDF {
			terms = append(terms, term)
		}
	}
	sort.Strings(terms)
	for i, term := range terms {
		cv.Vocabulary[term] = i
	}
}

// FitTransform fits the vocabulary and transforms the corpus.
func (cv *CountVectorizer) FitTransform(corpus []string) []SparseVector {
	cv.Fit(corpus)
	result := make([]SparseVector, len(corpus))
	for i, doc := range corpus {
		result[i] = cv.Transform(doc)
	}
	return result
}

// Transform converts a single document to a sparse vector.
func (cv *CountVectorizer) Transform(text string) SparseVector {
	dim := len(cv.Vocabulary)
	sv := NewSparseVector(dim)
	features := cv.analyze(text)

	counts := make(map[int]float64)
	for _, f := range features {
		if idx, ok := cv.Vocabulary[f]; ok {
			counts[idx]++
		}
	}

	for idx, count := range counts {
		if cv.Binary {
			sv.Set(idx, 1.0)
		} else {
			sv.Set(idx, count)
		}
	}
	return sv
}

// VocabSize returns the vocabulary size.
func (cv *CountVectorizer) VocabSize() int {
	return len(cv.Vocabulary)
}

// MarshalJSON implements json.Marshaler.
func (cv *CountVectorizer) MarshalJSON() ([]byte, error) {
	type Alias CountVectorizer
	return json.Marshal((*Alias)(cv))
}

// UnmarshalJSON implements json.Unmarshaler.
func (cv *CountVectorizer) UnmarshalJSON(data []byte) error {
	type Alias CountVectorizer
	return json.Unmarshal(data, (*Alias)(cv))
}
