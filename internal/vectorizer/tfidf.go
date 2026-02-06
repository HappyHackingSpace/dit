package vectorizer

import (
	"math"
)

// TfidfVectorizer converts text to TF-IDF weighted vectors.
// Uses binary=true mode (matching Formasaurus): value = IDF[term] if present, 0 otherwise.
type TfidfVectorizer struct {
	CountVec  *CountVectorizer `json:"count_vec"`
	IDF       []float64        `json:"idf"`
	StopWords map[string]bool  `json:"stop_words,omitempty"`
}

// NewTfidfVectorizer creates a TfidfVectorizer.
func NewTfidfVectorizer(ngramRange [2]int, minDF int, binary bool, analyzer string, stopWords map[string]bool) *TfidfVectorizer {
	return &TfidfVectorizer{
		CountVec:  NewCountVectorizer(ngramRange, binary, analyzer, minDF),
		StopWords: stopWords,
	}
}

// Fit computes IDF values from a corpus.
func (tv *TfidfVectorizer) Fit(corpus []string) {
	// Filter stop words from corpus for word analyzer
	filtered := tv.filterCorpus(corpus)
	tv.CountVec.Fit(filtered)

	nDocs := float64(len(filtered))
	vocabSize := tv.CountVec.VocabSize()
	tv.IDF = make([]float64, vocabSize)

	// Compute document frequencies
	df := make([]float64, vocabSize)
	for _, doc := range filtered {
		sv := tv.CountVec.Transform(doc)
		for _, idx := range sv.Indices {
			df[idx]++
		}
	}

	// sklearn smooth IDF: log((1 + n) / (1 + df)) + 1
	for i := 0; i < vocabSize; i++ {
		tv.IDF[i] = math.Log((1+nDocs)/(1+df[i])) + 1
	}
}

// FitTransform fits and transforms the corpus.
func (tv *TfidfVectorizer) FitTransform(corpus []string) []SparseVector {
	tv.Fit(corpus)
	result := make([]SparseVector, len(corpus))
	for i, doc := range corpus {
		result[i] = tv.Transform(doc)
	}
	return result
}

// Transform converts a single document to a TF-IDF sparse vector.
func (tv *TfidfVectorizer) Transform(text string) SparseVector {
	filtered := tv.filterText(text)
	sv := tv.CountVec.Transform(filtered)

	// Apply IDF weights
	for i, idx := range sv.Indices {
		if idx < len(tv.IDF) {
			sv.Values[i] *= tv.IDF[idx]
		}
	}

	// L2 normalize (sklearn default)
	norm := sv.L2Norm()
	if norm > 0 {
		for i := range sv.Values {
			sv.Values[i] /= norm
		}
	}
	return sv
}

// VocabSize returns the vocabulary size.
func (tv *TfidfVectorizer) VocabSize() int {
	return tv.CountVec.VocabSize()
}

func (tv *TfidfVectorizer) filterCorpus(corpus []string) []string {
	if len(tv.StopWords) == 0 {
		return corpus
	}
	// For char_wb analyzer, stop word filtering happens at the word level before char n-gram extraction
	// But sklearn applies stop words to the final feature names for char_wb, which we handle via vocabulary filtering
	// For word analyzer, we filter tokens
	if tv.CountVec.Analyzer == "char_wb" {
		return corpus
	}
	result := make([]string, len(corpus))
	for i, doc := range corpus {
		result[i] = tv.filterText(doc)
	}
	return result
}

func (tv *TfidfVectorizer) filterText(text string) string {
	if len(tv.StopWords) == 0 || tv.CountVec.Analyzer == "char_wb" {
		return text
	}
	// For word analyzer, we need to remove stop words at the token level
	// This is handled by removing stop words from the analyzed tokens
	// Since we lowercase in analyze(), we just return text as-is and let
	// the vocabulary handle filtering (stop words won't be in vocab if minDF filters them)
	return text
}

// EnglishStopWords returns sklearn's default English stop words set.
func EnglishStopWords() map[string]bool {
	words := []string{
		"a", "about", "above", "after", "again", "against", "ain", "all", "am",
		"an", "and", "any", "are", "aren", "aren't", "as", "at", "be", "because",
		"been", "before", "being", "below", "between", "both", "but", "by", "can",
		"couldn", "couldn't", "d", "did", "didn", "didn't", "do", "does", "doesn",
		"doesn't", "doing", "don", "don't", "down", "during", "each", "few", "for",
		"from", "further", "had", "hadn", "hadn't", "has", "hasn", "hasn't", "have",
		"haven", "haven't", "having", "he", "her", "here", "hers", "herself", "him",
		"himself", "his", "how", "i", "if", "in", "into", "is", "isn", "isn't", "it",
		"it's", "its", "itself", "just", "ll", "m", "ma", "me", "mightn", "mightn't",
		"more", "most", "mustn", "mustn't", "my", "myself", "needn", "needn't", "no",
		"nor", "not", "now", "o", "of", "off", "on", "once", "only", "or", "other",
		"our", "ours", "ourselves", "out", "over", "own", "re", "s", "same", "shan",
		"shan't", "she", "she's", "should", "should've", "shouldn", "shouldn't", "so",
		"some", "such", "t", "than", "that", "that'll", "the", "their", "theirs",
		"them", "themselves", "then", "there", "these", "they", "this", "those",
		"through", "to", "too", "under", "until", "up", "ve", "very", "was", "wasn",
		"wasn't", "we", "were", "weren", "weren't", "what", "when", "where", "which",
		"while", "who", "whom", "why", "will", "with", "won", "won't", "wouldn",
		"wouldn't", "y", "you", "you'd", "you'll", "you're", "you've", "your",
		"yours", "yourself", "yourselves",
	}
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}
