// Package textutil provides text processing utilities for form classification.
package textutil

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

var tokenizeRe = regexp.MustCompile(`[\p{L}\p{N}_]+`)

// Tokenize extracts word tokens from text (Unicode-aware, matching Python's (?u)\b\w+\b).
func Tokenize(text string) []string {
	return tokenizeRe.FindAllString(text, -1)
}

// Ngrams returns min_n to max_n character-level n-grams of the given string.
func Ngrams(s string, minN, maxN int) []string {
	runes := []rune(s)
	textLen := len(runes)
	var res []string
	for n := minN; n <= maxN && n <= textLen; n++ {
		for i := 0; i <= textLen-n; i++ {
			res = append(res, string(runes[i:i+n]))
		}
	}
	return res
}

// TokenNgrams returns n-grams from a list of tokens, joined by space.
func TokenNgrams(tokens []string, minN, maxN int) []string {
	tLen := len(tokens)
	var res []string
	for n := minN; n <= maxN && n <= tLen; n++ {
		for i := 0; i <= tLen-n; i++ {
			res = append(res, strings.Join(tokens[i:i+n], " "))
		}
	}
	return res
}

var (
	newlineRe    = regexp.MustCompile(`[\n\r]`)
	multiSpaceRe = regexp.MustCompile(`\s{2,}`)
)

// NormalizeWhitespaces replaces newlines and multiple whitespace with a single space.
func NormalizeWhitespaces(text string) string {
	text = newlineRe.ReplaceAllString(text, " ")
	return multiSpaceRe.ReplaceAllString(text, " ")
}

// Normalize lowercases text and normalizes whitespace.
func Normalize(text string) string {
	return NormalizeWhitespaces(strings.ToLower(text))
}

var digitRe = regexp.MustCompile(`\d`)

// NumberPattern replaces digits with X and letters with C if the digit ratio >= threshold.
// Returns empty string otherwise.
func NumberPattern(text string, ratio float64) string {
	if text == "" {
		return ""
	}

	total := utf8.RuneCountInString(text)
	digitCount := 0
	for _, r := range text {
		if unicode.IsDigit(r) {
			digitCount++
		}
	}

	digitRatio := float64(digitCount) / float64(total)
	if digitRatio >= ratio {
		// Replace digits with X
		result := digitRe.ReplaceAllString(text, "X")
		// Replace non-X word characters (letters) with C — match [^X\W] which is word chars that aren't X
		var buf strings.Builder
		for _, r := range result {
			if r == 'X' || !unicode.IsLetter(r) {
				buf.WriteRune(r)
			} else {
				buf.WriteRune('C')
			}
		}
		return buf.String()
	}
	return ""
}
