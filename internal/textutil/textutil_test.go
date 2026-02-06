package textutil

import (
	"reflect"
	"testing"
)

func TestTokenize(t *testing.T) {
	tests := []struct {
		input string
		want  []string
	}{
		{"hello world", []string{"hello", "world"}},
		{"user_name", []string{"user_name"}},
		{"email@example.com", []string{"email", "example", "com"}},
		{"", nil},
		{"  spaces  ", []string{"spaces"}},
		{"café résumé", []string{"café", "résumé"}},
		{"hello-world", []string{"hello", "world"}},
		{"input[name]", []string{"input", "name"}},
	}
	for _, tt := range tests {
		got := Tokenize(tt.input)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("Tokenize(%q) = %v, want %v", tt.input, got, tt.want)
		}
	}
}

func TestNgrams(t *testing.T) {
	tests := []struct {
		s    string
		min  int
		max  int
		want []string
	}{
		{"abc", 2, 3, []string{"ab", "bc", "abc"}},
		{"ab", 3, 5, nil},
		{"hello", 5, 5, []string{"hello"}},
		{"ab", 1, 2, []string{"a", "b", "ab"}},
		{"", 1, 3, nil},
	}
	for _, tt := range tests {
		got := Ngrams(tt.s, tt.min, tt.max)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("Ngrams(%q, %d, %d) = %v, want %v", tt.s, tt.min, tt.max, got, tt.want)
		}
	}
}

func TestTokenNgrams(t *testing.T) {
	tokens := []string{"the", "quick", "brown", "fox"}
	got := TokenNgrams(tokens, 1, 2)
	want := []string{"the", "quick", "brown", "fox", "the quick", "quick brown", "brown fox"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("TokenNgrams = %v, want %v", got, want)
	}
}

func TestNormalize(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Hello World", "hello world"},
		{"  multiple   spaces  ", " multiple spaces "},
		{"line\nbreak\rhere", "line break here"},
		{"UPPER", "upper"},
	}
	for _, tt := range tests {
		got := Normalize(tt.input)
		if got != tt.want {
			t.Errorf("Normalize(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNumberPattern(t *testing.T) {
	tests := []struct {
		input string
		ratio float64
		want  string
	}{
		{"12345", 0.3, "XXXXX"},
		{"abc123", 0.3, "CCCXXX"},
		{"abc", 0.3, ""},
		{"", 0.3, ""},
		{"12-34", 0.3, "XX-XX"},
		{"a1b2c3", 0.3, "CXCXCX"},
	}
	for _, tt := range tests {
		got := NumberPattern(tt.input, tt.ratio)
		if got != tt.want {
			t.Errorf("NumberPattern(%q, %v) = %q, want %q", tt.input, tt.ratio, got, tt.want)
		}
	}
}

func TestNormalizeWhitespaces(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello\nworld", "hello world"},
		{"hello\r\nworld", "hello world"},
		{"a  b   c", "a b c"},
	}
	for _, tt := range tests {
		got := NormalizeWhitespaces(tt.input)
		if got != tt.want {
			t.Errorf("NormalizeWhitespaces(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
