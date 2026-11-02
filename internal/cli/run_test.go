package cli

import (
	"reflect"
	"strings"
	"testing"
)

func TestReadURLList(t *testing.T) {
	input := `https://example.com/login

# a comment
  https://example.org/signup
https://example.net/search
`
	urls, err := readURLList(strings.NewReader(input))
	if err != nil {
		t.Fatalf("readURLList: %v", err)
	}
	want := []string{
		"https://example.com/login",
		"https://example.org/signup",
		"https://example.net/search",
	}
	if !reflect.DeepEqual(urls, want) {
		t.Errorf("expected %v, got %v", want, urls)
	}
}

func TestReadURLListEmpty(t *testing.T) {
	urls, err := readURLList(strings.NewReader("\n# only comments\n\n"))
	if err != nil {
		t.Fatalf("readURLList: %v", err)
	}
	if len(urls) != 0 {
		t.Errorf("expected no URLs, got %v", urls)
	}
}
