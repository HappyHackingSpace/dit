package cli

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadInputHTML(t *testing.T) {
	html := `<html><body><form><input type="text" name="q"/></form></body></html>`

	content, target, err := readInput(strings.NewReader(html), fetchOptions{})
	if err != nil {
		t.Fatalf("readInput: %v", err)
	}
	if content != html {
		t.Errorf("expected HTML content to pass through, got %q", content)
	}
	if target != "stdin" {
		t.Errorf("expected target %q, got %q", "stdin", target)
	}
}

func TestReadInputEmpty(t *testing.T) {
	if _, _, err := readInput(strings.NewReader("  \n\t"), fetchOptions{}); err == nil {
		t.Error("expected error for empty input")
	}
}

func TestReadInputURL(t *testing.T) {
	html := `<html><body>fetched</body></html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(html))
	}))
	defer srv.Close()

	content, target, err := readInput(strings.NewReader(srv.URL+"\n"), fetchOptions{})
	if err != nil {
		t.Fatalf("readInput: %v", err)
	}
	if content != html {
		t.Errorf("expected fetched HTML, got %q", content)
	}
	if target != srv.URL {
		t.Errorf("expected target %q, got %q", srv.URL, target)
	}
}
