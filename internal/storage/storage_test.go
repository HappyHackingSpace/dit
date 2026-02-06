package storage

import "testing"

func TestGetDomain(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"http://example.org/page", "example"},
		{"https://foo.example.co.uk/path", "example"},
		{"http://www.google.com", "google"},
		{"example.org", "example"},
		{"http://localhost:8080/path", "localhost"},
	}
	for _, tt := range tests {
		got := GetDomain(tt.url)
		if got != tt.want {
			t.Errorf("GetDomain(%q) = %q, want %q", tt.url, got, tt.want)
		}
	}
}
