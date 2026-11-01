package dit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func TestDownloadModelWritesFile(t *testing.T) {
	content := []byte(`{"model":"test"}`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "model.json")
	sum, err := downloadModel(srv.URL, dest, "", nil)
	if err != nil {
		t.Fatalf("downloadModel: %v", err)
	}
	if want := sha256Hex(content); sum != want {
		t.Errorf("checksum = %s, want %s", sum, want)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("file content = %q, want %q", got, content)
	}
}

func TestDownloadModelCreatesParentDirs(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("data"))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "nested", "dir", "model.json")
	if _, err := downloadModel(srv.URL, dest, "", nil); err != nil {
		t.Fatalf("downloadModel: %v", err)
	}
	if _, err := os.Stat(dest); err != nil {
		t.Errorf("downloaded file missing: %v", err)
	}
}

func TestDownloadModelPinnedChecksumMatch(t *testing.T) {
	content := []byte("verified model data")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "model.json")
	sum, err := downloadModel(srv.URL, dest, sha256Hex(content), nil)
	if err != nil {
		t.Fatalf("downloadModel with matching pin: %v", err)
	}
	if want := sha256Hex(content); sum != want {
		t.Errorf("checksum = %s, want %s", sum, want)
	}
}

func TestDownloadModelPinnedChecksumCaseInsensitive(t *testing.T) {
	content := []byte("verified model data")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "model.json")
	if _, err := downloadModel(srv.URL, dest, strings.ToUpper(sha256Hex(content)), nil); err != nil {
		t.Fatalf("downloadModel with uppercase pin: %v", err)
	}
}

func TestDownloadModelChecksumMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tampered data"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "model.json")
	wrongSum := strings.Repeat("ab", 32)
	_, err := downloadModel(srv.URL, dest, wrongSum, nil)
	if err == nil {
		t.Fatal("expected checksum mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("error = %v, want checksum mismatch", err)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Errorf("expected no file at dest after mismatch, stat err = %v", statErr)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected empty dir after mismatch, found %d entries", len(entries))
	}
}

func TestDownloadModelHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "model.json")
	_, err := downloadModel(srv.URL, dest, "", nil)
	if err == nil {
		t.Fatal("expected HTTP error, got nil")
	}
	if !strings.Contains(err.Error(), "HTTP 404") {
		t.Errorf("error = %v, want HTTP 404", err)
	}
	if _, statErr := os.Stat(dest); !os.IsNotExist(statErr) {
		t.Errorf("expected no file at dest after HTTP error, stat err = %v", statErr)
	}
}

func TestDownloadModelDoesNotOverwriteOnFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("bad data"))
	}))
	defer srv.Close()

	dest := filepath.Join(t.TempDir(), "model.json")
	existing := []byte("existing good model")
	if err := os.WriteFile(dest, existing, 0644); err != nil {
		t.Fatalf("write existing: %v", err)
	}

	wrongSum := strings.Repeat("cd", 32)
	if _, err := downloadModel(srv.URL, dest, wrongSum, nil); err == nil {
		t.Fatal("expected checksum mismatch error, got nil")
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if !bytes.Equal(got, existing) {
		t.Errorf("existing file was overwritten on failed download")
	}
}

func TestDownloadModelProgress(t *testing.T) {
	content := bytes.Repeat([]byte("x"), 4096)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprint(len(content)))
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	var progress bytes.Buffer
	dest := filepath.Join(t.TempDir(), "model.json")
	if _, err := downloadModel(srv.URL, dest, "", &progress); err != nil {
		t.Fatalf("downloadModel: %v", err)
	}
	out := progress.String()
	if !strings.Contains(out, "Downloading model:") {
		t.Errorf("progress output missing header: %q", out)
	}
	if !strings.Contains(out, "(100%)") {
		t.Errorf("progress output missing final percentage: %q", out)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("progress output should end with newline: %q", out)
	}
}

func TestProgressWriterUnknownTotal(t *testing.T) {
	var buf bytes.Buffer
	pw := newProgressWriter(&buf, -1)
	if _, err := pw.Write(bytes.Repeat([]byte("y"), 2048)); err != nil {
		t.Fatalf("Write: %v", err)
	}
	pw.finish()
	out := buf.String()
	if !strings.Contains(out, "Downloading model: 0.0 MB") {
		t.Errorf("progress output = %q, want byte count without percentage", out)
	}
	if strings.Contains(out, "%") {
		t.Errorf("progress output should not contain percentage when total unknown: %q", out)
	}
}

func TestProgressWriterNilWriter(t *testing.T) {
	pw := newProgressWriter(nil, 100)
	if _, err := pw.Write([]byte("data")); err != nil {
		t.Fatalf("Write with nil writer: %v", err)
	}
	pw.finish()
}

func TestFileSHA256(t *testing.T) {
	content := []byte("checksum me")
	path := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	sum, err := FileSHA256(path)
	if err != nil {
		t.Fatalf("FileSHA256: %v", err)
	}
	if want := sha256Hex(content); sum != want {
		t.Errorf("FileSHA256 = %s, want %s", sum, want)
	}

	if _, err := FileSHA256(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestDefaultModelPath(t *testing.T) {
	path := DefaultModelPath()
	if filepath.Base(path) != "model.json" {
		t.Errorf("DefaultModelPath = %q, want model.json basename", path)
	}
	if filepath.Dir(path) != ModelDir() {
		t.Errorf("DefaultModelPath dir = %q, want %q", filepath.Dir(path), ModelDir())
	}
}
