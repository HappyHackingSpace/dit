package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestModelStatusMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "model.json")
	var buf bytes.Buffer
	if err := modelStatus(&buf, path); err != nil {
		t.Fatalf("modelStatus: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "path:    "+path) {
		t.Errorf("output missing path: %q", out)
	}
	if !strings.Contains(out, "exists:  false") {
		t.Errorf("output missing exists false: %q", out)
	}
	if strings.Contains(out, "sha256") {
		t.Errorf("output should not contain checksum for missing file: %q", out)
	}
}

func TestModelStatusExisting(t *testing.T) {
	content := []byte(`{"model":"test"}`)
	path := filepath.Join(t.TempDir(), "model.json")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("write model: %v", err)
	}

	var buf bytes.Buffer
	if err := modelStatus(&buf, path); err != nil {
		t.Fatalf("modelStatus: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "exists:  true") {
		t.Errorf("output missing exists true: %q", out)
	}
	if !strings.Contains(out, fmt.Sprintf("(%d bytes)", len(content))) {
		t.Errorf("output missing byte size: %q", out)
	}
	sum := sha256.Sum256(content)
	if !strings.Contains(out, "sha256:  "+hex.EncodeToString(sum[:])) {
		t.Errorf("output missing checksum: %q", out)
	}
}

func TestModelRm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "model.json")
	if err := os.WriteFile(path, []byte("data"), 0644); err != nil {
		t.Fatalf("write model: %v", err)
	}

	var buf bytes.Buffer
	if err := modelRm(&buf, path); err != nil {
		t.Fatalf("modelRm: %v", err)
	}
	if !strings.Contains(buf.String(), "Removed "+path) {
		t.Errorf("output = %q, want removal message", buf.String())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file still exists after rm, stat err = %v", err)
	}
}

func TestModelRmMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "model.json")
	var buf bytes.Buffer
	if err := modelRm(&buf, path); err != nil {
		t.Fatalf("modelRm on missing file: %v", err)
	}
	if !strings.Contains(buf.String(), "No cached model at "+path) {
		t.Errorf("output = %q, want no-model message", buf.String())
	}
}

func TestModelPullAlreadyCached(t *testing.T) {
	content := []byte("cached model")
	path := filepath.Join(t.TempDir(), "model.json")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("write model: %v", err)
	}

	var buf bytes.Buffer
	if err := modelPull(&buf, path, false); err != nil {
		t.Fatalf("modelPull: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "already cached") {
		t.Errorf("output = %q, want already-cached message", out)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read model: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("cached model modified by pull without --force")
	}
}
