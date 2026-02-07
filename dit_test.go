package dit

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const loginFormHTML = `<html><body>
<form method="POST" action="/login">
  <label for="user">Username</label>
  <input type="text" name="username" id="user"/>
  <label for="pass">Password</label>
  <input type="password" name="password" id="pass"/>
  <input type="submit" value="Log In"/>
</form>
</body></html>`

func buildBinary(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	binary := filepath.Join(tmpDir, "dit")

	cmd := exec.Command("go", "build", "-o", binary, "./cmd/dit")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build binary: %v\n%s", err, output)
	}

	return binary
}

func TestFunctional_RunStdin(t *testing.T) {
	binary := buildBinary(t)

	cmd := exec.Command(binary, "run", "-s")
	cmd.Stdin = strings.NewReader(loginFormHTML)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("Functional test failed: %v\nStderr: %s", err, stderr.String())
	}

	var results []struct {
		Type   string            `json:"type"`
		Fields map[string]string `json:"fields"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		t.Fatalf("Output is not valid JSON: %v\nOutput: %s", err, stdout.String())
	}

	if len(results) == 0 {
		t.Fatal("No forms found in output")
	}
}

func TestFunctional_RunStdinURL(t *testing.T) {
	binary := buildBinary(t)

	// Simulating: echo "https://github.com/login" | dit run
	cmd := exec.Command(binary, "run", "-s")
	cmd.Stdin = strings.NewReader("https://github.com/login")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("Functional URL test failed: %v\nStderr: %s", err, stderr.String())
	}

	var results []struct {
		Type   string            `json:"type"`
		Fields map[string]string `json:"fields"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		t.Fatalf("Output is not valid JSON: %v\nOutput: %s", err, stdout.String())
	}

	if len(results) == 0 {
		t.Fatal("No forms found in output from URL pipe")
	}
}

func TestExtractForms(t *testing.T) {
	modelPath := "model.json"
	if _, err := os.Stat(modelPath); os.IsNotExist(err) {
		t.Skip("model.json not found, skipping")
	}

	c, err := Load(modelPath)
	if err != nil {
		t.Fatal(err)
	}

	results, err := c.ExtractForms(loginFormHTML)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 form, got %d", len(results))
	}
	if results[0].Type == "" {
		t.Error("expected non-empty form type")
	}
	if results[0].Fields == nil {
		t.Error("expected non-nil fields")
	}
}

func TestExtractFormsProba(t *testing.T) {
	modelPath := "model.json"
	if _, err := os.Stat(modelPath); os.IsNotExist(err) {
		t.Skip("model.json not found, skipping")
	}

	c, err := Load(modelPath)
	if err != nil {
		t.Fatal(err)
	}

	results, err := c.ExtractFormsProba(loginFormHTML, 0.05)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 form, got %d", len(results))
	}
	if len(results[0].Type) == 0 {
		t.Error("expected non-empty type probabilities")
	}
}

func TestExtractFormsNoForms(t *testing.T) {
	modelPath := "model.json"
	if _, err := os.Stat(modelPath); os.IsNotExist(err) {
		t.Skip("model.json not found, skipping")
	}

	c, err := Load(modelPath)
	if err != nil {
		t.Fatal(err)
	}

	results, err := c.ExtractForms("<html><body>No forms here</body></html>")
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 0 {
		t.Errorf("expected 0 results, got %d", len(results))
	}
}

func TestLoadNonExistent(t *testing.T) {
	_, err := Load("nonexistent.json")
	if err == nil {
		t.Error("expected error for nonexistent model")
	}
}

func TestClassifierNotInitialized(t *testing.T) {
	c := &Classifier{}
	_, err := c.ExtractForms(loginFormHTML)
	if err == nil {
		t.Error("expected error for uninitialized classifier")
	}
}
