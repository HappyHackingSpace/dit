// Package dit classifies HTML form, field, and page types.
//
// It provides a three-stage ML pipeline: logistic regression for form types,
// a CRF model for field types, and logistic regression for page types.
//
//	c, _ := dit.New()
//	results, _ := c.ExtractForms(htmlString)
//	for _, r := range results {
//	    fmt.Println(r.Type)   // "login"
//	    fmt.Println(r.Fields) // {"username": "username or email", "password": "password"}
//	}
//
//	page, _ := c.ExtractPageType(htmlString)
//	fmt.Println(page.Type) // "login"
package dit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/happyhackingspace/dit/captcha"
	"github.com/happyhackingspace/dit/classifier"
	"github.com/happyhackingspace/dit/internal/htmlutil"
)

// downloadTimeout bounds the total time spent fetching the model.
// The model is ~93MB, so allow for slow connections.
const downloadTimeout = 10 * time.Minute

// ModelURL is the canonical download location for the pretrained model.
const ModelURL = "https://huggingface.co/datasets/happyhackingspace/dit/resolve/main/model.json"

// ModelSHA256 is the pinned hex-encoded SHA-256 checksum of the model served
// at ModelURL. When non-empty, Download verifies the fetched file against it
// and fails on mismatch.
//
// TODO: pin the published checksum of model.json. While empty, verification
// is skipped: the computed checksum is logged with a warning instead so it
// can be copied here.
const ModelSHA256 = ""

// Classifier wraps the form and field type classification models.
type Classifier struct {
	fc *classifier.FormFieldClassifier
}

// FormResult holds the classification result for a single form.
type FormResult struct {
	Type    string            `json:"type"`
	Captcha string            `json:"captcha_type,omitempty"`
	Fields  map[string]string `json:"fields,omitempty"`
}

// FormResultProba holds probability-based classification results for a single form.
type FormResultProba struct {
	Type    map[string]float64            `json:"type"`
	Captcha string                        `json:"captcha_type,omitempty"`
	Fields  map[string]map[string]float64 `json:"fields,omitempty"`
}

// PageResult holds the page type classification result.
type PageResult struct {
	Type    string       `json:"type"`
	Captcha string       `json:"captcha_type,omitempty"`
	Forms   []FormResult `json:"forms,omitempty"`
}

// PageResultProba holds probability-based page type classification results.
type PageResultProba struct {
	Type    map[string]float64 `json:"type"`
	Captcha string             `json:"captcha_type,omitempty"`
	Forms   []FormResultProba  `json:"forms,omitempty"`
}

// New loads the classifier from "model.json", searching the current directory
// and parent directories up to the module root, then ~/.dit/model.json.
// If no model is found locally, it is downloaded from ModelURL to
// ~/.dit/model.json and loaded from there. The download is a one-time cost
// per machine; subsequent calls reuse the cached file.
func New() (*Classifier, error) {
	if path, err := FindModel("model.json"); err == nil {
		return Load(path)
	}

	dest := DefaultModelPath()
	slog.Info("Model not found, downloading", "url", ModelURL, "dest", dest, "size", "~93MB")
	if err := Download(dest); err != nil {
		return nil, fmt.Errorf("dit: %w", err)
	}
	return Load(dest)
}

// Download fetches the pretrained model from ModelURL and writes it to dest,
// creating parent directories as needed. Progress is reported to stderr. The
// file is written to a temporary path and renamed into place only after the
// download completes and, when ModelSHA256 is set, its checksum matches, so
// a partial or corrupt file is never left at dest.
func Download(dest string) error {
	_, err := downloadModel(ModelURL, dest, ModelSHA256, os.Stderr)
	return err
}

// downloadModel fetches url into dest, streaming progress to progress and
// returning the hex-encoded SHA-256 checksum of the downloaded file. When
// pinnedSHA256 is non-empty the checksum must match or the download fails;
// when empty, the computed checksum is logged with a warning.
func downloadModel(url, dest, pinnedSHA256 string, progress io.Writer) (string, error) {
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("create model dir: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), downloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("download model: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download model: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download model: HTTP %d", resp.StatusCode)
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(dest)+".*.partial")
	if err != nil {
		return "", fmt.Errorf("create model file: %w", err)
	}

	hash := sha256.New()
	pw := newProgressWriter(progress, resp.ContentLength)
	written, err := io.Copy(io.MultiWriter(tmp, hash, pw), resp.Body)
	pw.finish()
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", fmt.Errorf("download model: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", fmt.Errorf("close model file: %w", err)
	}

	sum := hex.EncodeToString(hash.Sum(nil))
	switch {
	case pinnedSHA256 == "":
		slog.Warn("No pinned model checksum; skipping verification", "sha256", sum)
	case !strings.EqualFold(sum, pinnedSHA256):
		_ = os.Remove(tmp.Name())
		return "", fmt.Errorf("model checksum mismatch: got %s, want %s", sum, pinnedSHA256)
	}

	if err := os.Rename(tmp.Name(), dest); err != nil {
		_ = os.Remove(tmp.Name())
		return "", fmt.Errorf("move model file: %w", err)
	}

	slog.Info("Model downloaded", "size", fmt.Sprintf("%.1fMB", float64(written)/1024/1024), "sha256", sum)
	return sum, nil
}

// progressWriter reports byte-count progress to an io.Writer as data passes
// through it.
type progressWriter struct {
	w       io.Writer
	total   int64
	written int64
	lastAt  time.Time
}

// progressInterval throttles progress updates.
const progressInterval = 200 * time.Millisecond

func newProgressWriter(w io.Writer, total int64) *progressWriter {
	return &progressWriter{w: w, total: total}
}

// Write implements io.Writer and never fails.
func (p *progressWriter) Write(b []byte) (int, error) {
	p.written += int64(len(b))
	if time.Since(p.lastAt) >= progressInterval {
		p.report()
	}
	return len(b), nil
}

func (p *progressWriter) report() {
	if p.w == nil {
		return
	}
	p.lastAt = time.Now()
	mb := float64(p.written) / 1024 / 1024
	if p.total > 0 {
		pct := float64(p.written) / float64(p.total) * 100
		_, _ = fmt.Fprintf(p.w, "\rDownloading model: %.1f/%.1f MB (%.0f%%)", mb, float64(p.total)/1024/1024, pct)
	} else {
		_, _ = fmt.Fprintf(p.w, "\rDownloading model: %.1f MB", mb)
	}
}

// finish prints the final progress line followed by a newline.
func (p *progressWriter) finish() {
	if p.w == nil {
		return
	}
	p.report()
	_, _ = fmt.Fprintln(p.w)
}

// FileSHA256 returns the hex-encoded SHA-256 checksum of the file at path.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ModelDir returns the default model storage directory (~/.dit).
func ModelDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".dit")
}

// DefaultModelPath returns the default cached model location
// (~/.dit/model.json), the destination of implicit first-run downloads and
// of "dit model pull".
func DefaultModelPath() string {
	return filepath.Join(ModelDir(), "model.json")
}

// FindModel searches for a model file by name.
// Search order: current dir walk-up to module root, then ~/.dit/.
func FindModel(name string) (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	// Check ~/.dit/
	if modelDir := ModelDir(); modelDir != "" {
		path := filepath.Join(modelDir, name)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("model.json not found")
}

// Load loads a trained classifier from a model file.
func Load(path string) (*Classifier, error) {
	fc, err := classifier.LoadClassifier(path)
	if err != nil {
		return nil, fmt.Errorf("dit: %w", err)
	}
	return &Classifier{fc: fc}, nil
}

// Save writes the classifier to a model file.
func (c *Classifier) Save(path string) error {
	if c.fc == nil {
		return fmt.Errorf("dit: classifier not initialized")
	}
	if err := c.fc.SaveModel(path); err != nil {
		return fmt.Errorf("dit: %w", err)
	}
	return nil
}

// ExtractForms extracts and classifies all forms in the given HTML string.
// Returns an empty slice (not nil) if no forms are found.
func (c *Classifier) ExtractForms(html string) ([]FormResult, error) {
	if c.fc == nil || c.fc.FormModel == nil {
		return nil, fmt.Errorf("dit: classifier not initialized")
	}

	results, err := c.fc.ExtractForms(html, false, 0, true)
	if err != nil {
		return nil, fmt.Errorf("dit: %w", err)
	}

	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		return nil, fmt.Errorf("dit: %w", err)
	}
	forms := htmlutil.GetForms(doc)

	out := make([]FormResult, len(results))
	detector := &captcha.CaptchaDetector{}
	for i, r := range results {
		capStr := ""
		if i < len(forms) {
			if ct := detector.DetectInForm(forms[i]); ct != captcha.CaptchaTypeNone {
				capStr = string(ct)
			}
		}
		out[i] = FormResult{
			Type:    r.Result.Form,
			Captcha: capStr,
			Fields:  r.Result.Fields,
		}
	}
	return out, nil
}

// ExtractFormsProba extracts forms and returns classification probabilities.
// Probabilities below threshold are omitted.
func (c *Classifier) ExtractFormsProba(html string, threshold float64) ([]FormResultProba, error) {
	if c.fc == nil || c.fc.FormModel == nil {
		return nil, fmt.Errorf("dit: classifier not initialized")
	}

	results, err := c.fc.ExtractForms(html, true, threshold, true)
	if err != nil {
		return nil, fmt.Errorf("dit: %w", err)
	}

	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		return nil, fmt.Errorf("dit: %w", err)
	}
	forms := htmlutil.GetForms(doc)

	out := make([]FormResultProba, len(results))
	detector := &captcha.CaptchaDetector{}
	for i, r := range results {
		capStr := ""
		if i < len(forms) {
			if ct := detector.DetectInForm(forms[i]); ct != captcha.CaptchaTypeNone {
				capStr = string(ct)
			}
		}
		out[i] = FormResultProba{
			Type:    r.Proba.Form,
			Captcha: capStr,
			Fields:  r.Proba.Fields,
		}
	}
	return out, nil
}

// detectPageCaptcha detects page-level CAPTCHA by first checking each form
// and falling back to a full-HTML scan.
func detectPageCaptcha(htmlStr string) string {
	doc, err := htmlutil.LoadHTMLString(htmlStr)
	if err == nil {
		detector := &captcha.CaptchaDetector{}
		for _, f := range htmlutil.GetForms(doc) {
			if ct := detector.DetectInForm(f); ct != captcha.CaptchaTypeNone {
				return string(ct)
			}
		}
	}
	if ct := captcha.DetectCaptchaInHTML(htmlStr); ct != captcha.CaptchaTypeNone {
		return string(ct)
	}
	return ""
}

// ExtractPageType classifies the page type and all forms in the HTML.
func (c *Classifier) ExtractPageType(html string) (*PageResult, error) {
	if c.fc == nil || c.fc.FormModel == nil {
		return nil, fmt.Errorf("dit: classifier not initialized")
	}
	if c.fc.PageModel == nil {
		return nil, fmt.Errorf("dit: page model not available")
	}

	formResults, pageResult, _, err := c.fc.ExtractPage(html, false, 0, true)
	if err != nil {
		return nil, fmt.Errorf("dit: %w", err)
	}

	forms := make([]FormResult, len(formResults))
	for i, r := range formResults {
		forms[i] = FormResult{
			Type:   r.Result.Form,
			Fields: r.Result.Fields,
		}
	}

	return &PageResult{
		Type:    pageResult.Form,
		Captcha: detectPageCaptcha(html),
		Forms:   forms,
	}, nil
}

// ExtractPageTypeProba classifies the page type with probabilities.
func (c *Classifier) ExtractPageTypeProba(html string, threshold float64) (*PageResultProba, error) {
	if c.fc == nil || c.fc.FormModel == nil {
		return nil, fmt.Errorf("dit: classifier not initialized")
	}
	if c.fc.PageModel == nil {
		return nil, fmt.Errorf("dit: page model not available")
	}

	formResults, _, pageProba, err := c.fc.ExtractPage(html, true, threshold, true)
	if err != nil {
		return nil, fmt.Errorf("dit: %w", err)
	}

	forms := make([]FormResultProba, len(formResults))
	for i, r := range formResults {
		forms[i] = FormResultProba{
			Type:   r.Proba.Form,
			Fields: r.Proba.Fields,
		}
	}

	return &PageResultProba{
		Type:    pageProba.Form,
		Captcha: detectPageCaptcha(html),
		Forms:   forms,
	}, nil
}
