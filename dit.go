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
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/happyhackingspace/dit/captcha"
	"github.com/happyhackingspace/dit/classifier"
	"github.com/happyhackingspace/dit/internal/htmlutil"
)

// downloadTimeout bounds the total time spent fetching the model.
const downloadTimeout = 1 * time.Minute

// ModelURL is the canonical download location for the pretrained model.
const ModelURL = "https://huggingface.co/datasets/happyhackingspace/dit/resolve/main/model.json"

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

	dest := filepath.Join(ModelDir(), "model.json")
	slog.Info("Model not found, downloading", "url", ModelURL, "dest", dest)
	if err := Download(dest); err != nil {
		return nil, fmt.Errorf("dit: %w", err)
	}
	return Load(dest)
}

// Download fetches the pretrained model from ModelURL and writes it to dest,
// creating parent directories as needed. A partial file is removed on error.
func Download(dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		return fmt.Errorf("create model dir: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), downloadTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ModelURL, nil)
	if err != nil {
		return fmt.Errorf("download model: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download model: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download model: HTTP %d", resp.StatusCode)
	}

	f, err := os.Create(dest)
	if err != nil {
		return fmt.Errorf("create model file: %w", err)
	}

	written, err := io.Copy(f, resp.Body)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(dest)
		return fmt.Errorf("download model: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close model file: %w", err)
	}

	slog.Info("Model downloaded", "size", fmt.Sprintf("%.1fMB", float64(written)/1024/1024))
	return nil
}

// ModelDir returns the default model storage directory (~/.dit).
func ModelDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".dit")
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
