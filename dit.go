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
	"fmt"
	"os"
	"path/filepath"

	"github.com/happyhackingspace/dit/captcha"
	"github.com/happyhackingspace/dit/classifier"
	"github.com/happyhackingspace/dit/internal/htmlutil"
)

// Classifier wraps the form and field type classification models.
type Classifier struct {
	fc *classifier.FormFieldClassifier
}

// FormResult holds the classification result for a single form.
type FormResult struct {
	Type    string            `json:"type"`
	Captcha string            `json:"captcha,omitempty"`
	Fields  map[string]string `json:"fields,omitempty"`
}

// FormResultProba holds probability-based classification results for a single form.
type FormResultProba struct {
	Type    map[string]float64            `json:"type"`
	Captcha string                        `json:"captcha,omitempty"`
	Fields  map[string]map[string]float64 `json:"fields,omitempty"`
}

// PageResult holds the page type classification result.
type PageResult struct {
	Type    string       `json:"type"`
	Captcha string       `json:"captcha,omitempty"`
	Forms   []FormResult `json:"forms,omitempty"`
}

// PageResultProba holds probability-based page type classification results.
type PageResultProba struct {
	Type    map[string]float64 `json:"type"`
	Captcha string             `json:"captcha,omitempty"`
	Forms   []FormResultProba  `json:"forms,omitempty"`
}

// New loads the classifier from "model.json", searching the current directory
// and parent directories up to the module root, then ~/.dit/model.json.
func New() (*Classifier, error) {
	path, err := FindModel("model.json")
	if err != nil {
		return nil, fmt.Errorf("dit: %w", err)
	}
	return Load(path)
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

	// Also run per-form CAPTCHA detection and merge into the output
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		return nil, fmt.Errorf("dit: %w", err)
	}
	forms := htmlutil.GetForms(doc)

	out := make([]FormResult, len(results))
	detector := &captcha.CaptchaDetector{}
	for i, r := range results {
		capType := captcha.CaptchaTypeNone
		if i < len(forms) {
			capType = detector.DetectInForm(forms[i])
		}
		capStr := ""
		if capType != captcha.CaptchaTypeNone {
			capStr = string(capType)
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

	// Also run per-form CAPTCHA detection and merge into the output
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		return nil, fmt.Errorf("dit: %w", err)
	}
	forms := htmlutil.GetForms(doc)

	out := make([]FormResultProba, len(results))
	detector := &captcha.CaptchaDetector{}
	for i, r := range results {
		capType := captcha.CaptchaTypeNone
		if i < len(forms) {
			capType = detector.DetectInForm(forms[i])
		}
		capStr := ""
		if capType != captcha.CaptchaTypeNone {
			capStr = string(capType)
		}
		out[i] = FormResultProba{
			Type:    r.Proba.Form,
			Captcha: capStr,
			Fields:  r.Proba.Fields,
		}
	}
	return out, nil
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

	// Detect page-level captcha: prefer form-level detection, fall back to full-HTML scan
	capStr := ""
	doc, docErr := htmlutil.LoadHTMLString(html)
	if docErr == nil {
		htmlForms := htmlutil.GetForms(doc)
		detector := &captcha.CaptchaDetector{}
		for _, f := range htmlForms {
			if ct := detector.DetectInForm(f); ct != captcha.CaptchaTypeNone {
				capStr = string(ct)
				break
			}
		}
	}
	if capStr == "" {
		if pageCap := captcha.DetectCaptchaInHTML(html); pageCap != captcha.CaptchaTypeNone {
			capStr = string(pageCap)
		}
	}

	return &PageResult{
		Type:    pageResult.Form,
		Captcha: capStr,
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

	// Detect page-level captcha: prefer form-level detection, fall back to full-HTML scan
	capStr := ""
	doc, docErr := htmlutil.LoadHTMLString(html)
	if docErr == nil {
		htmlForms := htmlutil.GetForms(doc)
		detector := &captcha.CaptchaDetector{}
		for _, f := range htmlForms {
			if ct := detector.DetectInForm(f); ct != captcha.CaptchaTypeNone {
				capStr = string(ct)
				break
			}
		}
	}
	if capStr == "" {
		if pageCap := captcha.DetectCaptchaInHTML(html); pageCap != captcha.CaptchaTypeNone {
			capStr = string(pageCap)
		}
	}

	return &PageResultProba{
		Type:    pageProba.Form,
		Captcha: capStr,
		Forms:   forms,
	}, nil
}
