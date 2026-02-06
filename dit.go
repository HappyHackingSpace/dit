// Package dit classifies HTML form and field types.
//
// It provides a two-stage ML pipeline: logistic regression for form types
// and a CRF model for field types.
//
//	c, _ := dit.New()
//	results, _ := c.ExtractForms(htmlString)
//	for _, r := range results {
//	    fmt.Println(r.Type)   // "login"
//	    fmt.Println(r.Fields) // {"username": "username or email", "password": "password"}
//	}
package dit

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/happyhackingspace/dit/classifier"
)

// Classifier wraps the form and field type classification models.
type Classifier struct {
	fc *classifier.FormFieldClassifier
}

// FormResult holds the classification result for a single form.
type FormResult struct {
	Type   string            `json:"type"`
	Fields map[string]string `json:"fields,omitempty"`
}

// FormResultProba holds probability-based classification results for a single form.
type FormResultProba struct {
	Type   map[string]float64            `json:"type"`
	Fields map[string]map[string]float64 `json:"fields,omitempty"`
}

// New loads the classifier from "model.json", searching the current directory
// and parent directories up to the module root (where go.mod lives).
func New() (*Classifier, error) {
	path, err := findModel("model.json")
	if err != nil {
		return nil, fmt.Errorf("dit: %w", err)
	}
	return Load(path)
}

func findModel(name string) (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
		// Stop at module root
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
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

	out := make([]FormResult, len(results))
	for i, r := range results {
		out[i] = FormResult{
			Type:   r.Result.Form,
			Fields: r.Result.Fields,
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

	out := make([]FormResultProba, len(results))
	for i, r := range results {
		out[i] = FormResultProba{
			Type:   r.Proba.Form,
			Fields: r.Proba.Fields,
		}
	}
	return out, nil
}
