package classifier

import (
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/happyhackingspace/dit/internal/htmlutil"
)

// FormFieldClassifier detects HTML form and field types.
type FormFieldClassifier struct {
	FormModel  *FormTypeModel
	FieldModel *FieldTypeModel
}

// ClassifyResult holds the classification result for a form.
type ClassifyResult struct {
	Form   string            `json:"form"`
	Fields map[string]string `json:"fields,omitempty"`
}

// ClassifyProbaResult holds probability-based classification results.
type ClassifyProbaResult struct {
	Form   map[string]float64            `json:"form"`
	Fields map[string]map[string]float64 `json:"fields,omitempty"`
}

// Classify returns the form type and field types.
func (c *FormFieldClassifier) Classify(form *goquery.Selection, fields bool) ClassifyResult {
	formType := c.FormModel.Classify(form)
	result := ClassifyResult{Form: formType}
	if fields && c.FieldModel != nil {
		result.Fields = c.FieldModel.Classify(form, formType)
	}
	return result
}

// ClassifyProba returns probabilities for form and field types.
func (c *FormFieldClassifier) ClassifyProba(form *goquery.Selection, threshold float64, fields bool) ClassifyProbaResult {
	formProba := c.FormModel.ClassifyProba(form)
	filtered := thresholdMap(formProba, threshold)
	result := ClassifyProbaResult{Form: filtered}

	if fields && c.FieldModel != nil {
		// Use most likely form type for field classification
		bestFormType := ""
		bestProb := -1.0
		for cls, prob := range formProba {
			if prob > bestProb {
				bestProb = prob
				bestFormType = cls
			}
		}
		fieldProba := c.FieldModel.ClassifyProba(form, bestFormType)
		result.Fields = make(map[string]map[string]float64)
		for name, probs := range fieldProba {
			result.Fields[name] = thresholdMap(probs, threshold)
		}
	}

	return result
}

// ExtractForms extracts and classifies all forms from HTML.
func (c *FormFieldClassifier) ExtractForms(htmlStr string, proba bool, threshold float64, classifyFields bool) ([]FormResult, error) {
	doc, err := htmlutil.LoadHTMLString(htmlStr)
	if err != nil {
		return nil, err
	}

	forms := htmlutil.GetForms(doc)
	results := make([]FormResult, len(forms))

	for i, form := range forms {
		results[i].FormHTML, _ = form.Html()
		if proba {
			results[i].Proba = c.ClassifyProba(form, threshold, classifyFields)
		} else {
			results[i].Result = c.Classify(form, classifyFields)
		}
	}

	return results, nil
}

// ExtractFormsFromReader extracts and classifies forms from an io.Reader.
func (c *FormFieldClassifier) ExtractFormsFromReader(r *strings.Reader, proba bool, threshold float64, classifyFields bool) ([]FormResult, error) {
	doc, err := htmlutil.LoadHTML(r)
	if err != nil {
		return nil, err
	}

	forms := htmlutil.GetForms(doc)
	results := make([]FormResult, len(forms))

	for i, form := range forms {
		results[i].FormHTML, _ = form.Html()
		if proba {
			results[i].Proba = c.ClassifyProba(form, threshold, classifyFields)
		} else {
			results[i].Result = c.Classify(form, classifyFields)
		}
	}

	return results, nil
}

// FormResult holds the result for a single form.
type FormResult struct {
	FormHTML string              `json:"form_html"`
	Result   ClassifyResult      `json:"result,omitempty"`
	Proba    ClassifyProbaResult `json:"proba,omitempty"`
}

func thresholdMap(m map[string]float64, threshold float64) map[string]float64 {
	if threshold <= 0 {
		return m
	}
	result := make(map[string]float64)
	for k, v := range m {
		if v >= threshold {
			result[k] = v
		}
	}
	return result
}
