// Package classifier implements form and field type classification.
package classifier

import (
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/happyhackingspace/dit/internal/htmlutil"
)

// FormFeatureExtractor extracts features from a form element.
type FormFeatureExtractor interface {
	ExtractString(form *goquery.Selection) string
	ExtractDict(form *goquery.Selection) map[string]any
	IsDict() bool
}

// FormElements extracts structural boolean features from a form.
type FormElements struct{}

func (f FormElements) IsDict() bool { return true }
func (f FormElements) ExtractString(_ *goquery.Selection) string {
	return ""
}
func (f FormElements) ExtractDict(form *goquery.Selection) map[string]any {
	counts := htmlutil.GetTypeCounts(form)
	inputCount := htmlutil.GetInputCount(form)
	return map[string]any{
		"has <textarea>":                    counts["textarea"] > 0,
		"has <input type=radio>":            counts["radio"] > 0,
		"has <select>":                      counts["select"] > 0,
		"has <input type=checkbox>":         counts["checkbox"] > 0,
		"has <input type=email>":            counts["email"] > 0,
		"2 or 3 inputs":                     inputCount == 2 || inputCount == 3,
		"no <input type=password>":          counts["password"] == 0,
		"exactly one <input type=password>": counts["password"] == 1,
		"exactly two <input type=password>": counts["password"] == 2,
		"no <input type=text>":              counts["text"] == 0,
		"exactly one <input type=text>":     counts["text"] == 1,
		"exactly two <input type=text>":     counts["text"] == 2,
		"3 or more <input type=text>":       counts["text"] >= 3,
		"<form method":                      htmlutil.GetFormMethod(form),
	}
}

// SubmitText extracts submit button text.
type SubmitText struct{}

func (f SubmitText) IsDict() bool { return false }
func (f SubmitText) ExtractDict(_ *goquery.Selection) map[string]any {
	return nil
}
func (f SubmitText) ExtractString(form *goquery.Selection) string {
	return htmlutil.GetSubmitTexts(form)
}

// FormLinksText extracts link text inside the form.
type FormLinksText struct{}

func (f FormLinksText) IsDict() bool { return false }
func (f FormLinksText) ExtractDict(_ *goquery.Selection) map[string]any {
	return nil
}
func (f FormLinksText) ExtractString(form *goquery.Selection) string {
	return htmlutil.GetLinksText(form)
}

// FormLabelText extracts label text inside the form.
type FormLabelText struct{}

func (f FormLabelText) IsDict() bool { return false }
func (f FormLabelText) ExtractDict(form *goquery.Selection) map[string]any {
	return nil
}
func (f FormLabelText) ExtractString(form *goquery.Selection) string {
	return htmlutil.GetLabelText(form)
}

// FormURL extracts the form action URL (normalized).
type FormURL struct{}

func (f FormURL) IsDict() bool { return false }
func (f FormURL) ExtractDict(form *goquery.Selection) map[string]any {
	return nil
}
func (f FormURL) ExtractString(form *goquery.Selection) string {
	action := htmlutil.GetFormAction(form)
	if action == "" {
		return ""
	}
	// Add scheme if missing
	if !strings.Contains(action, "//") {
		action = "http://" + action
	}
	u, err := url.Parse(action)
	if err != nil {
		return action
	}
	path := normalizeURLPart(u.Path)
	params := normalizeURLPart(u.RawQuery)
	query := normalizeURLPart(u.RawQuery)
	fragment := normalizeURLPart(u.Fragment)
	return path + params + query + "#" + fragment
}

func normalizeURLPart(part string) string {
	part = strings.ReplaceAll(part, "/", "")
	part = strings.ReplaceAll(part, "_", "")
	part = strings.ReplaceAll(part, "-", "")
	return part
}

// FormCSS extracts form CSS class and ID.
type FormCSS struct{}

func (f FormCSS) IsDict() bool { return false }
func (f FormCSS) ExtractDict(form *goquery.Selection) map[string]any {
	return nil
}
func (f FormCSS) ExtractString(form *goquery.Selection) string {
	return htmlutil.GetFormCSS(form)
}

// FormInputCSS extracts CSS of non-hidden inputs.
type FormInputCSS struct{}

func (f FormInputCSS) IsDict() bool { return false }
func (f FormInputCSS) ExtractDict(form *goquery.Selection) map[string]any {
	return nil
}
func (f FormInputCSS) ExtractString(form *goquery.Selection) string {
	return htmlutil.GetInputCSS(form)
}

// FormInputNames extracts names of non-hidden inputs.
type FormInputNames struct{}

func (f FormInputNames) IsDict() bool { return false }
func (f FormInputNames) ExtractDict(form *goquery.Selection) map[string]any {
	return nil
}
func (f FormInputNames) ExtractString(form *goquery.Selection) string {
	return htmlutil.GetInputNames(form)
}

// FormInputTitle extracts title attributes of non-hidden inputs.
type FormInputTitle struct{}

func (f FormInputTitle) IsDict() bool { return false }
func (f FormInputTitle) ExtractDict(form *goquery.Selection) map[string]any {
	return nil
}
func (f FormInputTitle) ExtractString(form *goquery.Selection) string {
	return htmlutil.GetInputTitles(form)
}

// DefaultFeaturePipelines returns the 9 feature extraction pipelines
// matching Formasaurus's FEATURES list.
func DefaultFeaturePipelines() []FeaturePipeline {
	return []FeaturePipeline{
		{Name: "form elements", Extractor: FormElements{}, VecType: "dict"},
		{Name: "submit text", Extractor: SubmitText{}, VecType: "count", NgramRange: [2]int{1, 2}, MinDF: 1, Binary: true, Analyzer: "word"},
		{Name: "links text", Extractor: FormLinksText{}, VecType: "tfidf", NgramRange: [2]int{1, 2}, MinDF: 4, Binary: true, Analyzer: "word", StopWords: map[string]bool{"and": true, "or": true, "of": true}},
		{Name: "label text", Extractor: FormLabelText{}, VecType: "tfidf", NgramRange: [2]int{1, 2}, MinDF: 3, Binary: true, Analyzer: "word", StopWords: nil, UseEnglishStop: true},
		{Name: "form url", Extractor: FormURL{}, VecType: "tfidf", NgramRange: [2]int{5, 6}, MinDF: 4, Binary: true, Analyzer: "char_wb"},
		{Name: "form css", Extractor: FormCSS{}, VecType: "tfidf", NgramRange: [2]int{4, 5}, MinDF: 3, Binary: true, Analyzer: "char_wb"},
		{Name: "input css", Extractor: FormInputCSS{}, VecType: "tfidf", NgramRange: [2]int{4, 5}, MinDF: 5, Binary: true, Analyzer: "char_wb"},
		{Name: "input names", Extractor: FormInputNames{}, VecType: "tfidf", NgramRange: [2]int{5, 6}, MinDF: 3, Binary: true, Analyzer: "char_wb"},
		{Name: "input title", Extractor: FormInputTitle{}, VecType: "tfidf", NgramRange: [2]int{5, 6}, MinDF: 3, Binary: true, Analyzer: "char_wb"},
	}
}

// FeaturePipeline describes a feature extraction + vectorization pipeline.
type FeaturePipeline struct {
	Name           string
	Extractor      FormFeatureExtractor
	VecType        string // "dict", "count", "tfidf"
	NgramRange     [2]int
	MinDF          int
	Binary         bool
	Analyzer       string
	StopWords      map[string]bool
	UseEnglishStop bool
}
