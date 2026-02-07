package classifier

import (
	"net/url"
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/happyhackingspace/dit/internal/htmlutil"
)

// PageFeatureExtractor extracts features from a page document.
type PageFeatureExtractor interface {
	ExtractString(doc *goquery.Document, formResults []ClassifyResult) string
	ExtractDict(doc *goquery.Document, formResults []ClassifyResult) map[string]any
	IsDict() bool
}

// PageFeaturePipeline describes a page feature extraction + vectorization pipeline.
type PageFeaturePipeline struct {
	Name           string
	Extractor      PageFeatureExtractor
	VecType        string // "dict", "tfidf"
	NgramRange     [2]int
	MinDF          int
	Binary         bool
	Analyzer       string
	StopWords      map[string]bool
	UseEnglishStop bool
}

// --- Concrete extractors ---

// PageStructureExtractor extracts structural features + error indicators.
type PageStructureExtractor struct{}

func (e PageStructureExtractor) IsDict() bool { return true }
func (e PageStructureExtractor) ExtractString(_ *goquery.Document, _ []ClassifyResult) string {
	return ""
}
func (e PageStructureExtractor) ExtractDict(doc *goquery.Document, _ []ClassifyResult) map[string]any {
	return htmlutil.GetPageStructure(doc)
}

// PageTitleExtractor extracts <title> text.
type PageTitleExtractor struct{}

func (e PageTitleExtractor) IsDict() bool { return false }
func (e PageTitleExtractor) ExtractDict(_ *goquery.Document, _ []ClassifyResult) map[string]any {
	return nil
}
func (e PageTitleExtractor) ExtractString(doc *goquery.Document, _ []ClassifyResult) string {
	return htmlutil.GetPageTitle(doc)
}

// PageMetaDescriptionExtractor extracts <meta name="description"> content.
type PageMetaDescriptionExtractor struct{}

func (e PageMetaDescriptionExtractor) IsDict() bool { return false }
func (e PageMetaDescriptionExtractor) ExtractDict(_ *goquery.Document, _ []ClassifyResult) map[string]any {
	return nil
}
func (e PageMetaDescriptionExtractor) ExtractString(doc *goquery.Document, _ []ClassifyResult) string {
	return htmlutil.GetMetaDescription(doc)
}

// PageHeadingsExtractor extracts all h1-h6 text concatenated.
type PageHeadingsExtractor struct{}

func (e PageHeadingsExtractor) IsDict() bool { return false }
func (e PageHeadingsExtractor) ExtractDict(_ *goquery.Document, _ []ClassifyResult) map[string]any {
	return nil
}
func (e PageHeadingsExtractor) ExtractString(doc *goquery.Document, _ []ClassifyResult) string {
	return htmlutil.GetHeadings(doc)
}

// PageH1Extractor extracts <h1> text.
type PageH1Extractor struct{}

func (e PageH1Extractor) IsDict() bool { return false }
func (e PageH1Extractor) ExtractDict(_ *goquery.Document, _ []ClassifyResult) map[string]any {
	return nil
}
func (e PageH1Extractor) ExtractString(doc *goquery.Document, _ []ClassifyResult) string {
	return htmlutil.GetH1Text(doc)
}

// PageCSSExtractor extracts body/main class and id attributes.
type PageCSSExtractor struct{}

func (e PageCSSExtractor) IsDict() bool { return false }
func (e PageCSSExtractor) ExtractDict(_ *goquery.Document, _ []ClassifyResult) map[string]any {
	return nil
}
func (e PageCSSExtractor) ExtractString(doc *goquery.Document, _ []ClassifyResult) string {
	return htmlutil.GetPageCSS(doc)
}

// PageNavTextExtractor extracts <nav> text.
type PageNavTextExtractor struct{}

func (e PageNavTextExtractor) IsDict() bool { return false }
func (e PageNavTextExtractor) ExtractDict(_ *goquery.Document, _ []ClassifyResult) map[string]any {
	return nil
}
func (e PageNavTextExtractor) ExtractString(doc *goquery.Document, _ []ClassifyResult) string {
	return htmlutil.GetNavText(doc)
}

// FormTypeSummaryExtractor extracts features from form classification results.
type FormTypeSummaryExtractor struct{}

func (e FormTypeSummaryExtractor) IsDict() bool { return true }
func (e FormTypeSummaryExtractor) ExtractString(_ *goquery.Document, _ []ClassifyResult) string {
	return ""
}
func (e FormTypeSummaryExtractor) ExtractDict(_ *goquery.Document, formResults []ClassifyResult) map[string]any {
	features := map[string]any{
		"form_count":    float64(len(formResults)),
		"has_any_form":  boolToPageFloat(len(formResults) > 0),
		"dominant_type": "none",
	}

	typeCounts := make(map[string]int)
	for _, r := range formResults {
		typeCounts[r.Form]++
	}

	// Per-type boolean features
	knownTypes := []string{
		"login", "registration", "search", "password/login recovery",
		"contact/comment", "mailing list", "order/checkout", "other",
	}
	for _, tp := range knownTypes {
		key := "has_" + strings.ReplaceAll(strings.ReplaceAll(tp, "/", "_"), " ", "_") + "_form"
		features[key] = boolToPageFloat(typeCounts[tp] > 0)
	}

	// Dominant form type
	if len(formResults) > 0 {
		maxCount := 0
		dominant := ""
		for tp, count := range typeCounts {
			if count > maxCount {
				maxCount = count
				dominant = tp
			}
		}
		features["dominant_type"] = dominant
	}

	return features
}

// PageBodyTextExtractor extracts visible body text (first 2000 chars).
type PageBodyTextExtractor struct{}

func (e PageBodyTextExtractor) IsDict() bool { return false }
func (e PageBodyTextExtractor) ExtractDict(_ *goquery.Document, _ []ClassifyResult) map[string]any {
	return nil
}
func (e PageBodyTextExtractor) ExtractString(doc *goquery.Document, _ []ClassifyResult) string {
	return htmlutil.GetBodyText(doc, 2000)
}

// PageURLExtractor extracts URL path patterns.
type PageURLExtractor struct {
	URL string // set per-document before extraction
}

func (e PageURLExtractor) IsDict() bool { return false }
func (e PageURLExtractor) ExtractDict(_ *goquery.Document, _ []ClassifyResult) map[string]any {
	return nil
}
func (e PageURLExtractor) ExtractString(_ *goquery.Document, _ []ClassifyResult) string {
	if e.URL == "" {
		return ""
	}
	u, err := url.Parse(e.URL)
	if err != nil {
		return e.URL
	}
	return normalizeURLPart(u.Path) + " " + normalizeURLPart(u.RawQuery)
}

// DefaultPageFeaturePipelines returns the 9 page feature extraction pipelines.
func DefaultPageFeaturePipelines() []PageFeaturePipeline {
	return []PageFeaturePipeline{
		{Name: "page structure", Extractor: PageStructureExtractor{}, VecType: "dict"},
		{Name: "page title", Extractor: PageTitleExtractor{}, VecType: "tfidf", NgramRange: [2]int{1, 2}, MinDF: 2, Binary: true, Analyzer: "word"},
		{Name: "page meta desc", Extractor: PageMetaDescriptionExtractor{}, VecType: "tfidf", NgramRange: [2]int{1, 2}, MinDF: 2, Binary: true, Analyzer: "word"},
		{Name: "page headings", Extractor: PageHeadingsExtractor{}, VecType: "tfidf", NgramRange: [2]int{1, 2}, MinDF: 2, Binary: true, Analyzer: "word"},
		{Name: "page h1", Extractor: PageH1Extractor{}, VecType: "tfidf", NgramRange: [2]int{1, 2}, MinDF: 2, Binary: true, Analyzer: "word"},
		{Name: "page css", Extractor: PageCSSExtractor{}, VecType: "tfidf", NgramRange: [2]int{4, 5}, MinDF: 2, Binary: true, Analyzer: "char_wb"},
		{Name: "page nav text", Extractor: PageNavTextExtractor{}, VecType: "tfidf", NgramRange: [2]int{1, 2}, MinDF: 2, Binary: true, Analyzer: "word"},
		{Name: "form type summary", Extractor: FormTypeSummaryExtractor{}, VecType: "dict"},
		{Name: "page body text", Extractor: PageBodyTextExtractor{}, VecType: "tfidf", NgramRange: [2]int{1, 2}, MinDF: 3, Binary: true, Analyzer: "word", UseEnglishStop: true},
		{Name: "page url", Extractor: PageURLExtractor{}, VecType: "tfidf", NgramRange: [2]int{5, 6}, MinDF: 2, Binary: true, Analyzer: "char_wb"},
	}
}

func boolToPageFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}
