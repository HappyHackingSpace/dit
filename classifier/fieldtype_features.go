package classifier

import (
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/happyhackingspace/dit/internal/htmlutil"
	"github.com/happyhackingspace/dit/internal/textutil"
)

// ElemFeatures extracts per-field features for CRF classification.
func ElemFeatures(elem *goquery.Selection, form *goquery.Selection) map[string]any {
	name, _ := elem.Attr("name")
	elemName := textutil.Normalize(name)
	elemValue := normalizeAttr(elem, "value")
	elemPlaceholder := normalizeAttr(elem, "placeholder")
	elemCSSClass := normalizeAttr(elem, "class")
	elemID := normalizeAttr(elem, "id")
	elemTitle := normalizeAttr(elem, "title")

	feat := map[string]any{
		"tag":              goquery.NodeName(elem),
		"name":             textutil.Tokenize(elemName),
		"name-ngrams-3-5":  textutil.Ngrams(elemName, 3, 5),
		"value":            textutil.Ngrams(elemValue, 5, 5),
		"value-ngrams":     textutil.Ngrams(elemValue, 5, 5),
		"css-class-ngrams": textutil.Ngrams(elemCSSClass, 5, 5),
		"help":             textutil.Tokenize(elemTitle + " " + elemPlaceholder),
		"id-ngrams":        textutil.Ngrams(elemID, 4, 4),
		"id":               textutil.Tokenize(elemID),
	}

	// Label features
	label := htmlutil.FindLabel(form, elem)
	if label != nil {
		labelText := textutil.Normalize(label.Text())
		feat["label"] = textutil.Tokenize(labelText)
		feat["label-ngrams-3-5"] = textutil.Ngrams(labelText, 3, 5)
	}

	// Input type
	tag := goquery.NodeName(elem)
	if tag == "input" {
		tp, exists := elem.Attr("type")
		if !exists {
			tp = "text"
		}
		feat["input-type"] = strings.ToLower(tp)
	}

	// Select options
	if tag == "select" {
		var optTexts, optValues []string
		elem.Find("option").Each(func(i int, opt *goquery.Selection) {
			optTexts = append(optTexts, textutil.Normalize(opt.Text()))
			val, _ := opt.Attr("value")
			optValues = append(optValues, textutil.Normalize(val))
		})
		feat["option-text"] = optTexts
		feat["option-value"] = optValues

		// Number patterns
		patternSet := make(map[string]bool)
		for _, v := range append(optTexts, optValues...) {
			p := textutil.NumberPattern(v, 0.3)
			if p != "" {
				patternSet[p] = true
			}
		}
		var patterns []string
		for p := range patternSet {
			patterns = append(patterns, p)
		}
		feat["option-num-pattern"] = patterns
	}

	return feat
}

// GetFormFeatures extracts CRF feature sequences for a form.
func GetFormFeatures(form *goquery.Selection, formType string, fieldElems []*goquery.Selection) []map[string]any {
	if fieldElems == nil {
		fieldElems = htmlutil.GetFieldsToAnnotate(form)
	}

	textAround := htmlutil.GetTextAroundElems(form, fieldElems)

	res := make([]map[string]any, len(fieldElems))
	for idx, elem := range fieldElems {
		feat := ElemFeatures(elem, form)

		if idx == 0 {
			feat["is-first"] = true
		}
		if idx == len(fieldElems)-1 {
			feat["is-last"] = true
		}

		feat["form-type"] = formType

		// Text before element
		textBefore := textutil.Normalize(textAround.Before[elem])
		tokensBefore := textutil.Tokenize(textBefore)
		if len(tokensBefore) > 6 {
			tokensBefore = tokensBefore[len(tokensBefore)-6:]
		}
		feat["text-before"] = textutil.TokenNgrams(tokensBefore, 1, 2)

		// Text after element
		textAfter := textutil.Normalize(textAround.After[elem])
		tokensAfter := textutil.Tokenize(textAfter)
		if len(tokensAfter) > 5 {
			tokensAfter = tokensAfter[:5]
		}
		feat["text-after"] = textutil.TokenNgrams(tokensAfter, 1, 2)

		feat["bias"] = 1

		res[idx] = feat
	}

	return res
}

func normalizeAttr(elem *goquery.Selection, attr string) string {
	val, _ := elem.Attr(attr)
	return textutil.Normalize(val)
}
