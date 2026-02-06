// Package htmlutil provides HTML form and field extraction utilities.
package htmlutil

import (
	"io"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// LoadHTML parses HTML bytes into a goquery Document.
func LoadHTML(r io.Reader) (*goquery.Document, error) {
	return goquery.NewDocumentFromReader(r)
}

// LoadHTMLString parses HTML string into a goquery Document.
func LoadHTMLString(htmlStr string) (*goquery.Document, error) {
	return goquery.NewDocumentFromReader(strings.NewReader(htmlStr))
}

// GetForms returns all <form> elements in the document.
func GetForms(doc *goquery.Document) []*goquery.Selection {
	var forms []*goquery.Selection
	doc.Find("form").Each(func(_ int, s *goquery.Selection) {
		forms = append(forms, s)
	})
	return forms
}

// GetVisibleFields returns visible form fields (textarea, select, button, non-hidden inputs).
func GetVisibleFields(form *goquery.Selection) []*goquery.Selection {
	var fields []*goquery.Selection
	form.Find("textarea, select, button, input").Each(func(_ int, s *goquery.Selection) {
		if goquery.NodeName(s) == "input" {
			tp, exists := s.Attr("type")
			if exists && strings.EqualFold(tp, "hidden") {
				return
			}
		}
		fields = append(fields, s)
	})
	return fields
}

// GetFieldsToAnnotate returns visible fields with non-empty name attribute.
func GetFieldsToAnnotate(form *goquery.Selection) []*goquery.Selection {
	visible := GetVisibleFields(form)
	var result []*goquery.Selection
	for _, f := range visible {
		if name, _ := f.Attr("name"); name != "" {
			result = append(result, f)
		}
	}
	return result
}

// GetTypeCounts returns counts of different input types in a form.
func GetTypeCounts(form *goquery.Selection) map[string]int {
	counts := make(map[string]int)
	form.Find("input, textarea, select").Each(func(_ int, s *goquery.Selection) {
		tag := goquery.NodeName(s)
		switch tag {
		case "textarea":
			counts["textarea"]++
		case "select":
			counts["select"]++
		case "input":
			tp, exists := s.Attr("type")
			if !exists {
				tp = "text"
			}
			counts[strings.ToLower(tp)]++
		}
	})
	return counts
}

// GetInputCount returns the number of named input elements (matching lxml form.inputs.keys()).
func GetInputCount(form *goquery.Selection) int {
	seen := make(map[string]bool)
	form.Find("input, textarea, select").Each(func(_ int, s *goquery.Selection) {
		if name, _ := s.Attr("name"); name != "" {
			seen[name] = true
		}
	})
	return len(seen)
}

// FindLabel finds the <label> element associated with a form field.
// It checks for label[for=id] or ancestor <label>.
func FindLabel(form *goquery.Selection, elem *goquery.Selection) *goquery.Selection {
	// Try matching by for=id
	if id, exists := elem.Attr("id"); exists && id != "" {
		label := form.Find("label[for=\"" + id + "\"]")
		if label.Length() > 0 {
			return label.First()
		}
	}

	// Try ancestor <label>
	parent := elem.Closest("label")
	if parent.Length() > 0 {
		return parent
	}

	return nil
}

// GetFormMethod returns the form's method attribute, lowercased.
func GetFormMethod(form *goquery.Selection) string {
	method, _ := form.Attr("method")
	method = strings.ToLower(strings.TrimSpace(method))
	if method == "" {
		return "MISSING"
	}
	return method
}

// GetFormAction returns the form's action attribute.
func GetFormAction(form *goquery.Selection) string {
	action, _ := form.Attr("action")
	return action
}

// GetSubmitTexts returns the values of all <input type="submit"> elements.
func GetSubmitTexts(form *goquery.Selection) string {
	var texts []string
	form.Find("input[type=\"submit\"]").Each(func(i int, s *goquery.Selection) {
		if val, exists := s.Attr("value"); exists {
			texts = append(texts, val)
		}
	})
	return strings.Join(texts, " ")
}

// GetLinksText returns text of all links inside the form.
func GetLinksText(form *goquery.Selection) string {
	var texts []string
	form.Find("a").Each(func(i int, s *goquery.Selection) {
		texts = append(texts, s.Text())
	})
	return strings.Join(texts, " ")
}

// GetLabelText returns text of all <label> elements in the form.
func GetLabelText(form *goquery.Selection) string {
	var texts []string
	form.Find("label").Each(func(i int, s *goquery.Selection) {
		texts = append(texts, s.Text())
	})
	return strings.Join(texts, " ")
}

// GetInputNames returns names of all non-hidden <input> elements, cleaned up.
func GetInputNames(form *goquery.Selection) string {
	var names []string
	form.Find("input").Each(func(i int, s *goquery.Selection) {
		tp, _ := s.Attr("type")
		if strings.EqualFold(tp, "hidden") {
			return
		}
		if name, exists := s.Attr("name"); exists {
			name = strings.ReplaceAll(name, "_", "")
			name = strings.ReplaceAll(name, "[", "")
			name = strings.ReplaceAll(name, "]", "")
			names = append(names, name)
		}
	})
	return strings.Join(names, " ")
}

// GetFormCSS returns the form's class and id attributes.
func GetFormCSS(form *goquery.Selection) string {
	class, _ := form.Attr("class")
	id, _ := form.Attr("id")
	return class + " " + id
}

// GetInputCSS returns CSS classes and IDs of non-hidden input elements.
func GetInputCSS(form *goquery.Selection) string {
	var parts []string
	form.Find("input").Each(func(i int, s *goquery.Selection) {
		tp, _ := s.Attr("type")
		if strings.EqualFold(tp, "hidden") {
			return
		}
		class, _ := s.Attr("class")
		id, _ := s.Attr("id")
		parts = append(parts, class+" "+id)
	})
	return strings.Join(parts, " ")
}

// GetInputTitles returns title attributes of non-hidden input elements.
func GetInputTitles(form *goquery.Selection) string {
	var titles []string
	form.Find("input").Each(func(i int, s *goquery.Selection) {
		tp, _ := s.Attr("type")
		if strings.EqualFold(tp, "hidden") {
			return
		}
		if title, exists := s.Attr("title"); exists {
			titles = append(titles, title)
		}
	})
	return strings.Join(titles, " ")
}

// GetAllFormText returns all text content inside the form.
func GetAllFormText(form *goquery.Selection) string {
	return form.Text()
}
