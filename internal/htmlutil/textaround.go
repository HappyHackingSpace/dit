package htmlutil

import (
	"strings"

	"github.com/PuerkitoBio/goquery"
	"github.com/happyhackingspace/dit/internal/textutil"
	"golang.org/x/net/html"
)

// TextAround holds text before and after each element.
type TextAround struct {
	Before map[*goquery.Selection]string
	After  map[*goquery.Selection]string
}

// GetTextAroundElems returns text before and after each specified element,
// matching lxml's text/tail walk behavior from Formasaurus.
func GetTextAroundElems(root *goquery.Selection, elems []*goquery.Selection) TextAround {
	result := TextAround{
		Before: make(map[*goquery.Selection]string, len(elems)),
		After:  make(map[*goquery.Selection]string, len(elems)),
	}

	if len(elems) == 0 {
		return result
	}

	// Build a set of target html.Node pointers for quick lookup
	nodeToSel := make(map[*html.Node]*goquery.Selection, len(elems))
	for _, sel := range elems {
		if sel.Length() > 0 {
			nodeToSel[sel.Get(0)] = sel
		}
	}

	// Walk the DOM tree, accumulating text and flushing when we hit target elements.
	// This mirrors lxml's text/tail behavior:
	//   - elem.text = text content directly inside elem before first child
	//   - elem.tail = text after elem's closing tag, before next sibling
	var buf []string
	var orderedElems []*goquery.Selection

	flushBuf := func() string {
		var parts []string
		for _, b := range buf {
			trimmed := strings.TrimSpace(b)
			if trimmed != "" {
				parts = append(parts, textutil.NormalizeWhitespaces(trimmed))
			}
		}
		buf = buf[:0]
		return strings.Join(parts, "  ")
	}

	var visit func(n *html.Node)
	visit = func(n *html.Node) {
		if sel, ok := nodeToSel[n]; ok {
			// This is a target element — flush buffer as "before" text
			result.Before[sel] = flushBuf()
			orderedElems = append(orderedElems, sel)
			// Add the element's tail text (text after this element)
			return
		}

		// Regular element — collect its text content
		if n.Type == html.TextNode {
			buf = append(buf, n.Data)
			return
		}

		// Recurse into children
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			visit(c)
		}
	}

	// Start walk from root's underlying node
	rootNode := root.Get(0)
	visit(rootNode)

	// Set "after" for each element: after[elem_i] = before[elem_{i+1}]
	for i := 0; i < len(orderedElems)-1; i++ {
		result.After[orderedElems[i]] = result.Before[orderedElems[i+1]]
	}
	// Last element's "after" is remaining buffer
	if len(orderedElems) > 0 {
		result.After[orderedElems[len(orderedElems)-1]] = flushBuf()
	}

	return result
}
