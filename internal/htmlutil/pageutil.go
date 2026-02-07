package htmlutil

import (
	"maps"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// GetPageTitle returns the <title> text content.
func GetPageTitle(doc *goquery.Document) string {
	return strings.TrimSpace(doc.Find("title").First().Text())
}

// GetMetaDescription returns the content of <meta name="description">.
func GetMetaDescription(doc *goquery.Document) string {
	content, _ := doc.Find(`meta[name="description"]`).Attr("content")
	if content == "" {
		content, _ = doc.Find(`meta[name="Description"]`).Attr("content")
	}
	return strings.TrimSpace(content)
}

// GetMetaKeywords returns the content of <meta name="keywords">.
func GetMetaKeywords(doc *goquery.Document) string {
	content, _ := doc.Find(`meta[name="keywords"]`).Attr("content")
	if content == "" {
		content, _ = doc.Find(`meta[name="Keywords"]`).Attr("content")
	}
	return strings.TrimSpace(content)
}

// GetMetaRobots returns the content of <meta name="robots">.
func GetMetaRobots(doc *goquery.Document) string {
	content, _ := doc.Find(`meta[name="robots"]`).Attr("content")
	return strings.TrimSpace(content)
}

// GetHeadings returns concatenated text of all h1-h6 elements.
func GetHeadings(doc *goquery.Document) string {
	var parts []string
	doc.Find("h1, h2, h3, h4, h5, h6").Each(func(_ int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		if text != "" {
			parts = append(parts, text)
		}
	})
	return strings.Join(parts, " ")
}

// GetH1Text returns concatenated text of all <h1> elements.
func GetH1Text(doc *goquery.Document) string {
	var parts []string
	doc.Find("h1").Each(func(_ int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		if text != "" {
			parts = append(parts, text)
		}
	})
	return strings.Join(parts, " ")
}

// GetNavText returns concatenated text of all <nav> elements.
func GetNavText(doc *goquery.Document) string {
	var parts []string
	doc.Find("nav").Each(func(_ int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		if text != "" {
			parts = append(parts, text)
		}
	})
	return strings.Join(parts, " ")
}

// GetPageLinkTexts returns concatenated text of all <a> elements.
func GetPageLinkTexts(doc *goquery.Document) string {
	var parts []string
	doc.Find("a").Each(func(_ int, s *goquery.Selection) {
		text := strings.TrimSpace(s.Text())
		if text != "" {
			parts = append(parts, text)
		}
	})
	return strings.Join(parts, " ")
}

// GetBodyText returns visible text from the body, truncated for feature extraction.
func GetBodyText(doc *goquery.Document, maxLen int) string {
	text := strings.TrimSpace(doc.Find("body").Text())
	// Collapse whitespace
	fields := strings.Fields(text)
	text = strings.Join(fields, " ")
	if maxLen > 0 && len(text) > maxLen {
		text = text[:maxLen]
	}
	return text
}

// GetPageCSS returns class and id attributes from <body> and <main> elements.
func GetPageCSS(doc *goquery.Document) string {
	var parts []string
	doc.Find("body, main").Each(func(_ int, s *goquery.Selection) {
		if class, exists := s.Attr("class"); exists && class != "" {
			parts = append(parts, class)
		}
		if id, exists := s.Attr("id"); exists && id != "" {
			parts = append(parts, id)
		}
	})
	return strings.Join(parts, " ")
}

// GetPageStructure returns structural boolean features and counts about the page.
func GetPageStructure(doc *goquery.Document) map[string]any {
	features := make(map[string]any)

	formCount := doc.Find("form").Length()
	features["has_form"] = boolToFloat(formCount > 0)
	features["form_count"] = float64(formCount)
	features["has_nav"] = boolToFloat(doc.Find("nav").Length() > 0)
	features["has_header"] = boolToFloat(doc.Find("header").Length() > 0)
	features["has_footer"] = boolToFloat(doc.Find("footer").Length() > 0)
	features["has_article"] = boolToFloat(doc.Find("article").Length() > 0)
	features["has_aside"] = boolToFloat(doc.Find("aside").Length() > 0)
	features["has_main"] = boolToFloat(doc.Find("main").Length() > 0)
	features["has_table"] = boolToFloat(doc.Find("table").Length() > 0)
	features["has_video"] = boolToFloat(doc.Find("video").Length() > 0)
	features["has_iframe"] = boolToFloat(doc.Find("iframe").Length() > 0)

	// Password field indicates login/registration
	features["has_password"] = boolToFloat(doc.Find(`input[type="password"]`).Length() > 0)

	// Link count
	linkCount := doc.Find("a").Length()
	features["link_count_bucket"] = linkCountBucket(linkCount)

	// Image count
	imgCount := doc.Find("img").Length()
	features["img_count_bucket"] = imgCountBucket(imgCount)

	// Content length bucket
	bodyText := doc.Find("body").Text()
	features["content_length_bucket"] = contentLengthBucket(len(bodyText))

	// Heading count
	features["heading_count"] = float64(doc.Find("h1, h2, h3, h4, h5, h6").Length())

	// Error indicators (merged in)
	maps.Copy(features, GetErrorIndicators(doc))

	return features
}

// GetErrorIndicators returns features for detecting error/soft-404/special pages.
func GetErrorIndicators(doc *goquery.Document) map[string]any {
	features := make(map[string]any)

	title := strings.ToLower(GetPageTitle(doc))
	h1 := strings.ToLower(GetH1Text(doc))
	bodyText := strings.ToLower(doc.Find("body").Text())

	// Limit body text scan to first 5000 chars for performance
	if len(bodyText) > 5000 {
		bodyText = bodyText[:5000]
	}

	patterns := []struct {
		name    string
		keyword string
	}{
		{"404", "404"},
		{"not_found", "not found"},
		{"page_not_found", "page not found"},
		{"does_not_exist", "does not exist"},
		{"no_longer_available", "no longer available"},
		{"access_denied", "access denied"},
		{"forbidden", "forbidden"},
		{"unauthorized", "unauthorized"},
		{"server_error", "server error"},
		{"internal_error", "internal server error"},
		{"captcha", "captcha"},
		{"cloudflare", "cloudflare"},
		{"challenge", "challenge"},
		{"verify_human", "verify you are human"},
		{"domain_parking", "domain parking"},
		{"parked_domain", "parked domain"},
		{"coming_soon", "coming soon"},
		{"under_construction", "under construction"},
		{"maintenance", "maintenance"},
		{"launching_soon", "launching soon"},
		{"welcome_nginx", "welcome to nginx"},
		{"apache_default", "apache2 default page"},
		{"iis_default", "iis windows server"},
		{"index_of", "index of /"},
		{"directory_listing", "directory listing"},
		{"waf_block", "blocked"},
		{"bot_detection", "bot"},
		{"admin_panel", "admin"},
		{"dashboard", "dashboard"},
		{"login", "log in"},
		{"sign_in", "sign in"},
	}

	for _, p := range patterns {
		features["title_has_"+p.name] = boolToFloat(strings.Contains(title, p.keyword))
		features["h1_has_"+p.name] = boolToFloat(strings.Contains(h1, p.keyword))
		features["body_has_"+p.name] = boolToFloat(strings.Contains(bodyText, p.keyword))
	}

	return features
}

func boolToFloat(b bool) float64 {
	if b {
		return 1.0
	}
	return 0.0
}

func linkCountBucket(n int) float64 {
	switch {
	case n == 0:
		return 0
	case n <= 5:
		return 1
	case n <= 20:
		return 2
	case n <= 50:
		return 3
	default:
		return 4
	}
}

func imgCountBucket(n int) float64 {
	switch {
	case n == 0:
		return 0
	case n <= 3:
		return 1
	case n <= 10:
		return 2
	default:
		return 3
	}
}

func contentLengthBucket(n int) float64 {
	switch {
	case n < 100:
		return 0
	case n < 500:
		return 1
	case n < 2000:
		return 2
	case n < 10000:
		return 3
	default:
		return 4
	}
}
