package captcha

import (
	"regexp"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

// CaptchaType represents a detected CAPTCHA type
type CaptchaType string

const (
	// Known providers
	CaptchaTypeNone               CaptchaType = "none"
	CaptchaTypeRecaptcha          CaptchaType = "recaptcha"
	CaptchaTypeRecaptchaV2        CaptchaType = "recaptchav2"
	CaptchaTypeRecaptchaInvisible CaptchaType = "recaptcha-invisible"
	CaptchaTypeHCaptcha           CaptchaType = "hcaptcha"
	CaptchaTypeTurnstile          CaptchaType = "turnstile"
	CaptchaTypeGeetest            CaptchaType = "geetest"
	CaptchaTypeFriendlyCaptcha    CaptchaType = "friendlycaptcha"
	CaptchaTypeRotateCaptcha      CaptchaType = "rotatecaptcha"
	CaptchaTypeClickCaptcha       CaptchaType = "clickcaptcha"
	CaptchaTypeImageCaptcha       CaptchaType = "imagecaptcha"
	CaptchaTypePuzzleCaptcha      CaptchaType = "puzzlecaptcha"
	CaptchaTypeSliderCaptcha      CaptchaType = "slidercaptcha"
	CaptchaTypeMCaptcha           CaptchaType = "mcaptcha"
	CaptchaTypeDatadome           CaptchaType = "datadome"
	CaptchaTypePerimeterX         CaptchaType = "perimeterx"
	CaptchaTypeArgon              CaptchaType = "argon"
	CaptchaTypeBehaviotech        CaptchaType = "behaviotech"
	CaptchaTypeSmartCaptcha       CaptchaType = "smartcaptcha"
	CaptchaTypeYandex             CaptchaType = "yandex"
	CaptchaTypeFuncaptcha         CaptchaType = "funcaptcha"
	CaptchaTypeKasada             CaptchaType = "kasada"
	CaptchaTypeImperva            CaptchaType = "imperva"
	CaptchaTypeAwsWaf             CaptchaType = "awswaf"
	CaptchaTypeCoingecko          CaptchaType = "wsiz"
	CaptchaTypeNovaScape          CaptchaType = "novascape"
	CaptchaTypeSimple             CaptchaType = "simplecaptcha"
	CaptchaTypeOther              CaptchaType = "other"
)

// String returns the string representation of CaptchaType
func (ct CaptchaType) String() string { return string(ct) }

// IsValidCaptchaType reports whether the provided string maps to a known CaptchaType
func IsValidCaptchaType(s string) bool {
	switch s {
	case string(CaptchaTypeNone),
		string(CaptchaTypeRecaptcha),
		string(CaptchaTypeRecaptchaV2),
		string(CaptchaTypeRecaptchaInvisible),
		string(CaptchaTypeHCaptcha),
		string(CaptchaTypeTurnstile),
		string(CaptchaTypeGeetest),
		string(CaptchaTypeFriendlyCaptcha),
		string(CaptchaTypeRotateCaptcha),
		string(CaptchaTypeClickCaptcha),
		string(CaptchaTypeImageCaptcha),
		string(CaptchaTypePuzzleCaptcha),
		string(CaptchaTypeSliderCaptcha),
		string(CaptchaTypeMCaptcha),
		string(CaptchaTypeDatadome),
		string(CaptchaTypePerimeterX),
		string(CaptchaTypeArgon),
		string(CaptchaTypeBehaviotech),
		string(CaptchaTypeSmartCaptcha),
		string(CaptchaTypeYandex),
		string(CaptchaTypeFuncaptcha),
		string(CaptchaTypeKasada),
		string(CaptchaTypeImperva),
		string(CaptchaTypeAwsWaf),
		string(CaptchaTypeCoingecko),
		string(CaptchaTypeNovaScape),
		string(CaptchaTypeSimple),
		string(CaptchaTypeOther):
		return true
	default:
		return false
	}
}

// CaptchaDetector detects CAPTCHA protection in forms using multi-layer detection
type CaptchaDetector struct{}

// DetectInForm detects CAPTCHA in a form element using comprehensive detection methods
func (cd *CaptchaDetector) DetectInForm(form *goquery.Selection) CaptchaType {
	// Layer 1: Class-based detection (most specific and reliable)
	if captcha := detectByClasses(form); captcha != CaptchaTypeNone {
		return captcha
	}

	// Layer 2: Domain-based detection (script src attributes)
	if captcha := detectByScriptDomain(form); captcha != CaptchaTypeNone {
		return captcha
	}

	// Layer 3: Data attributes (be specific to avoid false positives)
	if captcha := detectByDataAttributes(form); captcha != CaptchaTypeNone {
		return captcha
	}

	// Layer 4: Element IDs and alt-text detection
	if captcha := detectByIDsAndAlt(form); captcha != CaptchaTypeNone {
		return captcha
	}

	// Layer 5: Field names (detect simple/text CAPTCHAs by input name)
	if captcha := detectByFieldNames(form); captcha != CaptchaTypeNone {
		return captcha
	}

	// Layer 6: Iframe-based detection
	if captcha := detectByIframe(form); captcha != CaptchaTypeNone {
		return captcha
	}

	// Layer 7: Generic markers
	if hasGenericCaptchaMarkers(form) {
		return CaptchaTypeOther
	}

	return CaptchaTypeNone
}

// detectByScriptDomain checks script src attributes for known CAPTCHA provider domains
func detectByScriptDomain(form *goquery.Selection) CaptchaType {
	// Get all scripts in the form and parent document
	scriptPatterns := []struct {
		captchaType CaptchaType
		patterns    []*regexp.Regexp
	}{
		{CaptchaTypeRecaptcha, []*regexp.Regexp{
			regexp.MustCompile(`google\.com/recaptcha`),
			regexp.MustCompile(`recaptcha.*\.js`),
			regexp.MustCompile(`gstatic\.com/.*recaptcha`),
		}},
		{CaptchaTypeRecaptchaV2, []*regexp.Regexp{
			regexp.MustCompile(`recaptcha.*v2`),
			regexp.MustCompile(`recaptcha/api\.js`),
		}},
		{CaptchaTypeRecaptchaInvisible, []*regexp.Regexp{
			regexp.MustCompile(`recaptcha.*invisible`),
			regexp.MustCompile(`grecaptcha\.render.*invisible`),
		}},
		{CaptchaTypeHCaptcha, []*regexp.Regexp{
			regexp.MustCompile(`js\.hcaptcha\.com`),
			regexp.MustCompile(`hcaptcha`),
		}},
		{CaptchaTypeTurnstile, []*regexp.Regexp{
			regexp.MustCompile(`challenges\.cloudflare\.com`),
			regexp.MustCompile(`js\.cloudflare\.com.*turnstile`),
		}},
		{CaptchaTypeGeetest, []*regexp.Regexp{
			regexp.MustCompile(`geetest`),
			regexp.MustCompile(`api\.geetest\.com`),
		}},
		{CaptchaTypeFriendlyCaptcha, []*regexp.Regexp{
			regexp.MustCompile(`friendlycaptcha`),
			regexp.MustCompile(`cdn\.friendlycaptcha\.com`),
		}},
		{CaptchaTypeRotateCaptcha, []*regexp.Regexp{
			regexp.MustCompile(`api\.rotatecaptcha\.com`),
		}},
		{CaptchaTypeClickCaptcha, []*regexp.Regexp{
			regexp.MustCompile(`assets\.clickcaptcha\.com`),
		}},
		{CaptchaTypeImageCaptcha, []*regexp.Regexp{
			regexp.MustCompile(`api\.imagecaptcha\.com`),
		}},
		{CaptchaTypePuzzleCaptcha, []*regexp.Regexp{
			regexp.MustCompile(`puzzle.*captcha`),
		}},
		{CaptchaTypeSliderCaptcha, []*regexp.Regexp{
			regexp.MustCompile(`slider.*captcha`),
			regexp.MustCompile(`api\.slidercaptcha\.com`),
			regexp.MustCompile(`slidercaptcha\.com`),
		}},
		{CaptchaTypeDatadome, []*regexp.Regexp{
			regexp.MustCompile(`datadome\.co`),
			regexp.MustCompile(`cdn\.mxpnl\.com`),
		}},
		{CaptchaTypePerimeterX, []*regexp.Regexp{
			regexp.MustCompile(`perimeterx\.net`),
		}},
		{CaptchaTypeArgon, []*regexp.Regexp{
			regexp.MustCompile(`argon.*captcha`),
			regexp.MustCompile(`captcha\.argon`),
		}},
		{CaptchaTypeBehaviotech, []*regexp.Regexp{
			regexp.MustCompile(`behaviotech\.com`),
		}},
		{CaptchaTypeSmartCaptcha, []*regexp.Regexp{
			regexp.MustCompile(`captcha\.yandex\.com`),
			regexp.MustCompile(`smartcaptcha\.yandex`),
		}},
		{CaptchaTypeYandex, []*regexp.Regexp{
			regexp.MustCompile(`yandex\.com/.*captcha`),
			regexp.MustCompile(`captcha\.yandex`),
			regexp.MustCompile(`smartcaptcha\.yandex`),
		}},
		{CaptchaTypeFuncaptcha, []*regexp.Regexp{
			regexp.MustCompile(`funcaptcha\.com`),
			regexp.MustCompile(`api\.funcaptcha\.com`),
		}},
		{CaptchaTypeCoingecko, []*regexp.Regexp{
			regexp.MustCompile(`wsiz\.com`),
		}},
		{CaptchaTypeNovaScape, []*regexp.Regexp{
			regexp.MustCompile(`novascape\.com`),
		}},
		{CaptchaTypeMCaptcha, []*regexp.Regexp{
			regexp.MustCompile(`mcaptcha`),
			regexp.MustCompile(`app\.mcaptcha\.io`),
		}},
		{CaptchaTypeKasada, []*regexp.Regexp{
			regexp.MustCompile(`kasada`),
			regexp.MustCompile(`kas\.kasadaproducts\.com`),
		}},
		{CaptchaTypeImperva, []*regexp.Regexp{
			regexp.MustCompile(`/_Incapsula_Resource`),
			regexp.MustCompile(`incapsula`),
			regexp.MustCompile(`imperva`),
		}},
		{CaptchaTypeAwsWaf, []*regexp.Regexp{
			regexp.MustCompile(`/aws-waf-captcha/`),
			regexp.MustCompile(`awswaf\.com`),
			regexp.MustCompile(`captcha\.aws\.amazon\.com`),
		}},
	}

	var scriptSrcs []string
	form.Find("script").Each(func(_ int, s *goquery.Selection) {
		if src, ok := s.Attr("src"); ok {
			scriptSrcs = append(scriptSrcs, strings.ToLower(src))
		}
	})

	// Check for parent scripts too
	form.Parents().First().Find("script").Each(func(_ int, s *goquery.Selection) {
		if src, ok := s.Attr("src"); ok {
			scriptSrcs = append(scriptSrcs, strings.ToLower(src))
		}
	})

	// Match scripts against patterns
	for _, entry := range scriptPatterns {
		captchaType := entry.captchaType
		patterns := entry.patterns
		for _, src := range scriptSrcs {
			for _, pattern := range patterns {
				if pattern.MatchString(src) {
					return captchaType
				}
			}
		}
	}

	return CaptchaTypeNone
}

// The rest of the helper functions are ported verbatim from the original implementation.
// detectByDataAttributes checks for CAPTCHA-specific data attributes (less common, more specific patterns)
func detectByDataAttributes(form *goquery.Selection) CaptchaType {
	html, _ := form.Html()
	htmlLower := strings.ToLower(html)

	dataAttrPatterns := []struct {
		captchaType CaptchaType
		patterns    []string
	}{
		{CaptchaTypeKasada, []string{"data-kasada", "kasada"}},
		{CaptchaTypeImperva, []string{"data-incapsula", "data-imperva"}},
		{CaptchaTypeDatadome, []string{"data-datadome", "dd-challenge"}},
		{CaptchaTypePerimeterX, []string{"data-px", "_pxappid"}},
		{CaptchaTypeMCaptcha, []string{"data-mcaptcha"}},
		{CaptchaTypeSmartCaptcha, []string{"data-smartcaptcha", "smartcaptcha"}},
	}

	for _, entry := range dataAttrPatterns {
		captchaType := entry.captchaType
		patterns := entry.patterns
		for _, p := range patterns {
			if strings.Contains(htmlLower, p) {
				return captchaType
			}
		}
	}

	return CaptchaTypeNone
}

func detectByClasses(form *goquery.Selection) CaptchaType {
	html, _ := form.Html()
	htmlLower := strings.ToLower(html)

	classPatterns := []struct {
		captchaType CaptchaType
		patterns    []string
	}{
		{CaptchaTypeRecaptcha, []string{"g-recaptcha", "grecaptcha"}},
		{CaptchaTypeRecaptchaV2, []string{"g-recaptcha-v2", "grecaptcha-v2"}},
		{CaptchaTypeRecaptchaInvisible, []string{"g-recaptcha-invisible", "grecaptcha-invisible"}},
		{CaptchaTypeHCaptcha, []string{"h-captcha", "hcaptcha"}},
		{CaptchaTypeTurnstile, []string{"cf-turnstile", "turnstile"}},
		{CaptchaTypeGeetest, []string{"geetest_", "geetest-box", "gee-test"}},
		{CaptchaTypeFriendlyCaptcha, []string{"frc-captcha", "friendlycaptcha"}},
		{CaptchaTypeMCaptcha, []string{"mcaptcha", "mcaptcha-container"}},
		{CaptchaTypeKasada, []string{"kas", "kasada"}},
		{CaptchaTypeImperva, []string{"_inc", "incapsula", "imperva"}},
		{CaptchaTypeAwsWaf, []string{"aws-waf", "awswaf"}},
		{CaptchaTypeDatadome, []string{"dd-challenge", "dd-top"}},
		{CaptchaTypePerimeterX, []string{"_px3", "px-container"}},
		{CaptchaTypeSmartCaptcha, []string{"smart-captcha", "smartcaptcha"}},
		{CaptchaTypeArgon, []string{"argon-captcha", "argon"}},
		{CaptchaTypePuzzleCaptcha, []string{"puzzle-captcha", "__puzzle_captcha"}},
		{CaptchaTypeYandex, []string{"smartcaptcha", "yandex-captcha"}},
		{CaptchaTypeFuncaptcha, []string{"funcaptcha-container"}},
	}

	for _, entry := range classPatterns {
		captchaType := entry.captchaType
		classes := entry.patterns
		for _, class := range classes {
			if strings.Contains(htmlLower, class) {
				return captchaType
			}
		}
	}

	return CaptchaTypeNone
}

// detectByIDsAndAlt checks element IDs and img alt attributes for captcha type hints
func detectByIDsAndAlt(form *goquery.Selection) CaptchaType {
	// Check element IDs
	idPatterns := []struct {
		captchaType CaptchaType
		patterns    []string
	}{
		{CaptchaTypeGeetest, []string{"geetest", "gt-captcha", "embed-captcha"}},
		{CaptchaTypeRecaptcha, []string{"recaptcha"}},
		{CaptchaTypeHCaptcha, []string{"hcaptcha", "h-captcha"}},
		{CaptchaTypeTurnstile, []string{"cf-turnstile", "turnstile"}},
		{CaptchaTypeFuncaptcha, []string{"funcaptcha", "arkose"}},
	}

	form.Find("[id]").Each(func(_ int, s *goquery.Selection) {
		if id, ok := s.Attr("id"); ok {
			idLower := strings.ToLower(id)
			for i, entry := range idPatterns {
				for _, p := range entry.patterns {
					if strings.Contains(idLower, p) {
						// Mark this entry so we can return it after the loop
						idPatterns[i].patterns = []string{"__matched__"}
						return
					}
				}
			}
		}
	})
	for _, entry := range idPatterns {
		if len(entry.patterns) == 1 && entry.patterns[0] == "__matched__" {
			return entry.captchaType
		}
	}

	// Check img alt attributes for captcha type hints
	altPatterns := []struct {
		captchaType CaptchaType
		pattern     string
	}{
		{CaptchaTypeRotateCaptcha, "rotatecaptcha"},
		{CaptchaTypeClickCaptcha, "clickcaptcha"},
		{CaptchaTypeImageCaptcha, "imagecaptcha"},
		{CaptchaTypePuzzleCaptcha, "puzzlecaptcha"},
		{CaptchaTypeSliderCaptcha, "slidercaptcha"},
		{CaptchaTypeSimple, "textcaptcha"},
		{CaptchaTypeSimple, "text-captcha"},
	}

	altResult := CaptchaTypeNone
	form.Find("img[alt]").Each(func(_ int, s *goquery.Selection) {
		if altResult != CaptchaTypeNone {
			return
		}
		if alt, ok := s.Attr("alt"); ok {
			altLower := strings.ToLower(alt)
			for _, entry := range altPatterns {
				if strings.Contains(altLower, entry.pattern) {
					altResult = entry.captchaType
					return
				}
			}
		}
	})
	if altResult != CaptchaTypeNone {
		return altResult
	}

	return CaptchaTypeNone
}

func detectByFieldNames(form *goquery.Selection) CaptchaType {
	html, _ := form.Html()
	htmlLower := strings.ToLower(html)

	// Specific checks for scripted puzzle markers
	if strings.Contains(htmlLower, "__puzzle_captcha") || strings.Contains(htmlLower, "puzzle-captcha") {
		return CaptchaTypePuzzleCaptcha
	}

	simpleCaptchaPatterns := []string{
		"simplecaptcha",
		"captcha_code",
		"captcha_input",
		"verify_code",
		"verification_code",
		"security_code",
		"text_captcha",
		"captcha_result",
	}

	for _, pattern := range simpleCaptchaPatterns {
		if strings.Contains(htmlLower, pattern) {
			return CaptchaTypeSimple
		}
	}

	return CaptchaTypeNone
}

func detectByIframe(form *goquery.Selection) CaptchaType {
	var iframeSrcs []string
	form.Find("iframe").Each(func(_ int, s *goquery.Selection) {
		if src, ok := s.Attr("src"); ok {
			iframeSrcs = append(iframeSrcs, strings.ToLower(src))
		}
	})

	iframePatterns := []struct {
		captchaType CaptchaType
		patterns    []string
	}{
		{CaptchaTypeRecaptcha, []string{"google.com/recaptcha", "www.google.com/recaptcha"}},
		{CaptchaTypeHCaptcha, []string{"hcaptcha.com"}},
		{CaptchaTypeTurnstile, []string{"cloudflare.com/turnstile"}},
		{CaptchaTypeFuncaptcha, []string{"funcaptcha"}},
		{CaptchaTypeYandex, []string{"yandex", "smartcaptcha"}},
	}

	for _, entry := range iframePatterns {
		captchaType := entry.captchaType
		patterns := entry.patterns
		for _, src := range iframeSrcs {
			for _, p := range patterns {
				if strings.Contains(src, p) {
					return captchaType
				}
			}
		}
	}

	return CaptchaTypeNone
}

func hasGenericCaptchaMarkers(form *goquery.Selection) bool {
	html, _ := form.Html()
	htmlLower := strings.ToLower(html)

	genericMarkers := []string{"captcha", "g-recaptcha", "h-captcha", "turnstile", "geetest"}
	for _, m := range genericMarkers {
		if strings.Contains(htmlLower, m) {
			return true
		}
	}
	return false
}

// DetectCaptchaInHTML performs a best-effort detection on a full HTML string.
// It uses regex patterns that require captcha keywords to appear in integration
// contexts (script src, class/id attributes, data-sitekey, iframes) rather than
// bare mentions in navigation links or text content.
func DetectCaptchaInHTML(html string) CaptchaType {
	htmlLower := strings.ToLower(html)

	// Patterns that match actual captcha integration markers, not just keyword mentions.
	// Each regex requires the keyword to appear in a meaningful context like:
	//   - script src URLs
	//   - CSS class or id attributes
	//   - data-sitekey or data-* attributes
	//   - iframe src URLs
	//   - specific captcha API domains
	integrationPatterns := []struct {
		captchaType CaptchaType
		patterns    []*regexp.Regexp
	}{
		{CaptchaTypeRecaptchaInvisible, []*regexp.Regexp{
			regexp.MustCompile(`class="[^"]*g-recaptcha-invisible`),
			regexp.MustCompile(`data-size="invisible"`),
		}},
		{CaptchaTypeRecaptchaV2, []*regexp.Regexp{
			regexp.MustCompile(`class="[^"]*g-recaptcha-v2`),
		}},
		{CaptchaTypeRecaptcha, []*regexp.Regexp{
			regexp.MustCompile(`src="[^"]*google\.com/recaptcha`),
			regexp.MustCompile(`src="[^"]*gstatic\.com/[^"]*recaptcha`),
			regexp.MustCompile(`src="[^"]*recaptcha/api\.js`),
			regexp.MustCompile(`class="[^"]*g-recaptcha`),
		}},
		{CaptchaTypeHCaptcha, []*regexp.Regexp{
			regexp.MustCompile(`src="[^"]*js\.hcaptcha\.com`),
			regexp.MustCompile(`class="[^"]*h-captcha`),
			regexp.MustCompile(`data-hcaptcha-widget-id`),
		}},
		{CaptchaTypeTurnstile, []*regexp.Regexp{
			regexp.MustCompile(`src="[^"]*challenges\.cloudflare\.com`),
			regexp.MustCompile(`class="[^"]*cf-turnstile`),
		}},
		{CaptchaTypeGeetest, []*regexp.Regexp{
			regexp.MustCompile(`src="[^"]*geetest`),
			regexp.MustCompile(`class="[^"]*geetest`),
		}},
		{CaptchaTypeFriendlyCaptcha, []*regexp.Regexp{
			regexp.MustCompile(`src="[^"]*friendlycaptcha`),
			regexp.MustCompile(`class="[^"]*frc-captcha`),
		}},
		{CaptchaTypeRotateCaptcha, []*regexp.Regexp{
			regexp.MustCompile(`alt="[^"]*rotatecaptcha`),
			regexp.MustCompile(`src="[^"]*rotatecaptcha`),
		}},
		{CaptchaTypeClickCaptcha, []*regexp.Regexp{
			regexp.MustCompile(`alt="[^"]*clickcaptcha`),
			regexp.MustCompile(`src="[^"]*clickcaptcha`),
		}},
		{CaptchaTypeImageCaptcha, []*regexp.Regexp{
			regexp.MustCompile(`alt="[^"]*imagecaptcha`),
			regexp.MustCompile(`src="[^"]*imagecaptcha`),
		}},
		{CaptchaTypePuzzleCaptcha, []*regexp.Regexp{
			regexp.MustCompile(`class="[^"]*__puzzle_captcha`),
		}},
		{CaptchaTypeSliderCaptcha, []*regexp.Regexp{
			regexp.MustCompile(`class="[^"]*slider-captcha`),
			regexp.MustCompile(`src="[^"]*slidercaptcha`),
		}},
		{CaptchaTypeMCaptcha, []*regexp.Regexp{
			regexp.MustCompile(`src="[^"]*mcaptcha`),
			regexp.MustCompile(`class="[^"]*mcaptcha`),
			regexp.MustCompile(`data-mcaptcha`),
		}},
		{CaptchaTypeKasada, []*regexp.Regexp{
			regexp.MustCompile(`src="[^"]*kasadaproducts\.com`),
			regexp.MustCompile(`data-kasada`),
		}},
		{CaptchaTypeImperva, []*regexp.Regexp{
			regexp.MustCompile(`src="[^"]*/_incapsula_resource`),
			regexp.MustCompile(`data-incapsula`),
			regexp.MustCompile(`data-imperva`),
		}},
		{CaptchaTypeAwsWaf, []*regexp.Regexp{
			regexp.MustCompile(`src="[^"]*aws-waf-captcha`),
			regexp.MustCompile(`src="[^"]*awswaf\.com`),
		}},
		{CaptchaTypeDatadome, []*regexp.Regexp{
			regexp.MustCompile(`src="[^"]*datadome`),
			regexp.MustCompile(`data-datadome`),
			regexp.MustCompile(`class="[^"]*dd-challenge`),
		}},
		{CaptchaTypePerimeterX, []*regexp.Regexp{
			regexp.MustCompile(`src="[^"]*perimeterx`),
			regexp.MustCompile(`data-px`),
			regexp.MustCompile(`_pxappid`),
		}},
		{CaptchaTypeArgon, []*regexp.Regexp{
			regexp.MustCompile(`class="[^"]*argon-captcha`),
		}},
		{CaptchaTypeBehaviotech, []*regexp.Regexp{
			regexp.MustCompile(`src="[^"]*behaviotech\.com`),
		}},
		{CaptchaTypeSmartCaptcha, []*regexp.Regexp{
			regexp.MustCompile(`src="[^"]*captcha\.yandex`),
			regexp.MustCompile(`class="[^"]*smart-captcha`),
			regexp.MustCompile(`data-smartcaptcha`),
		}},
		{CaptchaTypeYandex, []*regexp.Regexp{
			regexp.MustCompile(`src="[^"]*smartcaptcha\.yandex`),
			regexp.MustCompile(`class="[^"]*yandex-captcha`),
		}},
		{CaptchaTypeFuncaptcha, []*regexp.Regexp{
			regexp.MustCompile(`src="[^"]*funcaptcha\.com`),
			regexp.MustCompile(`src="[^"]*arkoselabs\.com`),
			regexp.MustCompile(`class="[^"]*funcaptcha`),
		}},
		{CaptchaTypeCoingecko, []*regexp.Regexp{
			regexp.MustCompile(`src="[^"]*wsiz\.com`),
		}},
		{CaptchaTypeNovaScape, []*regexp.Regexp{
			regexp.MustCompile(`src="[^"]*novascape`),
		}},
		{CaptchaTypeSimple, []*regexp.Regexp{
			regexp.MustCompile(`name="[^"]*captcha_code`),
			regexp.MustCompile(`name="[^"]*captcha_input`),
			regexp.MustCompile(`id="[^"]*captcha_image`),
		}},
	}

	for _, entry := range integrationPatterns {
		for _, re := range entry.patterns {
			if re.MatchString(htmlLower) {
				return entry.captchaType
			}
		}
	}

	return CaptchaTypeNone
}
