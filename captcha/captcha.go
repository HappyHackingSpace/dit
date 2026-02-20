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

	// Layer 4: Field names (detect simple/text CAPTCHAs by input name)
	if captcha := detectByFieldNames(form); captcha != CaptchaTypeNone {
		return captcha
	}

	// Layer 5: Iframe-based detection
	if captcha := detectByIframe(form); captcha != CaptchaTypeNone {
		return captcha
	}

	// Layer 6: Generic markers
	if hasGenericCaptchaMarkers(form) {
		return CaptchaTypeOther
	}

	return CaptchaTypeNone
}

// detectByScriptDomain checks script src attributes for known CAPTCHA provider domains
func detectByScriptDomain(form *goquery.Selection) CaptchaType {
	// Get all scripts in the form and parent document
	scriptPatterns := map[CaptchaType][]*regexp.Regexp{
		CaptchaTypeRecaptcha: {
			regexp.MustCompile(`google\.com/recaptcha`),
			regexp.MustCompile(`recaptcha.*\.js`),
			regexp.MustCompile(`gstatic\.com/.*recaptcha`),
		},
		CaptchaTypeRecaptchaV2: {
			regexp.MustCompile(`recaptcha.*v2`),
			regexp.MustCompile(`recaptcha/api\.js`),
		},
		CaptchaTypeRecaptchaInvisible: {
			regexp.MustCompile(`recaptcha.*invisible`),
			regexp.MustCompile(`grecaptcha\.render.*invisible`),
		},
		CaptchaTypeHCaptcha: {
			regexp.MustCompile(`js\.hcaptcha\.com`),
			regexp.MustCompile(`hcaptcha`),
		},
		CaptchaTypeTurnstile: {
			regexp.MustCompile(`challenges\.cloudflare\.com`),
			regexp.MustCompile(`js\.cloudflare\.com.*turnstile`),
		},
		CaptchaTypeGeetest: {
			regexp.MustCompile(`geetest`),
			regexp.MustCompile(`api\.geetest\.com`),
		},
		CaptchaTypeFriendlyCaptcha: {
			regexp.MustCompile(`friendlycaptcha`),
			regexp.MustCompile(`cdn\.friendlycaptcha\.com`),
		},
		CaptchaTypeRotateCaptcha: {
			regexp.MustCompile(`api\.rotatecaptcha\.com`),
		},
		CaptchaTypeClickCaptcha: {
			regexp.MustCompile(`assets\.clickcaptcha\.com`),
		},
		CaptchaTypeImageCaptcha: {
			regexp.MustCompile(`api\.imagecaptcha\.com`),
		},
		CaptchaTypePuzzleCaptcha: {
			regexp.MustCompile(`puzzle.*captcha`),
		},
		CaptchaTypeSliderCaptcha: {
			regexp.MustCompile(`slider.*captcha`),
			regexp.MustCompile(`api\.slidercaptcha\.com`),
			regexp.MustCompile(`slidercaptcha\.com`),
		},
		CaptchaTypeDatadome: {
			regexp.MustCompile(`datadome\.co`),
			regexp.MustCompile(`cdn\.mxpnl\.com`),
		},
		CaptchaTypePerimeterX: {
			regexp.MustCompile(`perimeterx\.net`),
		},
		CaptchaTypeArgon: {
			regexp.MustCompile(`argon.*captcha`),
			regexp.MustCompile(`captcha\.argon`),
		},
		CaptchaTypeBehaviotech: {
			regexp.MustCompile(`behaviotech\.com`),
		},
		CaptchaTypeSmartCaptcha: {
			regexp.MustCompile(`captcha\.yandex\.com`),
			regexp.MustCompile(`smartcaptcha\.yandex`),
		},
		CaptchaTypeYandex: {
			regexp.MustCompile(`yandex\.com/.*captcha`),
			regexp.MustCompile(`captcha\.yandex`),
			regexp.MustCompile(`smartcaptcha\.yandex`),
		},
		CaptchaTypeFuncaptcha: {
			regexp.MustCompile(`funcaptcha\.com`),
			regexp.MustCompile(`api\.funcaptcha\.com`),
		},
		CaptchaTypeCoingecko: {
			regexp.MustCompile(`wsiz\.com`),
		},
		CaptchaTypeNovaScape: {
			regexp.MustCompile(`novascape\.com`),
		},
		CaptchaTypeMCaptcha: {
			regexp.MustCompile(`mcaptcha`),
			regexp.MustCompile(`app\.mcaptcha\.io`),
		},
		CaptchaTypeKasada: {
			regexp.MustCompile(`kasada`),
			regexp.MustCompile(`kas\.kasadaproducts\.com`),
		},
		CaptchaTypeImperva: {
			regexp.MustCompile(`/_Incapsula_Resource`),
			regexp.MustCompile(`incapsula`),
			regexp.MustCompile(`imperva`),
		},
		CaptchaTypeAwsWaf: {
			regexp.MustCompile(`/aws-waf-captcha/`),
			regexp.MustCompile(`awswaf\.com`),
			regexp.MustCompile(`captcha\.aws\.amazon\.com`),
		},
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
	for captchaType, patterns := range scriptPatterns {
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

	dataAttrPatterns := map[CaptchaType][]string{
		CaptchaTypeKasada:       {"data-kasada", "kasada"},
		CaptchaTypeImperva:      {"data-incapsula", "data-imperva"},
		CaptchaTypeDatadome:     {"data-datadome", "dd-challenge"},
		CaptchaTypePerimeterX:   {"data-px", "_pxappid"},
		CaptchaTypeMCaptcha:     {"data-mcaptcha"},
		CaptchaTypeSmartCaptcha: {"data-smartcaptcha", "smartcaptcha"},
	}

	for captchaType, patterns := range dataAttrPatterns {
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

	classPatterns := map[CaptchaType][]string{
		CaptchaTypeRecaptcha:          {"g-recaptcha", "grecaptcha"},
		CaptchaTypeRecaptchaV2:        {"g-recaptcha-v2", "grecaptcha-v2"},
		CaptchaTypeRecaptchaInvisible: {"g-recaptcha-invisible", "grecaptcha-invisible"},
		CaptchaTypeHCaptcha:           {"h-captcha", "hcaptcha"},
		CaptchaTypeTurnstile:          {"cf-turnstile", "turnstile"},
		CaptchaTypeGeetest:            {"geetest_", "geetest-box"},
		CaptchaTypeFriendlyCaptcha:    {"frc-captcha", "friendlycaptcha"},
		CaptchaTypeMCaptcha:           {"mcaptcha", "mcaptcha-container"},
		CaptchaTypeKasada:             {"kas", "kasada"},
		CaptchaTypeImperva:            {"_inc", "incapsula", "imperva"},
		CaptchaTypeAwsWaf:             {"aws-waf", "awswaf"},
		CaptchaTypeDatadome:           {"dd-challenge", "dd-top"},
		CaptchaTypePerimeterX:         {"_px3", "px-container"},
		CaptchaTypeSmartCaptcha:       {"smart-captcha", "smartcaptcha"},
		CaptchaTypeArgon:              {"argon-captcha", "argon"},
		CaptchaTypePuzzleCaptcha:      {"puzzle-captcha", "__puzzle_captcha"},
		CaptchaTypeYandex:             {"smartcaptcha", "yandex-captcha"},
		CaptchaTypeFuncaptcha:         {"funcaptcha-container"},
	}

	for captchaType, classes := range classPatterns {
		for _, class := range classes {
			if strings.Contains(htmlLower, class) {
				return captchaType
			}
		}
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

	iframePatterns := map[CaptchaType][]string{
		CaptchaTypeRecaptcha:  {"google.com/recaptcha", "www.google.com/recaptcha"},
		CaptchaTypeHCaptcha:   {"hcaptcha.com"},
		CaptchaTypeTurnstile:  {"cloudflare.com/turnstile"},
		CaptchaTypeFuncaptcha: {"funcaptcha"},
		CaptchaTypeYandex:     {"yandex", "smartcaptcha"},
	}

	for captchaType, patterns := range iframePatterns {
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
// It checks literal substrings first and falls back to regex patterns for complex matches.
func DetectCaptchaInHTML(html string) CaptchaType {
	htmlLower := strings.ToLower(html)

	// Literal patterns for straightforward substring matching
	literalPatterns := map[CaptchaType][]string{
		CaptchaTypeRecaptcha:          {"google.com/recaptcha", "gstatic.com", "recaptcha/api.js", "recaptcha", "g-recaptcha"},
		CaptchaTypeRecaptchaV2:        {"recaptcha/api.js"},
		CaptchaTypeRecaptchaInvisible: {"recaptcha/api.js"},
		CaptchaTypeHCaptcha:           {"hcaptcha", "js.hcaptcha.com", "h-captcha"},
		CaptchaTypeTurnstile:          {"challenges.cloudflare.com", "js.cloudflare.com", "cf-turnstile", "turnstile"},
		CaptchaTypeGeetest:            {"geetest", "api.geetest.com"},
		CaptchaTypeFriendlyCaptcha:    {"friendlycaptcha", "cdn.friendlycaptcha.com"},
		CaptchaTypeRotateCaptcha:      {"rotatecaptcha", "api.rotatecaptcha.com"},
		CaptchaTypeClickCaptcha:       {"clickcaptcha", "assets.clickcaptcha.com"},
		CaptchaTypeImageCaptcha:       {"imagecaptcha", "api.imagecaptcha.com"},
		CaptchaTypePuzzleCaptcha:      {"puzzle-captcha", "__puzzle_captcha"},
		CaptchaTypeSliderCaptcha:      {"slider-captcha", "slidercaptcha"},
		CaptchaTypeMCaptcha:           {"mcaptcha", "app.mcaptcha.io"},
		CaptchaTypeKasada:             {"kasada", "kas.kasadaproducts.com"},
		CaptchaTypeImperva:            {"incapsula", "imperva"},
		CaptchaTypeAwsWaf:             {"awswaf", "captcha.aws.amazon.com"},
		CaptchaTypeDatadome:           {"datadome", "dd-challenge"},
		CaptchaTypePerimeterX:         {"perimeterx", "_pxappid"},
		CaptchaTypeArgon:              {"argon-captcha", "argon-captcha"},
		CaptchaTypeBehaviotech:        {"behaviotech"},
		CaptchaTypeSmartCaptcha:       {"captcha.yandex.com", "smartcaptcha"},
		CaptchaTypeFuncaptcha:         {"funcaptcha", "arkose"},
		CaptchaTypeCoingecko:          {"wsiz.com"},
		CaptchaTypeNovaScape:          {"novascape"},
	}

	// Regex patterns for complex domain matching
	regexPatterns := map[CaptchaType][]*regexp.Regexp{
		CaptchaTypeYandex: {
			regexp.MustCompile(`yandex\.com/[^"'\s]*captcha`),
			regexp.MustCompile(`yandex\.ru/[^"'\s]*captcha`),
			regexp.MustCompile(`smartcaptcha\.yandex`),
		},
	}

	// Check literal patterns first
	for captchaType, patterns := range literalPatterns {
		for _, pattern := range patterns {
			if strings.Contains(htmlLower, pattern) {
				return captchaType
			}
		}
	}

	// Check regex patterns
	for captchaType, regexes := range regexPatterns {
		for _, re := range regexes {
			if re.MatchString(htmlLower) {
				return captchaType
			}
		}
	}

	return CaptchaTypeNone
}
