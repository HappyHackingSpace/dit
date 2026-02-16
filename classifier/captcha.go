package classifier

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
	CaptchaTurnstile              CaptchaType = "turnstile"
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
		CaptchaTurnstile: {
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

// detectByDataAttributes checks for CAPTCHA-specific data attributes (less common, more specific patterns)
func detectByDataAttributes(form *goquery.Selection) CaptchaType {
	html, _ := form.Html()
	htmlLower := strings.ToLower(html)

	// Only check for unique data attributes that are specific to certain CAPTCHAs
	dataAttrPatterns := map[CaptchaType][]string{
		CaptchaTypeGeetest:         {"id_geetest", "geetest_id"},
		CaptchaTypeFriendlyCaptcha: {"frc-captcha", "data-public-key"},
		CaptchaTypeSliderCaptcha:   {"data-slideshow", "slide-verify-container"},
		CaptchaTypeDatadome:        {"dd-challenge", "dd-action"},
		CaptchaTypeYandex:          {"data-smartcaptcha", "captcha-container-yandex"},
		CaptchaTypePerimeterX:      {"_pxappid", "_px3"},
		CaptchaTypeArgon:           {"argon-captcha"},
		CaptchaTypeSmartCaptcha:    {"smart-captcha"},
	}

	for captchaType, attrs := range dataAttrPatterns {
		for _, attr := range attrs {
			if strings.Contains(htmlLower, attr) {
				return captchaType
			}
		}
	}

	return CaptchaTypeNone
}

// detectByFieldNames checks for simple/text-based CAPTCHAs by field name patterns
func detectByFieldNames(form *goquery.Selection) CaptchaType {
	html, _ := form.Html()
	htmlLower := strings.ToLower(html)

	// Detect simple text-based CAPTCHAs by common field names
	simpleCaptchaPatterns := []string{
		"simplecaptcha",     // simpleCaptcha field
		"captcha_code",      // captcha_code field
		"captcha_input",     // captcha_input field
		"verify_code",       // verify_code field
		"verification_code", // verification_code field
		"security_code",     // security_code field
		"text_captcha",      // text_captcha field
		"captcha_result",    // captcha_result field
	}

	for _, pattern := range simpleCaptchaPatterns {
		if strings.Contains(htmlLower, pattern) {
			return CaptchaTypeSimple
		}
	}

	return CaptchaTypeNone
}

// detectByClasses checks for CAPTCHA-specific class names
func detectByClasses(form *goquery.Selection) CaptchaType {
	classPatterns := map[CaptchaType][]string{
		CaptchaTypeRecaptcha:          {"g-recaptcha", "grecaptcha"},
		CaptchaTypeRecaptchaV2:        {"g-recaptcha-v2", "grecaptcha-v2"},
		CaptchaTypeRecaptchaInvisible: {"g-recaptcha-invisible", "grecaptcha-invisible"},
		CaptchaTypeHCaptcha:           {"h-captcha", "hcaptcha"},
		CaptchaTurnstile:              {"cf-turnstile", "cloudflare-turnstile-challenge", "turnstile"},
		CaptchaTypeGeetest:            {"geetest_", "geetest-box"},
		CaptchaTypeFriendlyCaptcha:    {"frc-captcha", "friendlycaptcha"},
		CaptchaTypeRotateCaptcha:      {"rotate-captcha", "rotatecaptcha"},
		CaptchaTypeClickCaptcha:       {"click-captcha", "clickcaptcha"},
		CaptchaTypeImageCaptcha:       {"image-captcha", "imagecaptcha"},
		CaptchaTypePuzzleCaptcha:      {"puzzle-captcha", "__puzzle_captcha"},
		CaptchaTypeSliderCaptcha:      {"slider-captcha", "slidercaptcha", "slide-verify"},
		CaptchaTypeDatadome:           {"dd-challenge", "dd-top"},
		CaptchaTypePerimeterX:         {"_px3", "px-container"},
		CaptchaTypeArgon:              {"argon-captcha"},
		CaptchaTypeSmartCaptcha:       {"smart-captcha"},
		CaptchaTypeYandex:             {"smartcaptcha", "yandex-captcha"},
		CaptchaTypeFuncaptcha:         {"funcaptcha-container"},
		CaptchaTypeMCaptcha:           {"mcaptcha", "mcaptcha-container"},
		CaptchaTypeKasada:             {"kas", "kasada"},
		CaptchaTypeImperva:            {"_inc", "incapsula", "imperva"},
		CaptchaTypeAwsWaf:             {"aws-waf", "awswaf"},
	}

	html, _ := form.Html()
	htmlLower := strings.ToLower(html)

	for captchaType, classes := range classPatterns {
		for _, class := range classes {
			if strings.Contains(htmlLower, class) {
				return captchaType
			}
		}
	}

	return CaptchaTypeNone
}

// detectByIframe checks for CAPTCHA-specific iframes
func detectByIframe(form *goquery.Selection) CaptchaType {
	iframePatterns := map[CaptchaType][]string{
		CaptchaTypeRecaptcha:     {"recaptcha"},
		CaptchaTypeHCaptcha:      {"hcaptcha"},
		CaptchaTurnstile:         {"challenges.cloudflare.com"},
		CaptchaTypeGeetest:       {"geetest"},
		CaptchaTypeSliderCaptcha: {"slidercaptcha", "slide-verify"},
		CaptchaTypeMCaptcha:      {"mcaptcha", "app.mcaptcha.io"},
		CaptchaTypeYandex:        {"yandex", "smartcaptcha"},
		CaptchaTypeKasada:        {"kasada", "kas"},
		CaptchaTypeImperva:       {"incapsula", "imperva"},
		CaptchaTypeDatadome:      {"datadome"},
	}

	html, _ := form.Html()
	htmlLower := strings.ToLower(html)

	// Check for iframe with CAPTCHA patterns in raw HTML
	if strings.Contains(htmlLower, "iframe") {
		for captchaType, patterns := range iframePatterns {
			for _, pattern := range patterns {
				if strings.Contains(htmlLower, pattern) && strings.Contains(htmlLower, "iframe") {
					return captchaType
				}
			}
		}
	}

	return CaptchaTypeNone
}

// hasGenericCaptchaMarkers checks for generic CAPTCHA-related HTML markers
func hasGenericCaptchaMarkers(form *goquery.Selection) bool {
	html, _ := form.Html()
	htmlLower := strings.ToLower(html)

	// Check for iframe with captcha-related keywords
	if strings.Contains(htmlLower, "iframe") {
		if strings.Contains(htmlLower, "captcha") ||
			strings.Contains(htmlLower, "challenge") ||
			strings.Contains(htmlLower, "security") {
			return true
		}
	}

	// Check for script tags with captcha/security keywords
	hasCaptchaInScript := false
	form.Find("script").Each(func(_ int, s *goquery.Selection) {
		scriptText := strings.ToLower(s.Text())
		if strings.Contains(scriptText, "captcha") ||
			strings.Contains(scriptText, "antibot") ||
			strings.Contains(scriptText, "challenge") {
			hasCaptchaInScript = true
		}
	})

	return hasCaptchaInScript
}

// DetectCaptchaInHTML detects all CAPTCHAs in an HTML document using domain-first approach
func DetectCaptchaInHTML(html string) CaptchaType {
	htmlLower := strings.ToLower(html)

	// Priority 1: Domain-based detection patterns (most reliable)
	domainPatterns := map[CaptchaType][]string{
		CaptchaTypeRecaptcha:          {"google.com/recaptcha", "gstatic.com", "recaptcha"},
		CaptchaTypeRecaptchaV2:        {"recaptcha/api.js", "recaptcha.*v2"},
		CaptchaTypeRecaptchaInvisible: {"recaptcha.*invisible"},
		CaptchaTypeHCaptcha:           {"hcaptcha", "js.hcaptcha.com"},
		CaptchaTurnstile:              {"challenges.cloudflare.com", "js.cloudflare.com"},
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
		CaptchaTypeArgon:              {"argon-captcha"},
		CaptchaTypeBehaviotech:        {"behaviotech"},
		CaptchaTypeSmartCaptcha:       {"captcha.yandex.com", "smartcaptcha"},
		CaptchaTypeYandex:             {"yandex.com/.*captcha", "yandex.ru/.*captcha", "smartcaptcha.yandex"},
		CaptchaTypeFuncaptcha:         {"funcaptcha", "arkose"},
		CaptchaTypeCoingecko:          {"wsiz.com"},
		CaptchaTypeNovaScape:          {"novascape"},
	}

	for captchaType, patterns := range domainPatterns {
		for _, pattern := range patterns {
			if strings.Contains(htmlLower, pattern) {
				return captchaType
			}
		}
	}

	// Priority 2: Class-based detection (when no domain is present)
	classPatterns := map[CaptchaType][]string{
		CaptchaTypeRecaptcha:          {"g-recaptcha", "grecaptcha"},
		CaptchaTypeRecaptchaV2:        {"g-recaptcha-v2", "grecaptcha-v2"},
		CaptchaTypeRecaptchaInvisible: {"g-recaptcha-invisible", "grecaptcha-invisible"},
		CaptchaTypeHCaptcha:           {"h-captcha", "hcaptcha"},
		CaptchaTurnstile:              {"cf-turnstile", "cloudflare-turnstile-challenge", "turnstile"},
		CaptchaTypeGeetest:            {"geetest_", "geetest-box"},
		CaptchaTypeFriendlyCaptcha:    {"frc-captcha", "friendlycaptcha"},
		CaptchaTypeRotateCaptcha:      {"rotate-captcha", "rotatecaptcha"},
		CaptchaTypeClickCaptcha:       {"click-captcha", "clickcaptcha"},
		CaptchaTypeImageCaptcha:       {"image-captcha", "imagecaptcha"},
		CaptchaTypePuzzleCaptcha:      {"puzzle-captcha", "__puzzle_captcha"},
		CaptchaTypeSliderCaptcha:      {"slider-captcha", "slidercaptcha"},
		CaptchaTypeMCaptcha:           {"mcaptcha", "mcaptcha-container"},
		CaptchaTypeKasada:             {"kas", "kasada"},
		CaptchaTypeImperva:            {"_inc", "incapsula", "imperva"},
		CaptchaTypeAwsWaf:             {"aws-waf", "awswaf"},
		CaptchaTypeDatadome:           {"dd-challenge", "dd-top"},
		CaptchaTypePerimeterX:         {"_px3", "px-container"},
		CaptchaTypeArgon:              {"argon-captcha"},
		CaptchaTypeSmartCaptcha:       {"smart-captcha"},
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

	// Priority 3: Simple/text-based CAPTCHA detection by field names
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

// IsValidCaptchaType checks if a string is a valid CaptchaType
func IsValidCaptchaType(s string) bool {
	validTypes := []CaptchaType{
		CaptchaTypeNone,
		CaptchaTypeRecaptcha,
		CaptchaTypeRecaptchaV2,
		CaptchaTypeRecaptchaInvisible,
		CaptchaTypeHCaptcha,
		CaptchaTurnstile,
		CaptchaTypeGeetest,
		CaptchaTypeFriendlyCaptcha,
		CaptchaTypeRotateCaptcha,
		CaptchaTypeClickCaptcha,
		CaptchaTypeImageCaptcha,
		CaptchaTypePuzzleCaptcha,
		CaptchaTypeSliderCaptcha,
		CaptchaTypeMCaptcha,
		CaptchaTypeDatadome,
		CaptchaTypePerimeterX,
		CaptchaTypeArgon,
		CaptchaTypeBehaviotech,
		CaptchaTypeSmartCaptcha,
		CaptchaTypeYandex,
		CaptchaTypeFuncaptcha,
		CaptchaTypeKasada,
		CaptchaTypeImperva,
		CaptchaTypeAwsWaf,
		CaptchaTypeCoingecko,
		CaptchaTypeNovaScape,
		CaptchaTypeSimple,
		CaptchaTypeOther,
	}

	for _, t := range validTypes {
		if CaptchaType(s) == t {
			return true
		}
	}
	return false
}

// String returns the string representation of a CaptchaType
func (ct CaptchaType) String() string {
	return string(ct)
}
