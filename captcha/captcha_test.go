package captcha_test

import (
	"testing"

	"github.com/happyhackingspace/dit/captcha"
	"github.com/happyhackingspace/dit/internal/htmlutil"
)

func TestDetectRecaptchaV2(t *testing.T) {
	html := `
<form method="POST" action="/login">
  <input type="email" name="email" />
  <input type="password" name="password" />
  <div class="g-recaptcha" data-sitekey="6LdpXXXXXXXXXXXXXXXXXXXX"></div>
  <input type="submit" value="Login" />
</form>
`
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}

	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find form")
	}

	detector := &captcha.CaptchaDetector{}
	result := detector.DetectInForm(forms[0])

	if result != captcha.CaptchaTypeRecaptcha {
		t.Errorf("expected recaptcha, got %v", result)
	}
}

func TestDetectRecaptchaScript(t *testing.T) {
	html := `
<form method="POST" action="/login">
  <input type="email" name="email" />
  <script src="https://www.google.com/recaptcha/api.js"></script>
  <input type="submit" value="Login" />
</form>
`
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}

	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find form")
	}

	detector := &captcha.CaptchaDetector{}
	result := detector.DetectInForm(forms[0])

	if result != captcha.CaptchaTypeRecaptcha {
		t.Errorf("expected recaptcha, got %v", result)
	}
}

func TestDetectHCaptcha(t *testing.T) {
	html := `
<form method="POST" action="/login">
  <input type="email" name="email" />
  <div class="h-captcha" data-sitekey="10000000-ffff-ffff-ffff-000000000001"></div>
  <input type="submit" value="Login" />
</form>
`
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}

	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find form")
	}

	detector := &captcha.CaptchaDetector{}
	result := detector.DetectInForm(forms[0])

	if result != captcha.CaptchaTypeHCaptcha {
		t.Errorf("expected hcaptcha, got %v", result)
	}
}

func TestDetectHCaptchaScript(t *testing.T) {
	html := `
<form method="POST" action="/login">
  <input type="email" name="email" />
  <script src="https://js.hcaptcha.com/1/api.js" async defer></script>
  <input type="submit" value="Login" />
</form>
`
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}

	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find form")
	}

	detector := &captcha.CaptchaDetector{}
	result := detector.DetectInForm(forms[0])

	if result != captcha.CaptchaTypeHCaptcha {
		t.Errorf("expected hcaptcha, got %v", result)
	}
}

func TestDetectTurnstile(t *testing.T) {
	html := `
<form method="POST" action="/login">
  <input type="email" name="email" />
  <div class="cf-turnstile" data-sitekey="1x00000000000000000000AA"></div>
  <input type="submit" value="Login" />
</form>
`
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}

	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find form")
	}

	detector := &captcha.CaptchaDetector{}
	result := detector.DetectInForm(forms[0])

	if result != captcha.CaptchaTypeTurnstile {
		t.Errorf("expected turnstile, got %v", result)
	}
}

func TestDetectTurnstileScript(t *testing.T) {
	html := `
<form method="POST" action="/login">
  <input type="email" name="email" />
  <script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
  <input type="submit" value="Login" />
</form>
`
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}

	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find form")
	}

	detector := &captcha.CaptchaDetector{}
	result := detector.DetectInForm(forms[0])

	if result != captcha.CaptchaTypeTurnstile {
		t.Errorf("expected turnstile, got %v", result)
	}
}

func TestDetectGeetest(t *testing.T) {
	html := `
<form method="POST" action="/login">
  <input type="email" name="email" />
  <div id="geetest_id"></div>
  <script src="https://static.geetest.com/static/tools/gt.js"></script>
  <input type="submit" value="Login" />
</form>
`
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}

	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find form")
	}

	detector := &captcha.CaptchaDetector{}
	result := detector.DetectInForm(forms[0])

	if result != captcha.CaptchaTypeGeetest {
		t.Errorf("expected geetest, got %v", result)
	}
}

func TestDetectFriendlyCaptcha(t *testing.T) {
	html := `
<form method="POST" action="/login">
  <input type="email" name="email" />
  <div class="frc-captcha" data-public-key="XXXXXXXXXXXXXXXXXXXXXXXX"></div>
  <input type="submit" value="Login" />
</form>
`
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}

	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find form")
	}

	detector := &captcha.CaptchaDetector{}
	result := detector.DetectInForm(forms[0])

	if result != captcha.CaptchaTypeFriendlyCaptcha {
		t.Errorf("expected friendlycaptcha, got %v", result)
	}
}

func TestDetectNoCaptcha(t *testing.T) {
	html := `
<form method="POST" action="/login">
  <input type="email" name="email" />
  <input type="password" name="password" />
  <input type="submit" value="Login" />
</form>
`
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}

	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find form")
	}

	detector := &captcha.CaptchaDetector{}
	result := detector.DetectInForm(forms[0])

	if result != captcha.CaptchaTypeNone {
		t.Errorf("expected no captcha, got %v", result)
	}
}

func TestDetectGenericCaptchaIframe(t *testing.T) {
	html := `
<form method="POST" action="/login">
  <input type="email" name="email" />
  <iframe src="https://example.com/captcha"></iframe>
  <input type="submit" value="Login" />
</form>
`
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}

	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find form")
	}

	detector := &captcha.CaptchaDetector{}
	result := detector.DetectInForm(forms[0])

	// Should detect as generic captcha or none (depending on iframe content)
	if result == captcha.CaptchaTypeRecaptcha || result == captcha.CaptchaTypeHCaptcha {
		t.Errorf("expected generic/none, got %v", result)
	}
}

func TestDetectCaptchaInMultipleForms(t *testing.T) {
	html := `
<html>
  <body>
    <form id="login" method="POST" action="/login">
      <input type="email" name="email" />
      <div class="g-recaptcha" data-sitekey="6LdpXXXXXXXXXXXXXXXXXXXX"></div>
      <input type="submit" value="Login" />
    </form>
    <form id="signup" method="POST" action="/signup">
      <input type="email" name="email" />
      <div class="h-captcha" data-sitekey="10000000-ffff-ffff-ffff-000000000001"></div>
      <input type="submit" value="Signup" />
    </form>
  </body>
</html>
`
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}

	forms := htmlutil.GetForms(doc)
	if len(forms) != 2 {
		t.Fatalf("expected 2 forms, got %d", len(forms))
	}

	detector := &captcha.CaptchaDetector{}

	result1 := detector.DetectInForm(forms[0])
	if result1 != captcha.CaptchaTypeRecaptcha {
		t.Errorf("form 1: expected recaptcha, got %v", result1)
	}

	result2 := detector.DetectInForm(forms[1])
	if result2 != captcha.CaptchaTypeHCaptcha {
		t.Errorf("form 2: expected hcaptcha, got %v", result2)
	}
}

func TestDetectCaptchaInHTML(t *testing.T) {
	// Test 1: Single CAPTCHA detection
	html1 := `
<html>
  <body>
    <form id="login">
      <div class="g-recaptcha" data-sitekey="6LdpXXXXXXXXXXXXXXXXXXXX"></div>
    </form>
  </body>
</html>
`
	result1 := captcha.DetectCaptchaInHTML(html1)
	if result1 != captcha.CaptchaTypeRecaptcha {
		t.Errorf("expected recaptcha, got %v", result1)
	}

	// Test 2: hCaptcha detection
	html2 := `
<html>
  <body>
    <form id="signup">
      <div class="h-captcha" data-sitekey="10000000-ffff-ffff-ffff-000000000001"></div>
    </form>
  </body>
</html>
`
	result2 := captcha.DetectCaptchaInHTML(html2)
	if result2 != captcha.CaptchaTypeHCaptcha {
		t.Errorf("expected hcaptcha, got %v", result2)
	}

	// Test 3: Turnstile detection
	html3 := `
<html>
  <body>
    <form id="contact">
      <div class="cf-turnstile" data-sitekey="1x00000000000000000000AA"></div>
    </form>
  </body>
</html>
`
	result3 := captcha.DetectCaptchaInHTML(html3)
	if result3 != captcha.CaptchaTypeTurnstile {
		t.Errorf("expected turnstile, got %v", result3)
	}

	// Test 4: Multiple CAPTCHAs (should detect first match)
	htmlMultiple := `
<html>
  <body>
    <form id="login">
      <div class="g-recaptcha" data-sitekey="6LdpXXXXXXXXXXXXXXXXXXXX"></div>
    </form>
    <form id="signup">
      <div class="h-captcha" data-sitekey="10000000-ffff-ffff-ffff-000000000001"></div>
    </form>
    <form id="contact">
      <div class="cf-turnstile" data-sitekey="1x00000000000000000000AA"></div>
    </form>
  </body>
</html>
`
	resultMultiple := captcha.DetectCaptchaInHTML(htmlMultiple)
	if resultMultiple == captcha.CaptchaTypeNone {
		t.Error("expected to detect at least one captcha")
	}
}

func TestCaptchaTypeString(t *testing.T) {
	tests := []struct {
		ct       captcha.CaptchaType
		expected string
	}{
		{captcha.CaptchaTypeNone, "none"},
		{captcha.CaptchaTypeRecaptcha, "recaptcha"},
		{captcha.CaptchaTypeHCaptcha, "hcaptcha"},
		{captcha.CaptchaTypeTurnstile, "turnstile"},
		{captcha.CaptchaTypeGeetest, "geetest"},
		{captcha.CaptchaTypeFriendlyCaptcha, "friendlycaptcha"},
		{captcha.CaptchaTypeOther, "other"},
	}

	for _, test := range tests {
		if test.ct.String() != test.expected {
			t.Errorf("CaptchaType.String(): expected %q, got %q", test.expected, test.ct.String())
		}
	}
}

func TestIsValidCaptchaType(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"none", true},
		{"recaptcha", true},
		{"hcaptcha", true},
		{"turnstile", true},
		{"geetest", true},
		{"friendlycaptcha", true},
		{"other", true},
		{"invalid", false},
		{"", false},
		{"RECAPTCHA", false},
	}

	for _, test := range tests {
		result := captcha.IsValidCaptchaType(test.input)
		if result != test.expected {
			t.Errorf("IsValidCaptchaType(%q): expected %v, got %v", test.input, test.expected, result)
		}
	}
}

func TestDetectRecaptchaV3(t *testing.T) {
	html := `
<form method="POST" action="/submit">
  <input type="email" name="email" />
  <script src="https://www.google.com/recaptcha/api.js?render=6LdpXXXXXXXXXXXXXXXXXXXX"></script>
  <input type="submit" value="Submit" />
</form>
`
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}

	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find form")
	}

	detector := &captcha.CaptchaDetector{}
	result := detector.DetectInForm(forms[0])

	if result != captcha.CaptchaTypeRecaptcha {
		t.Errorf("expected recaptcha, got %v", result)
	}
}

func TestDetectMultipleCaptchasInOneForm(t *testing.T) {
	// This form has both recaptcha and hcaptcha (unusual but possible)
	html := `
<form method="POST" action="/login">
  <input type="email" name="email" />
  <div class="g-recaptcha" data-sitekey="6LdpXXXXXXXXXXXXXXXXXXXX"></div>
  <div class="h-captcha" data-sitekey="10000000-ffff-ffff-ffff-000000000001"></div>
  <input type="submit" value="Login" />
</form>
`
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}

	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find form")
	}

	detector := &captcha.CaptchaDetector{}
	result := detector.DetectInForm(forms[0])

	// Should detect the first CAPTCHA found (recaptcha comes first)
	if result != captcha.CaptchaTypeRecaptcha && result != captcha.CaptchaTypeHCaptcha {
		t.Errorf("expected recaptcha or hcaptcha, got %v", result)
	}
}

// New CAPTCHA type tests

func TestDetectRotateCaptcha(t *testing.T) {
	html := `
<form method="POST" action="/login">
  <input type="email" name="email" />
  <div id="rotate-captcha"></div>
  <script src="https://api.rotatecaptcha.com/api.js"></script>
  <input type="submit" value="Login" />
</form>
`
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}

	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find form")
	}

	detector := &captcha.CaptchaDetector{}
	result := detector.DetectInForm(forms[0])

	if result != captcha.CaptchaTypeRotateCaptcha {
		t.Errorf("expected rotatecaptcha, got %v", result)
	}
}

func TestDetectClickCaptcha(t *testing.T) {
	html := `
<form method="POST" action="/login">
  <input type="email" name="email" />
  <div id="click-captcha"></div>
  <script src="https://assets.clickcaptcha.com/api.js"></script>
  <input type="submit" value="Login" />
</form>
`
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}

	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find form")
	}

	detector := &captcha.CaptchaDetector{}
	result := detector.DetectInForm(forms[0])

	if result != captcha.CaptchaTypeClickCaptcha {
		t.Errorf("expected clickcaptcha, got %v", result)
	}
}

func TestDetectImageCaptcha(t *testing.T) {
	html := `
<form method="POST" action="/login">
  <input type="email" name="email" />
  <div id="image-captcha"></div>
  <script src="https://api.imagecaptcha.com/api.js"></script>
  <input type="submit" value="Login" />
</form>
`
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}

	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find form")
	}

	detector := &captcha.CaptchaDetector{}
	result := detector.DetectInForm(forms[0])

	if result != captcha.CaptchaTypeImageCaptcha {
		t.Errorf("expected imagecaptcha, got %v", result)
	}
}

func TestDetectPuzzleCaptcha(t *testing.T) {
	html := `
<form method="POST" action="/login">
  <input type="email" name="email" />
  <div id="puzzle-captcha"></div>
  <script>var __puzzle_captcha = {};</script>
  <input type="submit" value="Login" />
</form>
`
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}

	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find form")
	}

	detector := &captcha.CaptchaDetector{}
	result := detector.DetectInForm(forms[0])

	if result != captcha.CaptchaTypePuzzleCaptcha {
		t.Errorf("expected puzzlecaptcha, got %v", result)
	}
}

func TestDetectDatadome(t *testing.T) {
	html := `
<form method="POST" action="/login">
  <input type="email" name="email" />
  <div id="dd-challenge"></div>
  <script src="https://datadome.co/api.js"></script>
  <input type="submit" value="Login" />
</form>
`
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}

	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find form")
	}

	detector := &captcha.CaptchaDetector{}
	result := detector.DetectInForm(forms[0])

	if result != captcha.CaptchaTypeDatadome {
		t.Errorf("expected datadome, got %v", result)
	}
}

func TestDetectPerimeterX(t *testing.T) {
	html := `
<form method="POST" action="/login">
  <input type="email" name="email" />
  <script>var _pxAppId = "app123";</script>
  <script src="https://perimeterx.net/api.js"></script>
  <input type="submit" value="Login" />
</form>
`
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}

	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find form")
	}

	detector := &captcha.CaptchaDetector{}
	result := detector.DetectInForm(forms[0])

	if result != captcha.CaptchaTypePerimeterX {
		t.Errorf("expected perimeterx, got %v", result)
	}
}

func TestDetectArgon(t *testing.T) {
	html := `
<form method="POST" action="/login">
  <input type="email" name="email" />
  <div id="argon-captcha"></div>
  <input type="submit" value="Login" />
</form>
`
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}

	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find form")
	}

	detector := &captcha.CaptchaDetector{}
	result := detector.DetectInForm(forms[0])

	if result != captcha.CaptchaTypeArgon {
		t.Errorf("expected argon, got %v", result)
	}
}

func TestDetectBehaviotech(t *testing.T) {
	html := `
<form method="POST" action="/login">
  <input type="email" name="email" />
  <script src="https://behaviotech.com/api.js"></script>
  <input type="submit" value="Login" />
</form>
`
	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}

	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find form")
	}

	detector := &captcha.CaptchaDetector{}
	result := detector.DetectInForm(forms[0])

	if result != captcha.CaptchaTypeBehaviotech {
		t.Errorf("expected behaviotech, got %v", result)
	}
}
