package dit

import (
	"testing"

	"github.com/happyhackingspace/dit/captcha"
	"github.com/happyhackingspace/dit/internal/htmlutil"
)

// TestFormResultStructure is a small unit test verifying struct shaping.
func TestFormResultStructure(t *testing.T) {
	result := FormResult{
		Type:    "login",
		Captcha: "recaptcha",
		Fields:  map[string]string{"email": "email", "password": "password"},
	}
	if result.Type != "login" {
		t.Errorf("Type: got %s, want login", result.Type)
	}
	if result.Captcha != "recaptcha" {
		t.Errorf("Captcha: got %s, want recaptcha", result.Captcha)
	}
	if len(result.Fields) != 2 {
		t.Errorf("Fields count: got %d, want 2", len(result.Fields))
	}
}

// TestPageResultStructure is a small unit test verifying page result struct shaping.
func TestPageResultStructure(t *testing.T) {
	result := PageResult{
		Type:    "login",
		Captcha: "turnstile",
		Forms: []FormResult{
			{Type: "login", Captcha: "turnstile", Fields: map[string]string{"email": "email"}},
		},
	}
	if result.Type != "login" {
		t.Errorf("Type: got %s, want login", result.Type)
	}
	if result.Captcha != "turnstile" {
		t.Errorf("Captcha: got %s, want turnstile", result.Captcha)
	}
	if len(result.Forms) != 1 {
		t.Errorf("Forms count: got %d, want 1", len(result.Forms))
	}
}

// TestDetectInFormVariousCaptchas exercises real detection logic via DetectInForm
// with HTML fixtures for multiple CAPTCHA providers.
func TestDetectInFormVariousCaptchas(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		expected captcha.CaptchaType
	}{
		{
			name: "recaptcha_class",
			html: `<html><body><form>
				<input name="email"/>
				<div class="g-recaptcha" data-sitekey="key"></div>
			</form></body></html>`,
			expected: captcha.CaptchaTypeRecaptcha,
		},
		{
			name: "recaptchav2_class",
			html: `<html><body><form>
				<input name="email"/>
				<div class="g-recaptcha-v2" data-sitekey="key"></div>
			</form></body></html>`,
			expected: captcha.CaptchaTypeRecaptchaV2,
		},
		{
			name: "recaptcha_invisible_class",
			html: `<html><body><form>
				<input name="email"/>
				<div class="g-recaptcha-invisible" data-sitekey="key"></div>
			</form></body></html>`,
			expected: captcha.CaptchaTypeRecaptchaInvisible,
		},
		{
			name: "hcaptcha_class",
			html: `<html><body><form>
				<input name="user"/>
				<div class="h-captcha" data-sitekey="key"></div>
			</form></body></html>`,
			expected: captcha.CaptchaTypeHCaptcha,
		},
		{
			name: "turnstile_class",
			html: `<html><body><form>
				<input name="name"/>
				<div class="cf-turnstile" data-sitekey="key"></div>
			</form></body></html>`,
			expected: captcha.CaptchaTypeTurnstile,
		},
		{
			name: "geetest_class",
			html: `<html><body><form>
				<input name="login"/>
				<div class="geetest_box"></div>
			</form></body></html>`,
			expected: captcha.CaptchaTypeGeetest,
		},
		{
			name: "friendlycaptcha_class",
			html: `<html><body><form>
				<input name="msg"/>
				<div class="frc-captcha"></div>
			</form></body></html>`,
			expected: captcha.CaptchaTypeFriendlyCaptcha,
		},
		{
			name: "mcaptcha_data_attr",
			html: `<html><body><form>
				<input name="comment"/>
				<div data-mcaptcha="true"></div>
			</form></body></html>`,
			expected: captcha.CaptchaTypeMCaptcha,
		},
		{
			name: "kasada_data_attr",
			html: `<html><body><form>
				<input name="token"/>
				<div data-kasada="true"></div>
			</form></body></html>`,
			expected: captcha.CaptchaTypeKasada,
		},
		{
			name: "imperva_data_attr",
			html: `<html><body><form>
				<input name="auth"/>
				<div data-imperva="true"></div>
			</form></body></html>`,
			expected: captcha.CaptchaTypeImperva,
		},
		{
			name: "no_captcha",
			html: `<html><body><form>
				<input name="q"/>
				<input type="submit" value="Search"/>
			</form></body></html>`,
			expected: captcha.CaptchaTypeNone,
		},
	}

	detector := &captcha.CaptchaDetector{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := htmlutil.LoadHTMLString(tt.html)
			if err != nil {
				t.Fatal(err)
			}
			forms := htmlutil.GetForms(doc)
			if len(forms) == 0 {
				t.Fatal("expected to find a form")
			}
			got := detector.DetectInForm(forms[0])
			if got != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, got)
			}
		})
	}
}

// TestDetectCaptchaInHTMLVariousProviders exercises page-level detection.
func TestDetectCaptchaInHTMLVariousProviders(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		expected captcha.CaptchaType
	}{
		{
			name: "recaptcha_script_double_quote",
			html: `<html><head><script src="https://www.google.com/recaptcha/api.js"></script></head>
				<body><form><div class="g-recaptcha"></div></form></body></html>`,
			expected: captcha.CaptchaTypeRecaptcha,
		},
		{
			name: "recaptcha_script_single_quote",
			html: `<html><head><script src='https://www.google.com/recaptcha/api.js'></script></head>
				<body><form><div class='g-recaptcha'></div></form></body></html>`,
			expected: captcha.CaptchaTypeRecaptcha,
		},
		{
			name: "hcaptcha",
			html: `<html><body><form><div class="h-captcha" data-sitekey="key"></div>
				<script src="https://js.hcaptcha.com/1/api.js"></script></form></body></html>`,
			expected: captcha.CaptchaTypeHCaptcha,
		},
		{
			name: "turnstile",
			html: `<html><body><form>
				<div class="cf-turnstile" data-sitekey="key"></div>
				<script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>
			</form></body></html>`,
			expected: captcha.CaptchaTypeTurnstile,
		},
		{
			name:     "no_captcha",
			html:     `<html><head><title>Hi</title></head><body><p>Hello</p></body></html>`,
			expected: captcha.CaptchaTypeNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := captcha.DetectCaptchaInHTML(tt.html)
			if got != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, got)
			}
		})
	}
}

// TestIsValidCaptchaType verifies the map-based lookup works correctly.
func TestIsValidCaptchaType(t *testing.T) {
	valid := []string{
		"none", "recaptcha", "recaptchav2", "recaptcha-invisible",
		"hcaptcha", "turnstile", "geetest", "kasada", "imperva",
		"awswaf", "mcaptcha", "other",
	}
	for _, s := range valid {
		if !captcha.IsValidCaptchaType(s) {
			t.Errorf("expected %q to be valid", s)
		}
	}
	invalid := []string{"unknown", "RECAPTCHA", "foo", ""}
	for _, s := range invalid {
		if captcha.IsValidCaptchaType(s) {
			t.Errorf("expected %q to be invalid", s)
		}
	}
}

// TestDetectInFormRecaptcha exercises the actual detection logic with a parsed HTML form.
func TestDetectInFormRecaptcha(t *testing.T) {
	html := `<html><body>
<form method="POST" action="/submit">
  <input type="email" name="email" />
  <div class="g-recaptcha" data-sitekey="6LdXXXXXX"></div>
  <input type="submit" value="Send" />
</form>
</body></html>`

	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}
	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find a form")
	}

	detector := &captcha.CaptchaDetector{}
	ct := detector.DetectInForm(forms[0])
	if ct != captcha.CaptchaTypeRecaptcha {
		t.Errorf("expected recaptcha, got %s", ct)
	}
}

// TestDetectInFormHCaptcha exercises hCaptcha detection on a parsed form.
func TestDetectInFormHCaptcha(t *testing.T) {
	html := `<html><body>
<form method="POST" action="/login">
  <input type="text" name="user" />
  <div class="h-captcha" data-sitekey="10000000-ffff-ffff-ffff-000000000001"></div>
  <input type="submit" value="Login" />
</form>
</body></html>`

	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}
	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find a form")
	}

	detector := &captcha.CaptchaDetector{}
	ct := detector.DetectInForm(forms[0])
	if ct != captcha.CaptchaTypeHCaptcha {
		t.Errorf("expected hcaptcha, got %s", ct)
	}
}

// TestDetectInFormTurnstile exercises Cloudflare Turnstile detection on a parsed form.
func TestDetectInFormTurnstile(t *testing.T) {
	html := `<html><body>
<form method="POST" action="/verify">
  <input type="text" name="name" />
  <div class="cf-turnstile" data-sitekey="0x4XXXXXXXXXXXXXXXXX"></div>
  <input type="submit" value="Verify" />
</form>
</body></html>`

	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}
	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find a form")
	}

	detector := &captcha.CaptchaDetector{}
	ct := detector.DetectInForm(forms[0])
	if ct != captcha.CaptchaTypeTurnstile {
		t.Errorf("expected turnstile, got %s", ct)
	}
}

// TestDetectInFormNoCaptcha verifies a plain form returns no captcha.
func TestDetectInFormNoCaptcha(t *testing.T) {
	html := `<html><body>
<form method="POST" action="/search">
  <input type="text" name="q" />
  <input type="submit" value="Search" />
</form>
</body></html>`

	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}
	forms := htmlutil.GetForms(doc)
	if len(forms) == 0 {
		t.Fatal("expected to find a form")
	}

	detector := &captcha.CaptchaDetector{}
	ct := detector.DetectInForm(forms[0])
	if ct != captcha.CaptchaTypeNone {
		t.Errorf("expected none, got %s", ct)
	}
}

// TestDetectCaptchaInHTMLRecaptcha tests full-HTML page-level detection.
func TestDetectCaptchaInHTMLRecaptcha(t *testing.T) {
	html := `<html><head>
<script src="https://www.google.com/recaptcha/api.js"></script>
</head><body>
<form method="POST"><input type="text" name="user" /><div class="g-recaptcha" data-sitekey="key"></div></form>
</body></html>`

	ct := captcha.DetectCaptchaInHTML(html)
	if ct != captcha.CaptchaTypeRecaptcha {
		t.Errorf("expected recaptcha, got %s", ct)
	}
}

// TestDetectCaptchaInHTMLNone verifies no false positives on plain HTML.
func TestDetectCaptchaInHTMLNone(t *testing.T) {
	html := `<html><head><title>Hello</title></head><body><p>Welcome</p></body></html>`

	ct := captcha.DetectCaptchaInHTML(html)
	if ct != captcha.CaptchaTypeNone {
		t.Errorf("expected none, got %s", ct)
	}
}
