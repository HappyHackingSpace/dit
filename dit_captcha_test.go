package dit

import (
	"testing"
)

// TestFormResultCaptchaTypes tests FormResult with various CAPTCHA types
func TestFormResultCaptchaTypes(t *testing.T) {
	tests := []struct {
		name        string
		captcha     string
		formType    string
		fieldCount  int
		wantCaptcha string
	}{
		{
			name:        "recaptcha",
			captcha:     "recaptcha",
			formType:    "login",
			fieldCount:  2,
			wantCaptcha: "recaptcha",
		},
		{
			name:        "recaptchav2",
			captcha:     "recaptchav2",
			formType:    "login",
			fieldCount:  2,
			wantCaptcha: "recaptchav2",
		},
		{
			name:        "recaptcha_invisible",
			captcha:     "recaptcha-invisible",
			formType:    "contacts",
			fieldCount:  3,
			wantCaptcha: "recaptcha-invisible",
		},
		{
			name:        "hcaptcha",
			captcha:     "hcaptcha",
			formType:    "register",
			fieldCount:  3,
			wantCaptcha: "hcaptcha",
		},
		{
			name:        "turnstile",
			captcha:     "turnstile",
			formType:    "login",
			fieldCount:  2,
			wantCaptcha: "turnstile",
		},
		{
			name:        "mcaptcha",
			captcha:     "mcaptcha",
			formType:    "feedback",
			fieldCount:  2,
			wantCaptcha: "mcaptcha",
		},
		{
			name:        "kasada",
			captcha:     "kasada",
			formType:    "checkout",
			fieldCount:  4,
			wantCaptcha: "kasada",
		},
		{
			name:        "imperva",
			captcha:     "imperva",
			formType:    "banking",
			fieldCount:  3,
			wantCaptcha: "imperva",
		},
		{
			name:        "awswaf",
			captcha:     "awswaf",
			formType:    "login",
			fieldCount:  2,
			wantCaptcha: "awswaf",
		},
		{
			name:        "yandex",
			captcha:     "yandex",
			formType:    "checkout",
			fieldCount:  4,
			wantCaptcha: "yandex",
		},
		{
			name:        "no_captcha",
			captcha:     "",
			formType:    "login",
			fieldCount:  2,
			wantCaptcha: "",
		},
		{
			name:        "other_captcha",
			captcha:     "geetest",
			formType:    "checkout",
			fieldCount:  4,
			wantCaptcha: "geetest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields := make(map[string]string)
			for i := 0; i < tt.fieldCount; i++ {
				fields[string(rune('a'+i))] = "field"
			}

			result := FormResult{
				Type:    tt.formType,
				Captcha: tt.captcha,
				Fields:  fields,
			}

			// Verify Type
			if result.Type != tt.formType {
				t.Errorf("Type: got %s, want %s", result.Type, tt.formType)
			}

			// Verify Captcha is correctly set
			if result.Captcha != tt.wantCaptcha {
				t.Errorf("Captcha: got %s, want %s", result.Captcha, tt.wantCaptcha)
			}

			// Verify Fields count
			if len(result.Fields) != tt.fieldCount {
				t.Errorf("Fields count: got %d, want %d", len(result.Fields), tt.fieldCount)
			}

			// Verify all fields are present
			for key := range result.Fields {
				if result.Fields[key] != "field" {
					t.Errorf("Field %s has unexpected value: %s", key, result.Fields[key])
				}
			}
		})
	}
}

// TestFormResultFieldValidation ensures fields are properly stored and retrieved
func TestFormResultFieldValidation(t *testing.T) {
	tests := []struct {
		name   string
		fields map[string]string
	}{
		{
			name:   "login_form_fields",
			fields: map[string]string{"email": "email", "password": "password"},
		},
		{
			name:   "register_form_fields",
			fields: map[string]string{"username": "username", "email": "email", "password": "password"},
		},
		{
			name:   "single_field",
			fields: map[string]string{"q": "search"},
		},
		{
			name:   "empty_fields",
			fields: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormResult{
				Type:    "test",
				Captcha: "recaptcha",
				Fields:  tt.fields,
			}

			// Verify Type is set correctly
			if result.Type != "test" {
				t.Errorf("Type: got %s, want test", result.Type)
			}

			// Verify Captcha is set correctly
			if result.Captcha != "recaptcha" {
				t.Errorf("Captcha: got %s, want recaptcha", result.Captcha)
			}

			// Verify field count matches
			if len(result.Fields) != len(tt.fields) {
				t.Errorf("Field count mismatch: got %d, want %d", len(result.Fields), len(tt.fields))
			}

			// Verify all fields are preserved
			for key, expectedValue := range tt.fields {
				actualValue, exists := result.Fields[key]
				if !exists {
					t.Errorf("Field %s not found in result", key)
					continue
				}
				if actualValue != expectedValue {
					t.Errorf("Field %s: got %s, want %s", key, actualValue, expectedValue)
				}
			}
		})
	}
}

// TestPageResultCaptchaConsistency tests multiple forms with varying CAPTCHA configurations
func TestPageResultCaptchaConsistency(t *testing.T) {
	tests := []struct {
		name         string
		pageType     string
		forms        []FormResult
		wantFormLen  int
		captchaForms int
	}{
		{
			name:     "all_forms_with_captcha",
			pageType: "login",
			forms: []FormResult{
				{Type: "login", Captcha: "recaptcha", Fields: map[string]string{"email": "email"}},
				{Type: "admin", Captcha: "hcaptcha", Fields: map[string]string{"user": "text"}},
			},
			wantFormLen:  2,
			captchaForms: 2,
		},
		{
			name:     "mixed_captcha_forms",
			pageType: "checkout",
			forms: []FormResult{
				{Type: "billing", Captcha: "recaptcha", Fields: map[string]string{"card": "text"}},
				{Type: "shipping", Captcha: "", Fields: map[string]string{"address": "text"}},
				{Type: "review", Captcha: "turnstile", Fields: map[string]string{"confirm": "checkbox"}},
			},
			wantFormLen:  3,
			captchaForms: 2,
		},
		{
			name:     "enterprise_captchas",
			pageType: "secured",
			forms: []FormResult{
				{Type: "kasada_form", Captcha: "kasada", Fields: map[string]string{"token": "text"}},
				{Type: "imperva_form", Captcha: "imperva", Fields: map[string]string{"auth": "text"}},
				{Type: "aws_form", Captcha: "awswaf", Fields: map[string]string{"session": "text"}},
			},
			wantFormLen:  3,
			captchaForms: 3,
		},
		{
			name:     "open_source_captchas",
			pageType: "community",
			forms: []FormResult{
				{Type: "mcaptcha_form", Captcha: "mcaptcha", Fields: map[string]string{"comment": "textarea"}},
				{Type: "recaptcha_v2", Captcha: "recaptchav2", Fields: map[string]string{"feedback": "text"}},
				{Type: "invisible_form", Captcha: "recaptcha-invisible", Fields: map[string]string{"submit": "button"}},
			},
			wantFormLen:  3,
			captchaForms: 3,
		},
		{
			name:     "regional_and_enterprise_mix",
			pageType: "global_checkout",
			forms: []FormResult{
				{Type: "yandex_form", Captcha: "yandex", Fields: map[string]string{"payment": "text"}},
				{Type: "imperva_form", Captcha: "imperva", Fields: map[string]string{"auth": "text"}},
				{Type: "hcaptcha_form", Captcha: "hcaptcha", Fields: map[string]string{"verify": "text"}},
			},
			wantFormLen:  3,
			captchaForms: 3,
		},
		{
			name:         "no_forms_with_captcha",
			pageType:     "signup",
			forms:        []FormResult{{Type: "register", Captcha: "", Fields: map[string]string{"username": "text"}}},
			wantFormLen:  1,
			captchaForms: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := PageResult{
				Type:  tt.pageType,
				Forms: tt.forms,
			}

			// Verify page type
			if result.Type != tt.pageType {
				t.Errorf("Type: got %s, want %s", result.Type, tt.pageType)
			}

			// Verify form count
			if len(result.Forms) != tt.wantFormLen {
				t.Errorf("Forms count: got %d, want %d", len(result.Forms), tt.wantFormLen)
			}

			// Verify CAPTCHA forms
			captchaCount := 0
			for _, form := range result.Forms {
				if form.Captcha != "" {
					captchaCount++
				}
				// Verify each form has Type field
				if form.Type == "" {
					t.Error("Form is missing Type field")
				}
				// Verify each form has Fields map
				if form.Fields == nil {
					t.Error("Form Fields map is nil")
				}
			}

			if captchaCount != tt.captchaForms {
				t.Errorf("CAPTCHA forms count: got %d, want %d", captchaCount, tt.captchaForms)
			}
		})
	}
}

// TestFormResultProbaValidation tests probability-based form results with proper thresholds
func TestFormResultProbaValidation(t *testing.T) {
	tests := []struct {
		name           string
		formProba      map[string]float64
		captcha        string
		fieldProba     map[string]map[string]float64
		wantFormTypes  int
		wantFieldTypes int
	}{
		{
			name:      "high_confidence_login_with_recaptcha",
			formProba: map[string]float64{"login": 0.95, "admin": 0.05},
			captcha:   "recaptcha",
			fieldProba: map[string]map[string]float64{
				"email":    {"email": 0.98},
				"password": {"password": 0.97},
			},
			wantFormTypes:  2,
			wantFieldTypes: 2,
		},
		{
			name:      "medium_confidence_register",
			formProba: map[string]float64{"register": 0.65, "contact": 0.35},
			captcha:   "hcaptcha",
			fieldProba: map[string]map[string]float64{
				"username": {"username": 0.88},
				"email":    {"email": 0.92},
				"password": {"password": 0.85},
			},
			wantFormTypes:  2,
			wantFieldTypes: 3,
		},
		{
			name:      "enterprise_kasada_protection",
			formProba: map[string]float64{"checkout": 0.91},
			captcha:   "kasada",
			fieldProba: map[string]map[string]float64{
				"credit_card": {"text": 0.94},
				"cvv":         {"password": 0.89},
			},
			wantFormTypes:  1,
			wantFieldTypes: 2,
		},
		{
			name:      "imperva_banking_form",
			formProba: map[string]float64{"login": 0.88, "mfa": 0.12},
			captcha:   "imperva",
			fieldProba: map[string]map[string]float64{
				"username": {"username": 0.95},
				"password": {"password": 0.93},
			},
			wantFormTypes:  2,
			wantFieldTypes: 2,
		},
		{
			name:      "aws_waf_protection",
			formProba: map[string]float64{"api": 0.87},
			captcha:   "awswaf",
			fieldProba: map[string]map[string]float64{
				"token": {"text": 0.91},
			},
			wantFormTypes:  1,
			wantFieldTypes: 1,
		},
		{
			name:      "mcaptcha_open_source",
			formProba: map[string]float64{"feedback": 0.89},
			captcha:   "mcaptcha",
			fieldProba: map[string]map[string]float64{
				"comment": {"textarea": 0.85},
			},
			wantFormTypes:  1,
			wantFieldTypes: 1,
		},
		{
			name:      "recaptcha_v2_variant",
			formProba: map[string]float64{"contact": 0.92},
			captcha:   "recaptchav2",
			fieldProba: map[string]map[string]float64{
				"message": {"textarea": 0.90},
			},
			wantFormTypes:  1,
			wantFieldTypes: 1,
		},
		{
			name:      "recaptcha_invisible",
			formProba: map[string]float64{"newsletter": 0.85},
			captcha:   "recaptcha-invisible",
			fieldProba: map[string]map[string]float64{
				"email": {"email": 0.88},
			},
			wantFormTypes:  1,
			wantFieldTypes: 1,
		},
		{
			name:      "yandex_regional_protection",
			formProba: map[string]float64{"checkout": 0.90},
			captcha:   "yandex",
			fieldProba: map[string]map[string]float64{
				"payment": {"text": 0.92},
			},
			wantFormTypes:  1,
			wantFieldTypes: 1,
		},
		{
			name:           "no_captcha_no_fields",
			formProba:      map[string]float64{"login": 1.0},
			captcha:        "",
			fieldProba:     map[string]map[string]float64{},
			wantFormTypes:  1,
			wantFieldTypes: 0,
		},
		{
			name:      "single_field_detection",
			formProba: map[string]float64{"search": 0.99},
			captcha:   "turnstile",
			fieldProba: map[string]map[string]float64{
				"q": {"search": 0.99},
			},
			wantFormTypes:  1,
			wantFieldTypes: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormResultProba{
				Type:    tt.formProba,
				Captcha: tt.captcha,
				Fields:  tt.fieldProba,
			}

			// Verify Type count
			if len(result.Type) != tt.wantFormTypes {
				t.Errorf("Type count: got %d, want %d", len(result.Type), tt.wantFormTypes)
			}

			// Verify all probabilities are valid (0.0-1.0)
			for formType, prob := range result.Type {
				if prob < 0.0 || prob > 1.0 {
					t.Errorf("Type %s probability out of range: %v", formType, prob)
				}
			}

			// Verify Captcha is set if provided
			if result.Captcha != tt.captcha {
				t.Errorf("Captcha: got %s, want %s", result.Captcha, tt.captcha)
			}

			// Verify Fields count
			if len(result.Fields) != tt.wantFieldTypes {
				t.Errorf("Fields count: got %d, want %d", len(result.Fields), tt.wantFieldTypes)
			}

			// Verify field probabilities are valid
			for fieldName, probs := range result.Fields {
				if len(probs) == 0 {
					t.Errorf("Field %s has empty probability map", fieldName)
				}
				for fieldType, prob := range probs {
					if prob < 0.0 || prob > 1.0 {
						t.Errorf("Field %s type %s probability out of range: %v", fieldName, fieldType, prob)
					}
				}
			}
		})
	}
}

// TestPageResultProbaStructure tests the complete probability-based page result
func TestPageResultProbaStructure(t *testing.T) {
	result := PageResultProba{
		Type:    map[string]float64{"login": 0.92, "admin": 0.08},
		Captcha: "recaptcha",
		Forms: []FormResultProba{
			{
				Type:    map[string]float64{"login": 0.98},
				Captcha: "recaptcha",
				Fields: map[string]map[string]float64{
					"email":    {"email": 0.99},
					"password": {"password": 0.97},
				},
			},
		},
	}

	// Verify page Type probabilities
	if len(result.Type) != 2 {
		t.Errorf("Expected 2 page types, got %d", len(result.Type))
	}
	if result.Type["login"] != 0.92 {
		t.Errorf("Login probability: got %v, want 0.92", result.Type["login"])
	}

	// Verify page Captcha
	if result.Captcha != "recaptcha" {
		t.Errorf("Page Captcha: got %s, want recaptcha", result.Captcha)
	}

	// Verify Forms
	if len(result.Forms) != 1 {
		t.Errorf("Expected 1 form, got %d", len(result.Forms))
	}

	form := result.Forms[0]
	if len(form.Type) != 1 {
		t.Errorf("Form Type count: got %d, want 1", len(form.Type))
	}
	if form.Captcha != "recaptcha" {
		t.Errorf("Form Captcha: got %s, want recaptcha", form.Captcha)
	}
	if len(form.Fields) != 2 {
		t.Errorf("Form Fields count: got %d, want 2", len(form.Fields))
	}
}

// TestEnterpriseCaptchaTypes tests detection of enterprise-grade CAPTCHA solutions
func TestEnterpriseCaptchaTypes(t *testing.T) {
	tests := []struct {
		name        string
		captcha     string
		description string
	}{
		{
			name:        "kasada_advanced_bot_protection",
			captcha:     "kasada",
			description: "Enterprise bot management for retailers and banks",
		},
		{
			name:        "imperva_web_application_firewall",
			captcha:     "imperva",
			description: "Enterprise DDoS and application protection",
		},
		{
			name:        "aws_waf_captcha",
			captcha:     "awswaf",
			description: "AWS Web Application Firewall CAPTCHA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormResult{
				Type:    "protected_form",
				Captcha: tt.captcha,
				Fields: map[string]string{
					"username": "username",
					"password": "password",
				},
			}

			if result.Captcha != tt.captcha {
				t.Errorf("Captcha: got %s, want %s", result.Captcha, tt.captcha)
			}

			// Verify Type field is set correctly
			if result.Type != "protected_form" {
				t.Errorf("Type: got %s, want protected_form", result.Type)
			}

			if len(result.Fields) != 2 {
				t.Errorf("Fields count: got %d, want 2", len(result.Fields))
			}
		})
	}
}

// TestOpenSourceCaptchaTypes tests detection of open-source and modern CAPTCHA solutions
func TestOpenSourceCaptchaTypes(t *testing.T) {
	tests := []struct {
		name        string
		captcha     string
		description string
	}{
		{
			name:        "mcaptcha_open_source",
			captcha:     "mcaptcha",
			description: "Open-source CAPTCHA alternative",
		},
		{
			name:        "recaptcha_v2_checkbox",
			captcha:     "recaptchav2",
			description: "Google reCAPTCHA v2 (Checkbox)",
		},
		{
			name:        "recaptcha_v2_invisible",
			captcha:     "recaptcha-invisible",
			description: "Google reCAPTCHA v2 Invisible",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormResult{
				Type:    "public_form",
				Captcha: tt.captcha,
				Fields: map[string]string{
					"email": "email",
				},
			}

			if result.Captcha != tt.captcha {
				t.Errorf("Captcha: got %s, want %s", result.Captcha, tt.captcha)
			}

			// Verify Type field is set correctly
			if result.Type != "public_form" {
				t.Errorf("Type: got %s, want public_form", result.Type)
			}

			if result.Fields["email"] != "email" {
				t.Errorf("Email field mismatch")
			}
		})
	}
}

// TestYandexCaptchaDetection tests Yandex SmartCaptcha and regional deployment scenarios
func TestYandexCaptchaDetection(t *testing.T) {
	tests := []struct {
		name        string
		captcha     string
		description string
		deplyRegion string
	}{
		{
			name:        "yandex_smartcaptcha",
			captcha:     "yandex",
			description: "Yandex SmartCaptcha - Russian behavioral CAPTCHA",
			deplyRegion: "russia",
		},
		{
			name:        "yandex_global",
			captcha:     "yandex",
			description: "Yandex SmartCaptcha - Global deployment",
			deplyRegion: "global",
		},
		{
			name:        "yandex_enterprise",
			captcha:     "yandex",
			description: "Yandex SmartCaptcha - Enterprise use",
			deplyRegion: "enterprise",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := FormResult{
				Type:    "payment_form",
				Captcha: tt.captcha,
				Fields: map[string]string{
					"payment_token": "text",
					"card_number":   "text",
				},
			}

			// Verify Captcha field
			if result.Captcha != "yandex" {
				t.Errorf("Captcha: got %s, want yandex", result.Captcha)
			}

			// Verify Type field
			if result.Type != "payment_form" {
				t.Errorf("Type: got %s, want payment_form", result.Type)
			}

			// Verify Fields are preserved
			if len(result.Fields) != 2 {
				t.Errorf("Fields count: got %d, want 2", len(result.Fields))
			}

			if result.Fields["payment_token"] != "text" {
				t.Errorf("payment_token field mismatch")
			}

			if result.Fields["card_number"] != "text" {
				t.Errorf("card_number field mismatch")
			}
		})
	}
}

// TestMultiCaptchaPage tests a page with mixed CAPTCHA types across forms
func TestMultiCaptchaPage(t *testing.T) {
	result := PageResult{
		Type:    "ecommerce",
		Captcha: "kasada", // Page-level captcha is the first detected
		Forms: []FormResult{
			{Type: "login", Captcha: "kasada", Fields: map[string]string{"user": "text", "pass": "password"}},
			{Type: "checkout", Captcha: "turnstile", Fields: map[string]string{"card": "text"}},
			{Type: "billing", Captcha: "imperva", Fields: map[string]string{"address": "textarea"}},
			{Type: "shipping", Captcha: "", Fields: map[string]string{"email": "email"}},
		},
	}

	// Verify page level
	if result.Type != "ecommerce" {
		t.Errorf("Page type: got %s, want ecommerce", result.Type)
	}

	if result.Captcha != "kasada" {
		t.Errorf("Page captcha: got %s, want kasada", result.Captcha)
	}

	// Verify forms
	if len(result.Forms) != 4 {
		t.Errorf("Forms count: got %d, want 4", len(result.Forms))
	}

	// Verify specific forms have correct CAPTCHA types
	expectedCaptchas := map[int]string{
		0: "kasada",
		1: "turnstile",
		2: "imperva",
		3: "",
	}

	for idx, expectedCaptcha := range expectedCaptchas {
		if result.Forms[idx].Captcha != expectedCaptcha {
			t.Errorf("Form %d captcha: got %s, want %s", idx, result.Forms[idx].Captcha, expectedCaptcha)
		}
	}
}
