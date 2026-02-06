package classifier

import (
	"strings"
	"testing"

	"github.com/happyhackingspace/dit/internal/htmlutil"
)

func TestFormFeatureExtractors(t *testing.T) {
	html := `
<form method="POST" action="/login" class="auth-form" id="loginForm">
  <label for="user">Username</label>
  <input type="text" name="username" id="user" title="Enter username" class="input-text"/>
  <label for="pass">Password</label>
  <input type="password" name="password" id="pass"/>
  <input type="hidden" name="csrf" value="abc"/>
  <input type="submit" value="Log In"/>
  <a href="/register">Register here</a>
</form>`

	doc, err := htmlutil.LoadHTMLString(html)
	if err != nil {
		t.Fatal(err)
	}
	forms := htmlutil.GetForms(doc)
	form := forms[0]

	// Test FormElements
	fe := FormElements{}
	feats := fe.ExtractDict(form)
	if feats["exactly one <input type=password>"] != true {
		t.Error("expected exactly one password")
	}
	if feats["exactly one <input type=text>"] != true {
		t.Error("expected exactly one text")
	}

	// Test SubmitText
	st := SubmitText{}
	text := st.ExtractString(form)
	if !strings.Contains(text, "Log In") {
		t.Errorf("submit text = %q, want 'Log In'", text)
	}

	// Test FormLinksText
	lt := FormLinksText{}
	linksText := lt.ExtractString(form)
	if !strings.Contains(linksText, "Register here") {
		t.Errorf("links text = %q", linksText)
	}

	// Test FormURL
	fu := FormURL{}
	urlFeat := fu.ExtractString(form)
	if urlFeat == "" {
		t.Error("expected non-empty URL feature")
	}

	// Test FormCSS
	fc := FormCSS{}
	css := fc.ExtractString(form)
	if !strings.Contains(css, "auth-form") {
		t.Errorf("css = %q", css)
	}

	// Test FormInputNames
	fin := FormInputNames{}
	names := fin.ExtractString(form)
	if !strings.Contains(names, "username") {
		t.Errorf("input names = %q", names)
	}
}

func TestElemFeatures(t *testing.T) {
	html := `
<form>
  <label for="email">Email address</label>
  <input type="email" name="email" id="email" placeholder="Enter email" class="form-control"/>
  <select name="country">
    <option value="us">United States</option>
    <option value="uk">United Kingdom</option>
  </select>
</form>`

	doc, _ := htmlutil.LoadHTMLString(html)
	forms := htmlutil.GetForms(doc)
	fields := htmlutil.GetFieldsToAnnotate(forms[0])

	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(fields))
	}

	// Test email input features
	feat := ElemFeatures(fields[0], forms[0])
	if feat["tag"] != "input" {
		t.Errorf("tag = %v", feat["tag"])
	}
	if feat["input-type"] != "email" {
		t.Errorf("input-type = %v", feat["input-type"])
	}

	// Test select features
	selectFeat := ElemFeatures(fields[1], forms[0])
	if selectFeat["tag"] != "select" {
		t.Errorf("tag = %v", selectFeat["tag"])
	}
	optTexts, ok := selectFeat["option-text"].([]string)
	if !ok || len(optTexts) == 0 {
		t.Error("expected option-text")
	}
}

func TestGetFormFeatures(t *testing.T) {
	html := `
<form>
  Text before field
  <input type="text" name="username"/>
  Text between
  <input type="password" name="password"/>
  Text after
</form>`

	doc, _ := htmlutil.LoadHTMLString(html)
	forms := htmlutil.GetForms(doc)
	feats := GetFormFeatures(forms[0], "login", nil)

	if len(feats) != 2 {
		t.Fatalf("expected 2 feature dicts, got %d", len(feats))
	}

	// First field should have is-first
	if feats[0]["is-first"] != true {
		t.Error("expected is-first on first field")
	}
	if _, ok := feats[0]["is-last"]; ok {
		t.Error("first field should not have is-last")
	}

	// Last field should have is-last
	if feats[1]["is-last"] != true {
		t.Error("expected is-last on last field")
	}

	// Both should have form-type
	if feats[0]["form-type"] != "login" {
		t.Errorf("form-type = %v", feats[0]["form-type"])
	}

	// Both should have bias
	if feats[0]["bias"] != 1 {
		t.Errorf("bias = %v", feats[0]["bias"])
	}
}
