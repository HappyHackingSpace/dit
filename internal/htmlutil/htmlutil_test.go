package htmlutil

import (
	"strings"
	"testing"
)

const testHTML = `
<html><body>
<form id="login" method="POST" action="/login" class="auth-form">
  <label for="user">Username</label>
  <input type="text" name="username" id="user" title="Enter username"/>
  <label for="pass">Password</label>
  <input type="password" name="password" id="pass"/>
  <input type="hidden" name="csrf" value="abc123"/>
  <input type="submit" value="Log In"/>
  <a href="/register">Register here</a>
</form>
</body></html>
`

func TestGetForms(t *testing.T) {
	doc, err := LoadHTMLString(testHTML)
	if err != nil {
		t.Fatal(err)
	}
	forms := GetForms(doc)
	if len(forms) != 1 {
		t.Errorf("expected 1 form, got %d", len(forms))
	}
}

func TestGetVisibleFields(t *testing.T) {
	doc, _ := LoadHTMLString(testHTML)
	forms := GetForms(doc)
	fields := GetVisibleFields(forms[0])

	// Should get: text input, password input, submit input (hidden is excluded)
	if len(fields) != 3 {
		t.Errorf("expected 3 visible fields, got %d", len(fields))
		for _, f := range fields {
			name, _ := f.Attr("name")
			tp, _ := f.Attr("type")
			t.Logf("  field: name=%s type=%s", name, tp)
		}
	}
}

func TestGetFieldsToAnnotate(t *testing.T) {
	doc, _ := LoadHTMLString(testHTML)
	forms := GetForms(doc)
	fields := GetFieldsToAnnotate(forms[0])

	// Submit buttons typically don't have name attr in our test, so:
	// username + password = 2
	if len(fields) != 2 {
		t.Errorf("expected 2 annotatable fields, got %d", len(fields))
		for _, f := range fields {
			name, _ := f.Attr("name")
			t.Logf("  field: %s", name)
		}
	}
}

func TestGetTypeCounts(t *testing.T) {
	doc, _ := LoadHTMLString(testHTML)
	forms := GetForms(doc)
	counts := GetTypeCounts(forms[0])

	if counts["text"] != 1 {
		t.Errorf("text count = %d, want 1", counts["text"])
	}
	if counts["password"] != 1 {
		t.Errorf("password count = %d, want 1", counts["password"])
	}
	if counts["hidden"] != 1 {
		t.Errorf("hidden count = %d, want 1", counts["hidden"])
	}
	if counts["submit"] != 1 {
		t.Errorf("submit count = %d, want 1", counts["submit"])
	}
}

func TestGetInputCount(t *testing.T) {
	doc, _ := LoadHTMLString(testHTML)
	forms := GetForms(doc)
	count := GetInputCount(forms[0])

	// username, password, csrf = 3 unique named inputs
	if count != 3 {
		t.Errorf("input count = %d, want 3", count)
	}
}

func TestFindLabel(t *testing.T) {
	doc, _ := LoadHTMLString(testHTML)
	forms := GetForms(doc)
	fields := GetFieldsToAnnotate(forms[0])

	label := FindLabel(forms[0], fields[0]) // username field
	if label == nil {
		t.Error("expected to find label for username field")
		return
	}
	text := strings.TrimSpace(label.Text())
	if text != "Username" {
		t.Errorf("label text = %q, want %q", text, "Username")
	}
}

func TestGetFormMethod(t *testing.T) {
	doc, _ := LoadHTMLString(testHTML)
	forms := GetForms(doc)
	method := GetFormMethod(forms[0])
	if method != "post" {
		t.Errorf("method = %q, want %q", method, "post")
	}
}

func TestGetSubmitTexts(t *testing.T) {
	doc, _ := LoadHTMLString(testHTML)
	forms := GetForms(doc)
	text := GetSubmitTexts(forms[0])
	if text != "Log In" {
		t.Errorf("submit text = %q, want %q", text, "Log In")
	}
}

func TestGetLinksText(t *testing.T) {
	doc, _ := LoadHTMLString(testHTML)
	forms := GetForms(doc)
	text := GetLinksText(forms[0])
	if !strings.Contains(text, "Register here") {
		t.Errorf("links text = %q, want to contain 'Register here'", text)
	}
}

func TestGetFormCSS(t *testing.T) {
	doc, _ := LoadHTMLString(testHTML)
	forms := GetForms(doc)
	css := GetFormCSS(forms[0])
	if !strings.Contains(css, "auth-form") {
		t.Errorf("css = %q, want to contain 'auth-form'", css)
	}
	if !strings.Contains(css, "login") {
		t.Errorf("css = %q, want to contain 'login'", css)
	}
}

func TestGetTextAroundElems(t *testing.T) {
	html := `
<form>
  Some text before
  <input type="text" name="field1"/>
  Middle text
  <input type="text" name="field2"/>
  After text
</form>`
	doc, _ := LoadHTMLString(html)
	forms := GetForms(doc)
	fields := GetFieldsToAnnotate(forms[0])

	if len(fields) != 2 {
		t.Fatalf("expected 2 fields, got %d", len(fields))
	}

	ta := GetTextAroundElems(forms[0], fields)

	before1 := ta.Before[fields[0]]
	if !strings.Contains(before1, "Some text before") {
		t.Errorf("before field1 = %q, want to contain 'Some text before'", before1)
	}

	after1 := ta.After[fields[0]]
	if !strings.Contains(after1, "Middle text") {
		t.Errorf("after field1 = %q, want to contain 'Middle text'", after1)
	}

	after2 := ta.After[fields[1]]
	if !strings.Contains(after2, "After text") {
		t.Errorf("after field2 = %q, want to contain 'After text'", after2)
	}
}

func TestGetFormMethodMissing(t *testing.T) {
	html := `<form><input type="text" name="q"/></form>`
	doc, _ := LoadHTMLString(html)
	forms := GetForms(doc)
	method := GetFormMethod(forms[0])
	if method != "MISSING" {
		t.Errorf("method = %q, want %q", method, "MISSING")
	}
}
