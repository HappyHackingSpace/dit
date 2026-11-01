package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/happyhackingspace/dit"
)

func samplePageResult() *dit.PageResult {
	return &dit.PageResult{
		Type:    "login",
		Captcha: "recaptcha",
		Forms: []dit.FormResult{
			{
				Type: "login",
				Fields: map[string]string{
					"username": "username or email",
					"password": "password",
				},
			},
		},
	}
}

func TestValidFormat(t *testing.T) {
	for _, f := range []string{formatJSON, formatTable, formatCSV} {
		if !validFormat(f) {
			t.Errorf("expected %q to be valid", f)
		}
	}
	for _, f := range []string{"", "xml", "JSON"} {
		if validFormat(f) {
			t.Errorf("expected %q to be invalid", f)
		}
	}
}

func TestOutputPageResultCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := outputPageResult(&buf, formatCSV, samplePageResult()); err != nil {
		t.Fatalf("outputPageResult: %v", err)
	}

	want := "page_type,captcha_type,form,form_type,field,field_type\n" +
		"login,recaptcha,1,login,password,password\n" +
		"login,recaptcha,1,login,username,username or email\n"
	if buf.String() != want {
		t.Errorf("expected:\n%s\ngot:\n%s", want, buf.String())
	}
}

func TestOutputPageResultTable(t *testing.T) {
	var buf bytes.Buffer
	if err := outputPageResult(&buf, formatTable, samplePageResult()); err != nil {
		t.Fatalf("outputPageResult: %v", err)
	}

	out := buf.String()
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, got %d:\n%s", len(lines), out)
	}
	if !strings.HasPrefix(lines[0], "PAGE_TYPE") {
		t.Errorf("expected header line, got %q", lines[0])
	}
	for _, s := range []string{"login", "recaptcha", "username or email"} {
		if !strings.Contains(out, s) {
			t.Errorf("expected output to contain %q:\n%s", s, out)
		}
	}
}

func TestOutputPageResultJSON(t *testing.T) {
	var buf bytes.Buffer
	result := samplePageResult()
	if err := outputPageResult(&buf, formatJSON, result); err != nil {
		t.Fatalf("outputPageResult: %v", err)
	}

	want, _ := json.MarshalIndent(result, "", "  ")
	if buf.String() != string(want)+"\n" {
		t.Errorf("expected:\n%s\ngot:\n%s", want, buf.String())
	}
}

func TestOutputPageResultNoForms(t *testing.T) {
	var buf bytes.Buffer
	r := &dit.PageResult{Type: "error"}
	if err := outputPageResult(&buf, formatCSV, r); err != nil {
		t.Fatalf("outputPageResult: %v", err)
	}

	want := "page_type,captcha_type,form,form_type,field,field_type\n" +
		"error,,,,,\n"
	if buf.String() != want {
		t.Errorf("expected:\n%s\ngot:\n%s", want, buf.String())
	}
}

func TestOutputFormResultsCSV(t *testing.T) {
	results := []dit.FormResult{
		{Type: "search", Fields: map[string]string{"q": "search query"}},
		{Type: "other", Captcha: "hcaptcha"},
	}

	var buf bytes.Buffer
	if err := outputFormResults(&buf, formatCSV, results); err != nil {
		t.Fatalf("outputFormResults: %v", err)
	}

	want := "page_type,captcha_type,form,form_type,field,field_type\n" +
		",,1,search,q,search query\n" +
		",hcaptcha,2,other,,\n"
	if buf.String() != want {
		t.Errorf("expected:\n%s\ngot:\n%s", want, buf.String())
	}
}
