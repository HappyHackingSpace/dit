package cli

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/happyhackingspace/dit"
)

// Supported output formats for the run command.
const (
	formatJSON  = "json"
	formatTable = "table"
	formatCSV   = "csv"
)

// validFormat reports whether format names a supported output format.
func validFormat(format string) bool {
	switch format {
	case formatJSON, formatTable, formatCSV:
		return true
	}
	return false
}

// resultHeader is the column layout shared by table and CSV output.
var resultHeader = []string{"page_type", "captcha_type", "form", "form_type", "field", "field_type"}

// pageResultRows flattens a page classification into one row per field.
func pageResultRows(r *dit.PageResult) [][]string {
	if len(r.Forms) == 0 {
		return [][]string{{r.Type, r.Captcha, "", "", "", ""}}
	}
	var rows [][]string
	for i, f := range r.Forms {
		captcha := r.Captcha
		if f.Captcha != "" {
			captcha = f.Captcha
		}
		rows = append(rows, formRows(r.Type, captcha, i+1, f)...)
	}
	return rows
}

// formResultRows flattens form classifications into one row per field.
func formResultRows(results []dit.FormResult) [][]string {
	var rows [][]string
	for i, f := range results {
		rows = append(rows, formRows("", f.Captcha, i+1, f)...)
	}
	return rows
}

// formRows renders one form as rows, one per field, sorted by field name.
func formRows(pageType, captcha string, index int, f dit.FormResult) [][]string {
	idx := fmt.Sprintf("%d", index)
	if len(f.Fields) == 0 {
		return [][]string{{pageType, captcha, idx, f.Type, "", ""}}
	}
	names := make([]string, 0, len(f.Fields))
	for name := range f.Fields {
		names = append(names, name)
	}
	sort.Strings(names)
	rows := make([][]string, 0, len(names))
	for _, name := range names {
		rows = append(rows, []string{pageType, captcha, idx, f.Type, name, f.Fields[name]})
	}
	return rows
}

// writeTable writes header and rows as an aligned text table.
func writeTable(w io.Writer, header []string, rows [][]string) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, strings.ToUpper(strings.Join(header, "\t"))); err != nil {
		return err
	}
	for _, row := range rows {
		if _, err := fmt.Fprintln(tw, strings.Join(row, "\t")); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// writeCSV writes header and rows as CSV.
func writeCSV(w io.Writer, header []string, rows [][]string) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, row := range rows {
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// outputPageResult writes a page classification result in the given format.
func outputPageResult(w io.Writer, format string, r *dit.PageResult) error {
	switch format {
	case formatTable:
		return writeTable(w, resultHeader, pageResultRows(r))
	case formatCSV:
		return writeCSV(w, resultHeader, pageResultRows(r))
	default:
		output, _ := json.MarshalIndent(r, "", "  ")
		_, err := fmt.Fprintln(w, string(output))
		return err
	}
}

// outputFormResults writes form classification results in the given format.
func outputFormResults(w io.Writer, format string, results []dit.FormResult) error {
	switch format {
	case formatTable:
		return writeTable(w, resultHeader, formResultRows(results))
	case formatCSV:
		return writeCSV(w, resultHeader, formResultRows(results))
	default:
		output, _ := json.MarshalIndent(results, "", "  ")
		fmt.Fprintln(w, string(output))
		return nil
	}
}
