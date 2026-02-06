package storage

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"

	"github.com/happyhackingspace/dit/internal/htmlutil"
)

// Storage wraps the annotation data folder.
type Storage struct {
	Folder string
}

// NewStorage creates a Storage for the given data folder.
func NewStorage(folder string) *Storage {
	return &Storage{Folder: folder}
}

// configJSON is the structure of config.json.
type configJSON struct {
	FormTypes  typeConfig `json:"form_types"`
	FieldTypes typeConfig `json:"field_types"`
}

type typeConfig struct {
	Types       []typeEntry       `json:"types"`
	NAValue     string            `json:"NA_value"`
	SkipValue   string            `json:"skip_value"`
	SimplifyMap map[string]string `json:"simplify_map"`
}

type typeEntry struct {
	Full  string `json:"full"`
	Short string `json:"short"`
}

// indexEntry represents a single entry in index.json.
type indexEntry struct {
	URL               string              `json:"url"`
	Forms             []string            `json:"forms"`
	VisibleHTMLFields []map[string]string `json:"visible_html_fields"`
}

// GetConfig reads the config file.
func (s *Storage) GetConfig() (*configJSON, error) {
	data, err := os.ReadFile(filepath.Join(s.Folder, "config.json"))
	if err != nil {
		return nil, err
	}
	var config configJSON
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	return &config, nil
}

// GetFormSchema returns the form annotation schema.
func (s *Storage) GetFormSchema() (*AnnotationSchema, error) {
	config, err := s.GetConfig()
	if err != nil {
		return nil, err
	}
	return buildSchema(config.FormTypes), nil
}

// GetFieldSchema returns the field annotation schema.
func (s *Storage) GetFieldSchema() (*AnnotationSchema, error) {
	config, err := s.GetConfig()
	if err != nil {
		return nil, err
	}
	return buildSchema(config.FieldTypes), nil
}

func buildSchema(tc typeConfig) *AnnotationSchema {
	types := make(map[string]string, len(tc.Types))
	typesInv := make(map[string]string, len(tc.Types))
	for _, t := range tc.Types {
		types[t.Full] = t.Short
		typesInv[t.Short] = t.Full
	}
	return &AnnotationSchema{
		Types:       types,
		TypesInv:    typesInv,
		NAValue:     tc.NAValue,
		SkipValue:   tc.SkipValue,
		SimplifyMap: tc.SimplifyMap,
	}
}

// GetIndex reads the index file.
func (s *Storage) GetIndex() (map[string]indexEntry, error) {
	data, err := os.ReadFile(filepath.Join(s.Folder, "index.json"))
	if err != nil {
		return nil, err
	}
	var index map[string]indexEntry
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, err
	}
	return index, nil
}

// IterAnnotations yields FormAnnotation objects from the storage.
func (s *Storage) IterAnnotations(opts IterOptions) ([]FormAnnotation, error) {
	formSchema, err := s.GetFormSchema()
	if err != nil {
		return nil, fmt.Errorf("get form schema: %w", err)
	}
	fieldSchema, err := s.GetFieldSchema()
	if err != nil {
		return nil, fmt.Errorf("get field schema: %w", err)
	}
	index, err := s.GetIndex()
	if err != nil {
		return nil, fmt.Errorf("get index: %w", err)
	}

	// Sort by domain + path for deterministic ordering
	type pathInfo struct {
		path string
		info indexEntry
	}
	sorted := make([]pathInfo, 0, len(index))
	for path, info := range index {
		sorted = append(sorted, pathInfo{path, info})
	}
	sort.Slice(sorted, func(i, j int) bool {
		di := GetDomain(sorted[i].info.URL)
		dj := GetDomain(sorted[j].info.URL)
		if di != dj {
			return di < dj
		}
		return sorted[i].path < sorted[j].path
	})

	seen := make(map[string]bool)
	var annotations []FormAnnotation

	for _, pi := range sorted {
		htmlPath := filepath.Join(s.Folder, pi.path)
		htmlData, err := os.ReadFile(htmlPath)
		if err != nil {
			slog.Warn("Cannot read annotation file", "path", pi.path, "error", err)
			continue
		}

		doc, err := htmlutil.LoadHTMLString(string(htmlData))
		if err != nil {
			continue
		}

		forms := htmlutil.GetForms(doc)

		for idx, form := range forms {
			if idx >= len(pi.info.Forms) {
				break
			}

			tp := pi.info.Forms[idx]

			if opts.SimplifyFormTypes {
				if simplified, ok := formSchema.SimplifyMap[tp]; ok {
					tp = simplified
				}
			}

			if opts.DropNA && tp == formSchema.NAValue {
				continue
			}
			if opts.DropSkipped && tp == formSchema.SkipValue {
				continue
			}

			// Deduplication by form content hash
			if opts.DropDuplicates {
				formHTML, _ := form.Html()
				hash := fmt.Sprintf("%x", md5.Sum([]byte(formHTML)))
				if seen[hash] {
					continue
				}
				seen[hash] = true
			}

			// Build field types
			var fieldTypes, fieldTypesFull map[string]string
			fieldsAnnotated := false
			if idx < len(pi.info.VisibleHTMLFields) && pi.info.VisibleHTMLFields[idx] != nil {
				rawFields := pi.info.VisibleHTMLFields[idx]
				fieldTypes = make(map[string]string, len(rawFields))
				fieldTypesFull = make(map[string]string, len(rawFields))
				allAnnotated := true
				for name, ftp := range rawFields {
					if opts.SimplifyFieldTypes {
						if simplified, ok := fieldSchema.SimplifyMap[ftp]; ok {
							ftp = simplified
						}
					}
					if ftp == fieldSchema.NAValue {
						allAnnotated = false
					}
					fieldTypes[name] = ftp
					if full, ok := fieldSchema.TypesInv[ftp]; ok {
						fieldTypesFull[name] = full
					} else {
						fieldTypesFull[name] = ftp
					}
				}
				fieldsAnnotated = allAnnotated && len(rawFields) > 0
			}

			// Get full form type name
			typeFull := tp
			if full, ok := formSchema.TypesInv[tp]; ok {
				typeFull = full
			}

			formHTML, _ := form.Html()
			ann := FormAnnotation{
				FormHTML:        formHTML,
				URL:             pi.info.URL,
				Type:            tp,
				TypeFull:        typeFull,
				FormIndex:       idx,
				FieldTypes:      fieldTypes,
				FieldTypesFull:  fieldTypesFull,
				FormSchema:      formSchema,
				FieldSchema:     fieldSchema,
				FormAnnotated:   tp != formSchema.NAValue,
				FieldsAnnotated: fieldsAnnotated,
			}
			annotations = append(annotations, ann)
		}
	}

	return annotations, nil
}

// IterOptions controls annotation iteration behavior.
type IterOptions struct {
	DropDuplicates     bool
	DropNA             bool
	DropSkipped        bool
	SimplifyFormTypes  bool
	SimplifyFieldTypes bool
	Verbose            bool
}

// DefaultIterOptions returns the default options for iterating annotations.
func DefaultIterOptions() IterOptions {
	return IterOptions{
		DropDuplicates:     true,
		DropNA:             true,
		DropSkipped:        true,
		SimplifyFormTypes:  true,
		SimplifyFieldTypes: true,
	}
}

// GetDomain extracts the domain name from a URL (for grouped cross-validation).
func GetDomain(rawURL string) string {
	// Extract host from URL
	host := rawURL
	if idx := strings.Index(host, "://"); idx >= 0 {
		host = host[idx+3:]
	}
	if idx := strings.Index(host, "/"); idx >= 0 {
		host = host[:idx]
	}
	if idx := strings.Index(host, ":"); idx >= 0 {
		host = host[:idx]
	}

	// Use publicsuffix to find the eTLD+1, then extract just the domain
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return host
	}
	// domain is like "example.co.uk", we want just "example"
	if idx := strings.Index(domain, "."); idx >= 0 {
		return domain[:idx]
	}
	return domain
}
