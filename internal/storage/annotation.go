// Package storage provides access to annotation data for form classification training.
package storage

// AnnotationSchema holds the types and their mappings for form or field annotations.
type AnnotationSchema struct {
	Types       map[string]string // full_name -> short_name
	TypesInv    map[string]string // short_name -> full_name
	NAValue     string
	SkipValue   string
	SimplifyMap map[string]string
}

// FormAnnotation represents a single annotated form.
type FormAnnotation struct {
	FormHTML       string
	URL            string
	Type           string            // short form type
	TypeFull       string            // full form type
	FormIndex      int               // index of form on the page
	FieldTypes     map[string]string // field_name -> short_type
	FieldTypesFull map[string]string // field_name -> full_type
	FormSchema     *AnnotationSchema
	FieldSchema    *AnnotationSchema

	// Computed
	FormAnnotated   bool
	FieldsAnnotated bool
}
