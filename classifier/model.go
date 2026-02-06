package classifier

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/happyhackingspace/dit/crf"
)

// UnifiedModel holds both form and field models for serialization.
type UnifiedModel struct {
	FormModel  *FormTypeModel `json:"form_model"`
	FieldModel *crf.Model     `json:"field_model"`
}

// SaveModel saves the classifier to disk.
func (c *FormFieldClassifier) SaveModel(path string) error {
	um := UnifiedModel{
		FormModel: c.FormModel,
	}
	if c.FieldModel != nil {
		um.FieldModel = c.FieldModel.CRF
	}

	data, err := json.MarshalIndent(um, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal model: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	return os.WriteFile(path, data, 0644)
}

// LoadClassifier loads a FormFieldClassifier from disk.
func LoadClassifier(path string) (*FormFieldClassifier, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read model: %w", err)
	}

	var um UnifiedModel
	if err := json.Unmarshal(data, &um); err != nil {
		return nil, fmt.Errorf("unmarshal model: %w", err)
	}

	c := &FormFieldClassifier{
		FormModel: um.FormModel,
	}

	if um.FormModel != nil {
		um.FormModel.InitRuntime()
	}

	if um.FieldModel != nil {
		c.FieldModel = &FieldTypeModel{CRF: um.FieldModel}
	}

	return c, nil
}
