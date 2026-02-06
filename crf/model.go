package crf

import (
	"encoding/json"
	"os"
)

// SaveModel serializes the model to JSON.
func SaveModel(model *Model, path string) error {
	data, err := json.MarshalIndent(model, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// LoadModel deserializes a model from JSON.
func LoadModel(path string) (*Model, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var model Model
	if err := json.Unmarshal(data, &model); err != nil {
		return nil, err
	}
	return &model, nil
}

// MarshalModel serializes the model to JSON bytes.
func MarshalModel(model *Model) ([]byte, error) {
	return json.Marshal(model)
}

// UnmarshalModel deserializes a model from JSON bytes.
func UnmarshalModel(data []byte) (*Model, error) {
	var model Model
	if err := json.Unmarshal(data, &model); err != nil {
		return nil, err
	}
	return &model, nil
}
