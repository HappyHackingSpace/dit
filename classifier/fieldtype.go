package classifier

import (
	"github.com/PuerkitoBio/goquery"
	"github.com/happyhackingspace/dit/crf"
	"github.com/happyhackingspace/dit/internal/htmlutil"
)

// FieldTypeModel wraps a CRF model for field type classification.
type FieldTypeModel struct {
	CRF *crf.Model
}

// Classify returns field types for a form given the form type.
func (m *FieldTypeModel) Classify(form *goquery.Selection, formType string) map[string]string {
	fieldElems := htmlutil.GetFieldsToAnnotate(form)
	if len(fieldElems) == 0 {
		return nil
	}

	rawFeatures := GetFormFeatures(form, formType, fieldElems)

	// Convert to CRF attributes
	crfFeatures := make([]map[string]float64, len(rawFeatures))
	for i, feat := range rawFeatures {
		crfFeatures[i] = crf.FeaturesToAttributes(feat)
	}

	// Predict
	labels := m.CRF.Predict(crfFeatures)

	// Map labels back to field names
	result := make(map[string]string, len(fieldElems))
	for i, elem := range fieldElems {
		name, _ := elem.Attr("name")
		if i < len(labels) {
			result[name] = labels[i]
		}
	}
	return result
}

// ClassifyProba returns field type probabilities for a form.
func (m *FieldTypeModel) ClassifyProba(form *goquery.Selection, formType string) map[string]map[string]float64 {
	fieldElems := htmlutil.GetFieldsToAnnotate(form)
	if len(fieldElems) == 0 {
		return nil
	}

	rawFeatures := GetFormFeatures(form, formType, fieldElems)

	crfFeatures := make([]map[string]float64, len(rawFeatures))
	for i, feat := range rawFeatures {
		crfFeatures[i] = crf.FeaturesToAttributes(feat)
	}

	marginals := m.CRF.PredictMarginals(crfFeatures)

	result := make(map[string]map[string]float64, len(fieldElems))
	for i, elem := range fieldElems {
		name, _ := elem.Attr("name")
		if i < len(marginals) {
			result[name] = marginals[i]
		}
	}
	return result
}

// TrainFieldType trains a CRF model for field type classification.
func TrainFieldType(sequences []crf.TrainingSequence, config crf.TrainerConfig) *FieldTypeModel {
	crfModel := crf.Train(sequences, config)
	return &FieldTypeModel{CRF: crfModel}
}
