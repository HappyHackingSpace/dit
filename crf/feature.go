package crf

import "fmt"

// FeaturesToAttributes converts a feature dict (with mixed value types)
// to CRF attribute strings with float64 values.
//
// Conversion rules:
//   - string value: "key=value" → 1.0
//   - []string value: "key:item" → 1.0 for each item
//   - bool value: "key" → 1.0 if true
//   - int/float value: "key" → float64(value)
func FeaturesToAttributes(features map[string]any) map[string]float64 {
	attrs := make(map[string]float64)
	for key, val := range features {
		switch v := val.(type) {
		case string:
			attrs[fmt.Sprintf("%s=%s", key, v)] = 1.0
		case []string:
			for _, item := range v {
				attrs[fmt.Sprintf("%s:%s", key, item)] = 1.0
			}
		case bool:
			if v {
				attrs[key] = 1.0
			}
		case int:
			attrs[key] = float64(v)
		case float64:
			attrs[key] = v
		default:
			attrs[key] = 1.0
		}
	}
	return attrs
}

// BuildAttributeAlphabet builds the attribute alphabet from training sequences.
func BuildAttributeAlphabet(sequences []TrainingSequence) *Alphabet {
	alpha := NewAlphabet()
	for _, seq := range sequences {
		for _, feats := range seq.Features {
			for attr := range feats {
				alpha.Add(attr)
			}
		}
	}
	return alpha
}

// BuildLabelAlphabet builds the label alphabet from training sequences.
func BuildLabelAlphabet(sequences []TrainingSequence) *Alphabet {
	alpha := NewAlphabet()
	for _, seq := range sequences {
		for _, label := range seq.Labels {
			alpha.Add(label)
		}
	}
	return alpha
}
