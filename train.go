package dit

import (
	"fmt"

	"github.com/PuerkitoBio/goquery"
	"github.com/happyhackingspace/dit/classifier"
	"github.com/happyhackingspace/dit/crf"
	"github.com/happyhackingspace/dit/internal/htmlutil"
	"github.com/happyhackingspace/dit/internal/storage"
)

// TrainConfig holds configuration for training.
type TrainConfig struct {
	Verbose bool
}

// EvalConfig holds configuration for evaluation.
type EvalConfig struct {
	Folds   int
	Verbose bool
}

// EvalResult holds cross-validation evaluation results.
type EvalResult struct {
	FormAccuracy     float64
	FieldAccuracy    float64
	SequenceAccuracy float64
	FormCorrect      int
	FormTotal        int
	FieldCorrect     int
	FieldTotal       int
	SequenceCorrect  int
	SequenceTotal    int
}

// Train trains a classifier on annotated HTML forms in the given data directory.
func Train(dataDir string, config *TrainConfig) (*Classifier, error) {
	verbose := false
	if config != nil {
		verbose = config.Verbose
	}

	store := storage.NewStorage(dataDir)
	opts := storage.DefaultIterOptions()
	opts.Verbose = verbose
	annotations, err := store.IterAnnotations(opts)
	if err != nil {
		return nil, fmt.Errorf("dit: %w", err)
	}
	if len(annotations) == 0 {
		return nil, fmt.Errorf("dit: no annotations found in %s", dataDir)
	}

	// Train form type classifier
	formAnnotations := filterFormAnnotated(annotations)
	forms, formLabels := extractFormTrainingData(formAnnotations)
	formConfig := classifier.DefaultFormTypeTrainConfig()
	formConfig.Verbose = verbose
	formModel := classifier.TrainFormType(forms, formLabels, formConfig)

	// Train field type classifier
	fieldAnnotations := filterFieldAnnotated(annotations)
	var fieldModel *classifier.FieldTypeModel
	if len(fieldAnnotations) > 0 {
		crfSequences, _ := buildCRFSequences(fieldAnnotations)
		crfConfig := crf.DefaultTrainerConfig()
		crfConfig.Verbose = verbose
		fieldModel = classifier.TrainFieldType(crfSequences, crfConfig)
	}

	fc := &classifier.FormFieldClassifier{
		FormModel:  formModel,
		FieldModel: fieldModel,
	}
	return &Classifier{fc: fc}, nil
}

// Evaluate runs cross-validation evaluation on annotated data.
func Evaluate(dataDir string, config *EvalConfig) (*EvalResult, error) {
	nFolds := 10
	verbose := false
	if config != nil {
		if config.Folds > 0 {
			nFolds = config.Folds
		}
		verbose = config.Verbose
	}

	store := storage.NewStorage(dataDir)
	opts := storage.DefaultIterOptions()
	opts.Verbose = verbose
	annotations, err := store.IterAnnotations(opts)
	if err != nil {
		return nil, fmt.Errorf("dit: %w", err)
	}
	if len(annotations) == 0 {
		return nil, fmt.Errorf("dit: no annotations found in %s", dataDir)
	}

	result := &EvalResult{}

	// Evaluate form types
	formAnnotations := filterFormAnnotated(annotations)
	if len(formAnnotations) > 0 {
		forms, labels := extractFormTrainingData(formAnnotations)
		groups := domainGroups(formAnnotations)
		folds := groupKFold(groups, nFolds)

		for _, testIdx := range folds {
			testSet := makeTestSet(len(forms), testIdx)
			trainForms, trainLabels := filterByIndex(forms, labels, testSet, false)
			model := classifier.TrainFormType(trainForms, trainLabels, classifier.DefaultFormTypeTrainConfig())

			for _, idx := range testIdx {
				if model.Classify(forms[idx]) == labels[idx] {
					result.FormCorrect++
				}
				result.FormTotal++
			}
		}
		if result.FormTotal > 0 {
			result.FormAccuracy = float64(result.FormCorrect) / float64(result.FormTotal)
		}
	}

	// Evaluate field types
	fieldAnnotations := filterFieldAnnotated(annotations)
	if len(fieldAnnotations) > 0 {
		sequences, keptAnnotations := buildCRFSequences(fieldAnnotations)
		groups := domainGroups(keptAnnotations)
		folds := groupKFold(groups, nFolds)

		for _, testIdx := range folds {
			testSet := makeTestSet(len(sequences), testIdx)
			var trainSeqs []crf.TrainingSequence
			for i, seq := range sequences {
				if !testSet[i] {
					trainSeqs = append(trainSeqs, seq)
				}
			}

			crfConfig := crf.DefaultTrainerConfig()
			fieldModel := classifier.TrainFieldType(trainSeqs, crfConfig)

			for _, idx := range testIdx {
				seq := sequences[idx]
				pred := fieldModel.CRF.Predict(seq.Features)
				allCorrect := true
				for j := range seq.Labels {
					if j < len(pred) && pred[j] == seq.Labels[j] {
						result.FieldCorrect++
					} else {
						allCorrect = false
					}
					result.FieldTotal++
				}
				if allCorrect {
					result.SequenceCorrect++
				}
				result.SequenceTotal++
			}
		}
		if result.FieldTotal > 0 {
			result.FieldAccuracy = float64(result.FieldCorrect) / float64(result.FieldTotal)
		}
		if result.SequenceTotal > 0 {
			result.SequenceAccuracy = float64(result.SequenceCorrect) / float64(result.SequenceTotal)
		}
	}

	return result, nil
}

// --- private helpers (moved from cmd/dit/main.go) ---

func filterFormAnnotated(annotations []storage.FormAnnotation) []storage.FormAnnotation {
	var result []storage.FormAnnotation
	for _, a := range annotations {
		if a.FormAnnotated {
			result = append(result, a)
		}
	}
	return result
}

func filterFieldAnnotated(annotations []storage.FormAnnotation) []storage.FormAnnotation {
	var result []storage.FormAnnotation
	for _, a := range annotations {
		if a.FieldsAnnotated {
			result = append(result, a)
		}
	}
	return result
}

func extractFormTrainingData(annotations []storage.FormAnnotation) ([]*goquery.Selection, []string) {
	forms := make([]*goquery.Selection, len(annotations))
	labels := make([]string, len(annotations))

	for i, ann := range annotations {
		doc, err := htmlutil.LoadHTMLString("<form>" + ann.FormHTML + "</form>")
		if err != nil {
			continue
		}
		formSel := doc.Find("form").First()
		forms[i] = formSel
		labels[i] = ann.TypeFull
	}
	return forms, labels
}

func buildCRFSequences(annotations []storage.FormAnnotation) ([]crf.TrainingSequence, []storage.FormAnnotation) {
	var sequences []crf.TrainingSequence
	var kept []storage.FormAnnotation

	for _, ann := range annotations {
		doc, err := htmlutil.LoadHTMLString("<form>" + ann.FormHTML + "</form>")
		if err != nil {
			continue
		}
		form := doc.Find("form").First()

		formType := ann.TypeFull

		fieldElems := htmlutil.GetFieldsToAnnotate(form)
		if len(fieldElems) == 0 {
			continue
		}

		rawFeats := classifier.GetFormFeatures(form, formType, fieldElems)

		crfFeatures := make([]map[string]float64, len(rawFeats))
		crfLabels := make([]string, len(rawFeats))

		for j, feat := range rawFeats {
			crfFeatures[j] = crf.FeaturesToAttributes(feat)
			name, _ := fieldElems[j].Attr("name")
			if label, ok := ann.FieldTypesFull[name]; ok {
				crfLabels[j] = label
			} else if label, ok := ann.FieldTypes[name]; ok {
				crfLabels[j] = label
			} else {
				crfLabels[j] = "other"
			}
		}

		seq := crf.TrainingSequence{
			Features: crfFeatures,
			Labels:   crfLabels,
		}
		sequences = append(sequences, seq)
		kept = append(kept, ann)
	}

	return sequences, kept
}

func groupKFold(groups []int, nFolds int) [][]int {
	uniqueGroups := make(map[int]bool)
	for _, g := range groups {
		uniqueGroups[g] = true
	}
	sortedGroups := make([]int, 0, len(uniqueGroups))
	for g := range uniqueGroups {
		sortedGroups = append(sortedGroups, g)
	}

	if nFolds > len(sortedGroups) {
		nFolds = len(sortedGroups)
	}

	groupToFold := make(map[int]int)
	for i, g := range sortedGroups {
		groupToFold[g] = i % nFolds
	}

	folds := make([][]int, nFolds)
	for i, g := range groups {
		fold := groupToFold[g]
		folds[fold] = append(folds[fold], i)
	}
	return folds
}

func domainGroups(annotations []storage.FormAnnotation) []int {
	groups := make([]int, len(annotations))
	domainMap := make(map[string]int)
	for i, ann := range annotations {
		domain := storage.GetDomain(ann.URL)
		if _, ok := domainMap[domain]; !ok {
			domainMap[domain] = len(domainMap)
		}
		groups[i] = domainMap[domain]
	}
	return groups
}

func makeTestSet(n int, testIdx []int) []bool {
	set := make([]bool, n)
	for _, i := range testIdx {
		set[i] = true
	}
	return set
}

func filterByIndex(forms []*goquery.Selection, labels []string, testSet []bool, isTest bool) ([]*goquery.Selection, []string) {
	var outForms []*goquery.Selection
	var outLabels []string
	for i := range forms {
		if testSet[i] == isTest {
			outForms = append(outForms, forms[i])
			outLabels = append(outLabels, labels[i])
		}
	}
	return outForms, outLabels
}
