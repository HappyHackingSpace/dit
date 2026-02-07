package dit

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

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
	PageAccuracy     float64
	FormCorrect      int
	FormTotal        int
	FieldCorrect     int
	FieldTotal       int
	SequenceCorrect  int
	SequenceTotal    int
	PageCorrect      int
	PageTotal        int
	// Per-class metrics
	PageConfusion  map[string]map[string]int
	PageClasses    []string
	PagePrecision  map[string]float64
	PageRecall     map[string]float64
	PageF1         map[string]float64
	PageMacroF1    float64
	PageWeightedF1 float64
}

// Train trains a classifier on annotated HTML forms in the given data directory.
func Train(dataDir string, config *TrainConfig) (*Classifier, error) {
	verbose := false
	if config != nil {
		verbose = config.Verbose
	}

	store := storage.NewStorage(filepath.Join(dataDir, "forms"))
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

	// Train page type classifier (if page data exists)
	var pageModel *classifier.PageTypeModel
	pagesDir := filepath.Join(dataDir, "pages")
	if _, err := os.Stat(filepath.Join(pagesDir, "index.json")); err == nil {
		pageStore := storage.NewPageStorage(pagesDir)
		pageOpts := storage.DefaultIterOptions()
		pageOpts.Verbose = verbose
		pageAnnotations, err := pageStore.IterPageAnnotations(pageOpts)
		if err != nil {
			slog.Warn("Failed to load page annotations", "error", err)
		} else if len(pageAnnotations) > 0 {
			slog.Info("Training page type classifier", "annotations", len(pageAnnotations))
			docs, formResults, urls, labels := extractPageTrainingData(pageAnnotations, formModel)
			pageConfig := classifier.DefaultPageTypeTrainConfig()
			pageConfig.Verbose = verbose
			pageModel = classifier.TrainPageType(docs, formResults, urls, labels, pageConfig)
		}
	}

	fc := &classifier.FormFieldClassifier{
		FormModel:  formModel,
		FieldModel: fieldModel,
		PageModel:  pageModel,
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

	store := storage.NewStorage(filepath.Join(dataDir, "forms"))
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

	// Evaluate page types (if page data exists)
	pagesDir := filepath.Join(dataDir, "pages")
	if _, err := os.Stat(filepath.Join(pagesDir, "index.json")); err == nil {
		pageStore := storage.NewPageStorage(pagesDir)
		pageOpts := storage.DefaultIterOptions()
		pageOpts.Verbose = verbose
		pageAnnotations, err := pageStore.IterPageAnnotations(pageOpts)
		if err != nil {
			slog.Warn("Failed to load page annotations for evaluation", "error", err)
		} else if len(pageAnnotations) > 0 {
			docs, formResults, urls, labels := extractPageTrainingData(pageAnnotations, nil)
			groups := pageDomainGroups(pageAnnotations)
			folds := groupKFold(groups, nFolds)

			result.PageConfusion = make(map[string]map[string]int)
			classSet := make(map[string]bool)
			for _, l := range labels {
				classSet[l] = true
			}
			for cls := range classSet {
				result.PageConfusion[cls] = make(map[string]int)
				result.PageClasses = append(result.PageClasses, cls)
			}

			for _, testIdx := range folds {
				testSet := makeTestSet(len(docs), testIdx)
				trainDocs, trainFormResults, trainURLs, trainLabels := filterPageByIndex(docs, formResults, urls, labels, testSet, false)
				pageConfig := classifier.DefaultPageTypeTrainConfig()

				// Train form model for this fold to get form features
				formStore := storage.NewStorage(filepath.Join(dataDir, "forms"))
				formOpts := storage.DefaultIterOptions()
				formAnns, _ := formStore.IterAnnotations(formOpts)
				formAnnotated := filterFormAnnotated(formAnns)
				trainForms, trainFormLabels := extractFormTrainingData(formAnnotated)
				foldFormModel := classifier.TrainFormType(trainForms, trainFormLabels, classifier.DefaultFormTypeTrainConfig())

				// Get form results for training docs
				for i, doc := range trainDocs {
					trainFormResults[i] = classifyFormsOnDoc(foldFormModel, doc)
				}

				pageModel := classifier.TrainPageType(trainDocs, trainFormResults, trainURLs, trainLabels, pageConfig)

				for _, idx := range testIdx {
					formRes := classifyFormsOnDoc(foldFormModel, docs[idx])
					pred := pageModel.Classify(docs[idx], formRes)
					true_ := labels[idx]
					if pred == true_ {
						result.PageCorrect++
					}
					result.PageConfusion[true_][pred]++
					result.PageTotal++
				}
			}
			if result.PageTotal > 0 {
				result.PageAccuracy = float64(result.PageCorrect) / float64(result.PageTotal)
				result.PagePrecision, result.PageRecall, result.PageF1, result.PageMacroF1, result.PageWeightedF1 = computeMetrics(result.PageConfusion, result.PageClasses)
			}
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

// --- page classifier helpers ---

func extractPageTrainingData(annotations []storage.PageAnnotation, formModel *classifier.FormTypeModel) ([]*goquery.Document, [][]classifier.ClassifyResult, []string, []string) {
	docs := make([]*goquery.Document, 0, len(annotations))
	formResults := make([][]classifier.ClassifyResult, 0, len(annotations))
	urls := make([]string, 0, len(annotations))
	labels := make([]string, 0, len(annotations))

	for _, ann := range annotations {
		doc, err := htmlutil.LoadHTMLString(ann.HTML)
		if err != nil {
			continue
		}

		var results []classifier.ClassifyResult
		if formModel != nil {
			results = classifyFormsOnDoc(formModel, doc)
		}

		docs = append(docs, doc)
		formResults = append(formResults, results)
		urls = append(urls, ann.URL)
		labels = append(labels, ann.TypeFull)
	}

	return docs, formResults, urls, labels
}

func classifyFormsOnDoc(formModel *classifier.FormTypeModel, doc *goquery.Document) []classifier.ClassifyResult {
	forms := htmlutil.GetForms(doc)
	results := make([]classifier.ClassifyResult, len(forms))
	for i, form := range forms {
		results[i] = classifier.ClassifyResult{
			Form: formModel.Classify(form),
		}
	}
	return results
}

func pageDomainGroups(annotations []storage.PageAnnotation) []int {
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

func computeMetrics(confusion map[string]map[string]int, classes []string) (precision, recall, f1 map[string]float64, macroF1, weightedF1 float64) {
	precision = make(map[string]float64)
	recall = make(map[string]float64)
	f1 = make(map[string]float64)

	totalSamples := 0
	for _, cls := range classes {
		// TP = confusion[cls][cls]
		tp := confusion[cls][cls]

		// FP = sum of column cls minus TP
		fp := 0
		for _, trueCls := range classes {
			if trueCls != cls {
				fp += confusion[trueCls][cls]
			}
		}

		// FN = sum of row cls minus TP
		fn := 0
		for _, predCls := range classes {
			if predCls != cls {
				fn += confusion[cls][predCls]
			}
		}

		support := tp + fn
		totalSamples += support

		if tp+fp > 0 {
			precision[cls] = float64(tp) / float64(tp+fp)
		}
		if tp+fn > 0 {
			recall[cls] = float64(tp) / float64(tp+fn)
		}
		if precision[cls]+recall[cls] > 0 {
			f1[cls] = 2 * precision[cls] * recall[cls] / (precision[cls] + recall[cls])
		}
	}

	// Macro F1 = average F1 across classes
	sumF1 := 0.0
	for _, cls := range classes {
		sumF1 += f1[cls]
	}
	if len(classes) > 0 {
		macroF1 = sumF1 / float64(len(classes))
	}

	// Weighted F1 = weighted by support
	sumWeightedF1 := 0.0
	for _, cls := range classes {
		support := 0
		for _, v := range confusion[cls] {
			support += v
		}
		sumWeightedF1 += f1[cls] * float64(support)
	}
	if totalSamples > 0 {
		weightedF1 = sumWeightedF1 / float64(totalSamples)
	}

	return
}

func filterPageByIndex(docs []*goquery.Document, formResults [][]classifier.ClassifyResult, urls, labels []string, testSet []bool, isTest bool) ([]*goquery.Document, [][]classifier.ClassifyResult, []string, []string) {
	var outDocs []*goquery.Document
	var outFormResults [][]classifier.ClassifyResult
	var outURLs []string
	var outLabels []string
	for i := range docs {
		if testSet[i] == isTest {
			outDocs = append(outDocs, docs[i])
			outFormResults = append(outFormResults, formResults[i])
			outURLs = append(outURLs, urls[i])
			outLabels = append(outLabels, labels[i])
		}
	}
	return outDocs, outFormResults, outURLs, outLabels
}
