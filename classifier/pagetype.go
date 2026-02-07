package classifier

import (
	"github.com/PuerkitoBio/goquery"
	"github.com/happyhackingspace/dit/internal/vectorizer"
)

// PageTypeModel holds a trained page type classifier.
type PageTypeModel struct {
	Classes   []string             `json:"classes"`
	Coef      [][]float64          `json:"coef"`
	Intercept []float64            `json:"intercept"`
	Pipelines []SerializedPipeline `json:"pipelines"`

	// Runtime state (not serialized)
	dictVecs  []*vectorizer.DictVectorizer
	tfidfVecs []*vectorizer.TfidfVectorizer
	vecTypes  []string
	vecDims   []int
}

// PageTypeTrainConfig holds training configuration for the page type model.
type PageTypeTrainConfig struct {
	C            float64
	MaxIter      int
	Verbose      bool
	BalanceClass bool // use balanced class weights
}

// DefaultPageTypeTrainConfig returns default training config.
func DefaultPageTypeTrainConfig() PageTypeTrainConfig {
	return PageTypeTrainConfig{
		C:            5.0,
		MaxIter:      100,
		BalanceClass: true,
	}
}

// Classify returns the predicted page type.
func (m *PageTypeModel) Classify(doc *goquery.Document, formResults []ClassifyResult) string {
	proba := m.ClassifyProba(doc, formResults)
	bestClass := ""
	bestProb := -1.0
	for cls, prob := range proba {
		if prob > bestProb {
			bestProb = prob
			bestClass = cls
		}
	}
	return bestClass
}

// ClassifyProba returns probabilities for each page type.
func (m *PageTypeModel) ClassifyProba(doc *goquery.Document, formResults []ClassifyResult) map[string]float64 {
	features := m.extractFeatures(doc, formResults)

	numClasses := len(m.Classes)
	logits := make([]float64, numClasses)
	for c := range numClasses {
		logits[c] = features.Dot(m.Coef[c]) + m.Intercept[c]
	}

	probs := softmax(logits)
	result := make(map[string]float64, numClasses)
	for c, cls := range m.Classes {
		result[cls] = probs[c]
	}
	return result
}

// extractFeatures runs all page pipelines and concatenates feature vectors.
func (m *PageTypeModel) extractFeatures(doc *goquery.Document, formResults []ClassifyResult) vectorizer.SparseVector {
	pipelines := DefaultPageFeaturePipelines()
	vectors := make([]vectorizer.SparseVector, len(pipelines))

	for i, pipe := range pipelines {
		switch m.vecTypes[i] {
		case "dict":
			feats := pipe.Extractor.ExtractDict(doc, formResults)
			vectors[i] = m.dictVecs[i].Transform(feats)
		case "tfidf":
			text := pipe.Extractor.ExtractString(doc, formResults)
			vectors[i] = m.tfidfVecs[i].Transform(text)
		}
	}

	return vectorizer.ConcatSparse(vectors)
}

// InitRuntime initializes runtime state from serialized pipelines.
func (m *PageTypeModel) InitRuntime() {
	m.dictVecs = make([]*vectorizer.DictVectorizer, len(m.Pipelines))
	m.tfidfVecs = make([]*vectorizer.TfidfVectorizer, len(m.Pipelines))
	m.vecTypes = make([]string, len(m.Pipelines))
	m.vecDims = make([]int, len(m.Pipelines))

	for i, p := range m.Pipelines {
		m.vecTypes[i] = p.VecType
		switch p.VecType {
		case "dict":
			m.dictVecs[i] = p.DictVec
			m.vecDims[i] = p.DictVec.VocabSize()
		case "tfidf":
			m.tfidfVecs[i] = p.TfidfVec
			m.vecDims[i] = p.TfidfVec.VocabSize()
		}
	}
}

// TrainPageType trains a page type classifier.
func TrainPageType(docs []*goquery.Document, formResults [][]ClassifyResult, urls []string, labels []string, config PageTypeTrainConfig) *PageTypeModel {
	pipelines := DefaultPageFeaturePipelines()

	model := &PageTypeModel{}
	model.Pipelines = make([]SerializedPipeline, len(pipelines))
	model.dictVecs = make([]*vectorizer.DictVectorizer, len(pipelines))
	model.tfidfVecs = make([]*vectorizer.TfidfVectorizer, len(pipelines))
	model.vecTypes = make([]string, len(pipelines))
	model.vecDims = make([]int, len(pipelines))

	allVectors := make([][]vectorizer.SparseVector, len(pipelines))

	for i, pipe := range pipelines {
		model.vecTypes[i] = pipe.VecType
		sp := SerializedPipeline{
			Name:          pipe.Name,
			ExtractorType: pageExtractorTypeName(pipe.Extractor),
			VecType:       pipe.VecType,
		}

		// Inject URL into PageURLExtractor
		extractor := pipe.Extractor

		switch pipe.VecType {
		case "dict":
			dv := vectorizer.NewDictVectorizer()
			data := make([]map[string]any, len(docs))
			for j, doc := range docs {
				data[j] = extractor.ExtractDict(doc, formResults[j])
			}
			vecs := dv.FitTransform(data)
			allVectors[i] = vecs
			model.dictVecs[i] = dv
			model.vecDims[i] = dv.VocabSize()
			sp.DictVec = dv

		case "tfidf":
			stopWords := pipe.StopWords
			if pipe.UseEnglishStop {
				stopWords = vectorizer.EnglishStopWords()
			}
			tv := vectorizer.NewTfidfVectorizer(pipe.NgramRange, pipe.MinDF, pipe.Binary, pipe.Analyzer, stopWords)
			corpus := make([]string, len(docs))
			for j, doc := range docs {
				// Handle URL extractor specially
				if _, ok := extractor.(PageURLExtractor); ok {
					corpus[j] = PageURLExtractor{URL: urls[j]}.ExtractString(doc, formResults[j])
				} else {
					corpus[j] = extractor.ExtractString(doc, formResults[j])
				}
			}
			vecs := tv.FitTransform(corpus)
			allVectors[i] = vecs
			model.tfidfVecs[i] = tv
			model.vecDims[i] = tv.VocabSize()
			sp.TfidfVec = tv
		}

		model.Pipelines[i] = sp
	}

	n := len(docs)
	xData := make([]vectorizer.SparseVector, n)
	for j := range n {
		vectors := make([]vectorizer.SparseVector, len(pipelines))
		for i := range pipelines {
			vectors[i] = allVectors[i][j]
		}
		xData[j] = vectorizer.ConcatSparse(vectors)
	}

	classSet := make(map[string]int)
	var classes []string
	for _, l := range labels {
		if _, ok := classSet[l]; !ok {
			classSet[l] = len(classes)
			classes = append(classes, l)
		}
	}
	model.Classes = classes

	totalDim := xData[0].Dim
	numClasses := len(classes)

	y := make([]int, n)
	for j := range n {
		y[j] = classSet[labels[j]]
	}

	reg := config.C
	if reg <= 0 {
		reg = 5.0
	}

	// Compute balanced class weights: n_samples / (n_classes * n_per_class)
	var sampleWeights []float64
	if config.BalanceClass {
		classCounts := make([]int, numClasses)
		for _, yi := range y {
			classCounts[yi]++
		}
		classWeights := make([]float64, numClasses)
		for c := range numClasses {
			if classCounts[c] > 0 {
				classWeights[c] = float64(n) / (float64(numClasses) * float64(classCounts[c]))
			} else {
				classWeights[c] = 1.0
			}
		}
		sampleWeights = make([]float64, n)
		for j := range n {
			sampleWeights[j] = classWeights[y[j]]
		}
	}

	coef, intercept := trainLogReg(xData, y, numClasses, totalDim, reg, config.MaxIter, sampleWeights)
	model.Coef = coef
	model.Intercept = intercept

	return model
}

func pageExtractorTypeName(e PageFeatureExtractor) string {
	switch e.(type) {
	case PageStructureExtractor:
		return "PageStructure"
	case PageTitleExtractor:
		return "PageTitle"
	case PageMetaDescriptionExtractor:
		return "PageMetaDescription"
	case PageHeadingsExtractor:
		return "PageHeadings"
	case PageH1Extractor:
		return "PageH1"
	case PageCSSExtractor:
		return "PageCSS"
	case PageNavTextExtractor:
		return "PageNavText"
	case FormTypeSummaryExtractor:
		return "FormTypeSummary"
	case PageBodyTextExtractor:
		return "PageBodyText"
	case PageURLExtractor:
		return "PageURL"
	default:
		return "unknown"
	}
}
