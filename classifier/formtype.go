package classifier

import (
	"math"

	"github.com/PuerkitoBio/goquery"
	"github.com/happyhackingspace/dit/internal/vectorizer"
)

// FormTypeModel holds a trained form type classifier.
type FormTypeModel struct {
	Classes   []string             `json:"classes"`
	Coef      [][]float64          `json:"coef"`      // [numClasses][numFeatures]
	Intercept []float64            `json:"intercept"` // [numClasses]
	Pipelines []SerializedPipeline `json:"pipelines"`

	// Runtime state (not serialized directly)
	dictVecs  []*vectorizer.DictVectorizer
	countVecs []*vectorizer.CountVectorizer
	tfidfVecs []*vectorizer.TfidfVectorizer
	vecTypes  []string
	vecDims   []int
}

// SerializedPipeline holds the serialized state of a feature pipeline.
type SerializedPipeline struct {
	Name          string                      `json:"name"`
	ExtractorType string                      `json:"extractor_type"`
	VecType       string                      `json:"vec_type"`
	DictVec       *vectorizer.DictVectorizer  `json:"dict_vec,omitempty"`
	CountVec      *vectorizer.CountVectorizer `json:"count_vec,omitempty"`
	TfidfVec      *vectorizer.TfidfVectorizer `json:"tfidf_vec,omitempty"`
}

// Classify returns the predicted form type.
func (m *FormTypeModel) Classify(form *goquery.Selection) string {
	proba := m.ClassifyProba(form)
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

// ClassifyProba returns probabilities for each form type.
func (m *FormTypeModel) ClassifyProba(form *goquery.Selection) map[string]float64 {
	features := m.extractFeatures(form)

	// Compute logits: logits[c] = dot(coef[c], features) + intercept[c]
	numClasses := len(m.Classes)
	logits := make([]float64, numClasses)
	for c := range numClasses {
		logits[c] = features.Dot(m.Coef[c]) + m.Intercept[c]
	}

	// Softmax
	probs := softmax(logits)
	result := make(map[string]float64, numClasses)
	for c, cls := range m.Classes {
		result[cls] = probs[c]
	}
	return result
}

// extractFeatures runs all pipelines and concatenates feature vectors.
func (m *FormTypeModel) extractFeatures(form *goquery.Selection) vectorizer.SparseVector {
	pipelines := DefaultFeaturePipelines()
	vectors := make([]vectorizer.SparseVector, len(pipelines))

	for i, pipe := range pipelines {
		switch m.vecTypes[i] {
		case "dict":
			feats := pipe.Extractor.ExtractDict(form)
			vectors[i] = m.dictVecs[i].Transform(feats)
		case "count":
			text := pipe.Extractor.ExtractString(form)
			vectors[i] = m.countVecs[i].Transform(text)
		case "tfidf":
			text := pipe.Extractor.ExtractString(form)
			vectors[i] = m.tfidfVecs[i].Transform(text)
		}
	}

	return vectorizer.ConcatSparse(vectors)
}

// InitRuntime initializes runtime state from serialized pipelines.
func (m *FormTypeModel) InitRuntime() {
	m.dictVecs = make([]*vectorizer.DictVectorizer, len(m.Pipelines))
	m.countVecs = make([]*vectorizer.CountVectorizer, len(m.Pipelines))
	m.tfidfVecs = make([]*vectorizer.TfidfVectorizer, len(m.Pipelines))
	m.vecTypes = make([]string, len(m.Pipelines))
	m.vecDims = make([]int, len(m.Pipelines))

	for i, p := range m.Pipelines {
		m.vecTypes[i] = p.VecType
		switch p.VecType {
		case "dict":
			m.dictVecs[i] = p.DictVec
			m.vecDims[i] = p.DictVec.VocabSize()
		case "count":
			m.countVecs[i] = p.CountVec
			m.vecDims[i] = p.CountVec.VocabSize()
		case "tfidf":
			m.tfidfVecs[i] = p.TfidfVec
			m.vecDims[i] = p.TfidfVec.VocabSize()
		}
	}
}

// TrainFormType trains a form type classifier.
func TrainFormType(forms []*goquery.Selection, labels []string, config FormTypeTrainConfig) *FormTypeModel {
	pipelines := DefaultFeaturePipelines()

	model := &FormTypeModel{}
	model.Pipelines = make([]SerializedPipeline, len(pipelines))
	model.dictVecs = make([]*vectorizer.DictVectorizer, len(pipelines))
	model.countVecs = make([]*vectorizer.CountVectorizer, len(pipelines))
	model.tfidfVecs = make([]*vectorizer.TfidfVectorizer, len(pipelines))
	model.vecTypes = make([]string, len(pipelines))
	model.vecDims = make([]int, len(pipelines))

	// Extract raw features and fit vectorizers
	allVectors := make([][]vectorizer.SparseVector, len(pipelines))

	for i, pipe := range pipelines {
		model.vecTypes[i] = pipe.VecType
		sp := SerializedPipeline{
			Name:          pipe.Name,
			ExtractorType: extractorTypeName(pipe.Extractor),
			VecType:       pipe.VecType,
		}

		switch pipe.VecType {
		case "dict":
			dv := vectorizer.NewDictVectorizer()
			data := make([]map[string]any, len(forms))
			for j, form := range forms {
				data[j] = pipe.Extractor.ExtractDict(form)
			}
			vecs := dv.FitTransform(data)
			allVectors[i] = vecs
			model.dictVecs[i] = dv
			model.vecDims[i] = dv.VocabSize()
			sp.DictVec = dv

		case "count":
			stopWords := pipe.StopWords
			_ = stopWords
			cv := vectorizer.NewCountVectorizer(pipe.NgramRange, pipe.Binary, pipe.Analyzer, pipe.MinDF)
			corpus := make([]string, len(forms))
			for j, form := range forms {
				corpus[j] = pipe.Extractor.ExtractString(form)
			}
			vecs := cv.FitTransform(corpus)
			allVectors[i] = vecs
			model.countVecs[i] = cv
			model.vecDims[i] = cv.VocabSize()
			sp.CountVec = cv

		case "tfidf":
			stopWords := pipe.StopWords
			if pipe.UseEnglishStop {
				stopWords = vectorizer.EnglishStopWords()
			}
			tv := vectorizer.NewTfidfVectorizer(pipe.NgramRange, pipe.MinDF, pipe.Binary, pipe.Analyzer, stopWords)
			corpus := make([]string, len(forms))
			for j, form := range forms {
				corpus[j] = pipe.Extractor.ExtractString(form)
			}
			vecs := tv.FitTransform(corpus)
			allVectors[i] = vecs
			model.tfidfVecs[i] = tv
			model.vecDims[i] = tv.VocabSize()
			sp.TfidfVec = tv
		}

		model.Pipelines[i] = sp
	}

	n := len(forms)
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

	numParams := numClasses * (totalDim + 1)
	params := make([]float64, numParams)

	lbfgs := newLogRegLBFGS(10)
	for iter := range config.MaxIter {
		loss, gradients := logRegObjective(xData, y, params, numClasses, totalDim, reg)

		if config.Verbose && iter%10 == 0 {
			_ = loss
		}

		dir := lbfgs.computeDirection(gradients, numParams)
		step := logRegLineSearch(xData, y, params, dir, numClasses, totalDim, reg, loss)

		prevParams := make([]float64, numParams)
		copy(prevParams, params)
		for i := range numParams {
			params[i] += step * dir[i]
		}

		_, newGrad := logRegObjective(xData, y, params, numClasses, totalDim, reg)
		s := make([]float64, numParams)
		yVec := make([]float64, numParams)
		for i := range numParams {
			s[i] = params[i] - prevParams[i]
			yVec[i] = newGrad[i] - gradients[i]
		}
		lbfgs.update(s, yVec)

		// Check convergence
		maxGrad := 0.0
		for _, g := range newGrad {
			if math.Abs(g) > maxGrad {
				maxGrad = math.Abs(g)
			}
		}
		if maxGrad < 1e-5 {
			break
		}
	}

	// Extract coef and intercept
	model.Coef = make([][]float64, numClasses)
	model.Intercept = make([]float64, numClasses)
	for c := range numClasses {
		model.Coef[c] = make([]float64, totalDim)
		offset := c * (totalDim + 1)
		copy(model.Coef[c], params[offset:offset+totalDim])
		model.Intercept[c] = params[offset+totalDim]
	}

	return model
}

// FormTypeTrainConfig holds training configuration.
type FormTypeTrainConfig struct {
	C       float64
	MaxIter int
	Verbose bool
}

// DefaultFormTypeTrainConfig returns default training config.
func DefaultFormTypeTrainConfig() FormTypeTrainConfig {
	return FormTypeTrainConfig{
		C:       5.0,
		MaxIter: 100,
	}
}

func logRegObjective(x []vectorizer.SparseVector, y []int, params []float64, numClasses, totalDim int, c float64) (float64, []float64) {
	N := len(x)
	grad := make([]float64, len(params))
	loss := 0.0

	for j := range N {
		logits := make([]float64, numClasses)
		for k := range numClasses {
			offset := k * (totalDim + 1)
			logits[k] = x[j].Dot(params[offset:offset+totalDim]) + params[offset+totalDim]
		}

		probs := softmax(logits)

		if probs[y[j]] > 0 {
			loss -= math.Log(probs[y[j]])
		} else {
			loss += 100
		}

		for k := range numClasses {
			offset := k * (totalDim + 1)
			indicator := 0.0
			if k == y[j] {
				indicator = 1.0
			}
			diff := probs[k] - indicator

			for _, idx := range x[j].Indices {
				for vi, vidx := range x[j].Indices {
					if vidx == idx {
						grad[offset+idx] += diff * x[j].Values[vi]
						break
					}
				}
			}
			grad[offset+totalDim] += diff
		}
	}

	regCoeff := 1.0 / c
	for k := range numClasses {
		offset := k * (totalDim + 1)
		for i := range totalDim {
			loss += 0.5 * regCoeff * params[offset+i] * params[offset+i]
			grad[offset+i] += regCoeff * params[offset+i]
		}
	}

	return loss, grad
}

func logRegLineSearch(x []vectorizer.SparseVector, y []int, params, dir []float64, numClasses, totalDim int, c, currentLoss float64) float64 {
	step := 1.0
	n := len(params)
	wNew := make([]float64, n)

	for trial := 0; trial < 20; trial++ {
		for i := range n {
			wNew[i] = params[i] + step*dir[i]
		}
		newLoss, _ := logRegObjective(x, y, wNew, numClasses, totalDim, c)
		if newLoss < currentLoss {
			return step
		}
		step *= 0.5
	}
	return step
}

func softmax(logits []float64) []float64 {
	maxLogit := logits[0]
	for _, l := range logits[1:] {
		if l > maxLogit {
			maxLogit = l
		}
	}
	probs := make([]float64, len(logits))
	var sum float64
	for i, l := range logits {
		probs[i] = math.Exp(l - maxLogit)
		sum += probs[i]
	}
	for i := range probs {
		probs[i] /= sum
	}
	return probs
}

type logRegLBFGS struct {
	m    int
	s    [][]float64
	y    [][]float64
	rho  []float64
	k    int
	size int
}

func newLogRegLBFGS(m int) *logRegLBFGS {
	return &logRegLBFGS{
		m:   m,
		s:   make([][]float64, m),
		y:   make([][]float64, m),
		rho: make([]float64, m),
	}
}

func (l *logRegLBFGS) update(s, y []float64) {
	sy := 0.0
	for i := range s {
		sy += s[i] * y[i]
	}
	if sy <= 0 {
		return
	}
	idx := l.k % l.m
	l.s[idx] = make([]float64, len(s))
	l.y[idx] = make([]float64, len(y))
	copy(l.s[idx], s)
	copy(l.y[idx], y)
	l.rho[idx] = 1.0 / sy
	l.k++
	if l.size < l.m {
		l.size++
	}
}

func (l *logRegLBFGS) computeDirection(grad []float64, n int) []float64 {
	q := make([]float64, n)
	copy(q, grad)

	if l.size == 0 {
		for i := range q {
			q[i] = -q[i]
		}
		return q
	}

	alpha := make([]float64, l.size)

	for i := l.size - 1; i >= 0; i-- {
		idx := (l.k - 1 - (l.size - 1 - i)) % l.m
		if idx < 0 {
			idx += l.m
		}
		a := 0.0
		for j := range n {
			a += l.rho[idx] * l.s[idx][j] * q[j]
		}
		alpha[i] = a
		for j := range n {
			q[j] -= a * l.y[idx][j]
		}
	}

	latestIdx := (l.k - 1) % l.m
	if latestIdx < 0 {
		latestIdx += l.m
	}
	yy := 0.0
	sy := 0.0
	for i := range n {
		yy += l.y[latestIdx][i] * l.y[latestIdx][i]
		sy += l.s[latestIdx][i] * l.y[latestIdx][i]
	}
	if yy > 0 {
		gamma := sy / yy
		for i := range q {
			q[i] *= gamma
		}
	}

	for i := range l.size {
		idx := (l.k - l.size + i) % l.m
		if idx < 0 {
			idx += l.m
		}
		beta := 0.0
		for j := range n {
			beta += l.rho[idx] * l.y[idx][j] * q[j]
		}
		for j := range n {
			q[j] += (alpha[i] - beta) * l.s[idx][j]
		}
	}

	for i := range q {
		q[i] = -q[i]
	}
	return q
}

func extractorTypeName(e FormFeatureExtractor) string {
	switch e.(type) {
	case FormElements:
		return "FormElements"
	case SubmitText:
		return "SubmitText"
	case FormLinksText:
		return "FormLinksText"
	case FormLabelText:
		return "FormLabelText"
	case FormURL:
		return "FormURL"
	case FormCSS:
		return "FormCSS"
	case FormInputCSS:
		return "FormInputCSS"
	case FormInputNames:
		return "FormInputNames"
	case FormInputTitle:
		return "FormInputTitle"
	default:
		return "unknown"
	}
}
