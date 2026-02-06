# Contributing to dit

Thank you for your interest in contributing to dit!

## Getting Started

```bash
git clone https://github.com/happyhackingspace/dit.git
cd dit
go build ./...
go test ./...
```

## Architecture

dit is a Go port of [Formasaurus](https://github.com/scrapinghub/Formasaurus) with zero external ML dependencies.

**Two-stage ML pipeline:**

1. **Form type detection** -- Logistic regression (L-BFGS optimizer, L2 regularization) trained on features extracted from HTML forms: element counts, submit button text, input names, CSS classes, form action URL, label text, and link text.

2. **Field type detection** -- Linear-chain CRF (Conditional Random Field) with OWL-QN trainer (L1 support). Features include field tag/type/name/value/placeholder, CSS class/ID, label text, text before/after the field, and the form type predicted by stage 1.

Accuracy is estimated via grouped k-fold cross-validation (grouped by domain using public suffix list).

### Project Structure

```
dit.go, train.go         Public SDK (dit.New, dit.Load, dit.Train, dit.Evaluate)
cmd/dit/                  CLI tool
classifier/               Form type (LogReg) + field type (CRF) classifiers
  formtype.go             LogReg training and inference
  fieldtype.go            CRF wrapper for field classification
  formtype_features.go    9 feature pipelines (FormElements, SubmitText, etc.)
  fieldtype_features.go   Per-field CRF features (ElemFeatures, GetFormFeatures)
  model.go                Serialization (SaveModel, LoadClassifier)
crf/                      Standalone linear-chain CRF implementation
  trainer.go              OWL-QN optimizer (L1 regularization)
  forward_backward.go     Forward-backward algorithm
  viterbi.go              Viterbi decoding
  feature.go              Feature-to-attribute conversion
internal/htmlutil/        goquery-based HTML parsing, form/field extraction, text-around-elements
internal/storage/         Annotation data loading (config.json, index.json, HTML files)
internal/textutil/        Tokenize, Ngrams, Normalize, NumberPattern
internal/vectorizer/      SparseVector, CountVectorizer, TfidfVectorizer, DictVectorizer
data/                     Annotated HTML forms + config
```

### Key Design Decisions

- CRF trainer uses manual OWL-QN (for L1 support) instead of gonum's Minimize
- Formasaurus hyperparameters preserved: c1=0.1655, c2=0.0236, max_iter=100 (CRF), C=5 with L2 penalty (LogReg)
- `char_wb` analyzer pads words with spaces and extracts char n-grams from padded words (matching sklearn)
- sklearn smooth IDF formula: `log((1+n)/(1+df)) + 1`
- GroupKFold by domain using `publicsuffix` for cross-validation
- No external ML dependencies -- LogReg and CRF are self-contained

## API Reference

Full documentation is available at [pkg.go.dev/github.com/happyhackingspace/dit](https://pkg.go.dev/github.com/happyhackingspace/dit).

```go
// Load
func New() (*Classifier, error)                              // auto-finds model.json
func Load(path string) (*Classifier, error)                  // from specific path

// Classify
func (c *Classifier) ExtractForms(html string) ([]FormResult, error)
func (c *Classifier) ExtractFormsProba(html string, threshold float64) ([]FormResultProba, error)

// Train
func Train(dataDir string, config *TrainConfig) (*Classifier, error)
func (c *Classifier) Save(path string) error

// Evaluate
func Evaluate(dataDir string, config *EvalConfig) (*EvalResult, error)
```

## Code Contributions

1. Fork the repository and create a feature branch from `main`.
2. Write clear, minimal code that follows existing patterns.
3. Add tests for new functionality.
4. Run `go vet ./...` and `go test ./...` before submitting.
5. Open a pull request with a clear description of the change.

### Guidelines

- Keep the public API surface small. Internal packages should stay internal.
- No external ML dependencies.
- Match Python Formasaurus behavior where possible for compatibility.

## Data Contributions

The training data lives in `data/` and consists of annotated HTML forms from real websites.

### Adding New Annotations

1. Add the HTML file to `data/html/`.
2. Update `data/index.json` with the URL, form types, and field annotations.
3. Follow the type codes defined in `data/config.json`.
4. Re-train and verify accuracy doesn't regress:
   ```bash
   go run ./cmd/dit train model.json --data-folder data
   go run ./cmd/dit evaluate --data-folder data
   ```

### Annotation Format

Each entry in `index.json` maps an HTML file path to:
- `url` -- the source URL
- `forms` -- list of form type codes (one per `<form>` in the HTML)
- `visible_html_fields` -- list of field annotation maps (`field_name -> type_code`)

See `data/config.json` for the full list of form and field type codes.

## Bug Reports

Open an issue with:
- What you expected vs what happened
- Minimal HTML that reproduces the issue (if classification-related)
- Go version and OS

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
