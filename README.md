# dît
![Banner](banner.png)


**dît** (means *found* in Kurdish) tells you the type of an HTML page, form, and fields using machine learning.

It classifies pages (login, error, landing, blog, etc.), detects whether a form is a login, search, registration, password recovery, contact, mailing list, order form, or something else, and classifies each field (username, password, email, search query, etc.). Zero external ML dependencies.

## Install

```bash
go get github.com/happyhackingspace/dit
```

## Usage

### As a Library

```go
import "github.com/happyhackingspace/dit"

// Load classifier (finds model.json automatically)
c, _ := dit.New()

// Classify page type
page, _ := c.ExtractPageType(htmlString)
fmt.Println(page.Type)  // "login"
fmt.Println(page.Forms) // form classifications included

// Classify forms in HTML
results, _ := c.ExtractForms(htmlString)
for _, r := range results {
    fmt.Println(r.Type)   // "login"
    fmt.Println(r.Fields) // {"username": "username or email", "password": "password"}
}

// With probabilities
pageProba, _ := c.ExtractPageTypeProba(htmlString, 0.05)
formProba, _ := c.ExtractFormsProba(htmlString, 0.05)

// Train a new model
c, _ := dit.Train("data/", &dit.TrainConfig{Verbose: true})
c.Save("model.json")

// Evaluate via cross-validation
result, _ := dit.Evaluate("data/", &dit.EvalConfig{Folds: 10})
fmt.Printf("Form accuracy: %.1f%%\n", result.FormAccuracy*100)
fmt.Printf("Page accuracy: %.1f%%\n", result.PageAccuracy*100)
```

### As a CLI

```bash
# Classify page type and forms on a URL
dit run https://github.com/login

# Classify forms in a local file
dit run login.html

# With probabilities
dit run https://github.com/login --proba

# Process multiple URLs from a file (one URL per line)
dit run --list urls.txt

# Batch processing with probabilities
dit run --list urls.txt --proba

# Train a model
dit train model.json --data-folder data

# Evaluate model accuracy
dit evaluate --data-folder data

#### Batch Processing

Process multiple URLs from a file for efficient batch classification:

```bash
# Create a file with URLs (one per line)
cat > urls.txt << EOF
# Comments are supported
https://github.com/login
https://github.com/signup
https://github.com/password_reset
EOF

# Process all URLs and stream results as JSON lines
dit run --list urls.txt --silent

# Pretty print with jq
dit run --list urls.txt --silent | jq '.'

# Extract just URLs and page types
dit run --list urls.txt --silent | jq -r '"\(.url) -> \(.page.type)"'

# Filter specific page types
dit run --list urls.txt --silent | jq 'select(.page.type == "login")'
```

**Output format**: Results are streamed as [JSON Lines](https://jsonlines.org/) (one JSON object per line), making it easy to process with standard Unix tools.
```

## Page Types

| Type | Description |
|------|-------------|
| `login` | Login page |
| `registration` | Registration / signup page |
| `search` | Search results page |
| `checkout` | Checkout / payment page |
| `contact` | Contact page |
| `password_reset` | Password reset page |
| `landing` | Landing / home page |
| `product` | Product page |
| `blog` | Blog / article page |
| `settings` | Settings / account page |
| `soft_404` | Soft 404 (HTTP 200 but "not found" content) |
| `error` | Error page (404, 403, 500, etc.) |
| `captcha` | CAPTCHA / bot detection page |
| `parked` | Domain parking page |
| `coming_soon` | Under construction / maintenance page |
| `admin` | Admin panel / dashboard |
| `directory_listing` | Open directory index |
| `default_page` | Unconfigured server default |
| `waf_block` | WAF block page |
| `other` | Other page type |

## Form Types

| Type | Description |
|------|-------------|
| `login` | Login form |
| `search` | Search form |
| `registration` | Registration / signup form |
| `password/login recovery` | Password reset / recovery form |
| `contact/comment` | Contact or comment form |
| `join mailing list` | Newsletter / mailing list signup |
| `order/add to cart` | Order or add-to-cart form |
| `other` | Other form type |

## Field Types

| Category | Types |
|----------|-------|
| **Authentication** | username, password, password confirmation, email, email confirmation, username or email |
| **Names** | first name, last name, middle name, full name, organization name, gender |
| **Address** | country, city, state, address, postal code |
| **Contact** | phone, fax, url |
| **Search** | search query, search category |
| **Content** | comment text, comment title, about me text |
| **Buttons** | submit button, cancel button, reset button |
| **Verification** | captcha, honeypot, TOS confirmation, remember me checkbox, receive emails confirmation |
| **Security** | security question, security answer |
| **Time** | full date, day, month, year, timezone |
| **Product** | product quantity, sorting option, style select |
| **Other** | other number, other read-only, other |

Full list of 79 field type codes in [`data/config.json`](data/config.json).

## Accuracy

Cross-validation results (10-fold, grouped by domain):

| Metric | Score |
|--------|-------|
| Form type accuracy | 82.9% (1135/1369) |
| Field type accuracy | 86.6% (4518/5218) |
| Sequence accuracy | 78.7% (1025/1302) |
| Page type accuracy | 53.4% (403/754) |
| Page macro F1 | 40.2% |
| Page weighted F1 | 53.6% |

Trained on 1000+ annotated web forms and 754 annotated web pages.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Credits

Go port of [Formasaurus](https://github.com/scrapinghub/Formasaurus).

## License

[MIT](LICENSE)
