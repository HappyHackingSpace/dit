package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/happyhackingspace/dit"
	"github.com/spf13/cobra"
)

func (c *CLI) newRunCommand() *cobra.Command {
	var modelPath string
	var threshold float64
	var proba bool
	var render bool
	var renderTimeout int

	cmd := &cobra.Command{
		Use:   "run [url-or-file]",
		Short: "Classify page type and forms in a URL, HTML file, or stdin",
		Args:  cobra.MaximumNArgs(1),
		Example: `  # Classify a URL directly
  dit run https://github.com/login

  # Classify a local HTML file
  dit run login.html

  # Pipe HTML content from a file
  cat login.html | dit run

  # Pipe a URL from stdin
  echo "https://github.com/login" | dit run

  # Pipe HTML content from a URL using curl
  curl -s https://github.com/login | dit run

  # Show probability scores
  dit run https://github.com/login --proba

  # Use custom probability threshold
  dit run https://github.com/login --proba --threshold 0.1

  # Use custom model file
  dit run login.html --model custom.json

  # Render JavaScript-heavy pages
  dit run https://github.com/login --render

  # Silent mode (no banner)
  dit run https://github.com/login -s

  # Verbose mode with debug output
  dit run https://github.com/login -v`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var htmlContent string
			var target string
			var err error
			fetchOpts := fetchOptions{
				render:  render,
				timeout: time.Duration(renderTimeout) * time.Second,
			}

			if len(args) == 0 {
				if isStdinTerminal() {
					return cmd.Help()
				}
				htmlContent, target, err = readFromStdin(fetchOpts)
				if err != nil {
					return err
				}
			} else {
				target = args[0]
				if fetchOpts.render && isURL(target) && renderTimeout <= 0 {
					return fmt.Errorf("--timeout must be a positive integer")
				}
				slog.Debug("Fetching HTML", "target", target, "render", fetchOpts.render)
				htmlContent, err = fetchHTML(target, fetchOpts)
				if err != nil {
					return err
				}
			}
			slog.Debug("HTML fetched", "target", target, "bytes", len(htmlContent))

			start := time.Now()
			cl, err := loadModel(modelPath)
			if err != nil {
				return err
			}
			slog.Debug("Model loaded", "duration", time.Since(start))

			start = time.Now()
			if proba {
				pageResult, pageErr := cl.ExtractPageTypeProba(htmlContent, threshold)
				if pageErr == nil {
					slog.Debug("Page+form classification completed", "duration", time.Since(start))
					output, _ := json.MarshalIndent(pageResult, "", "  ")
					fmt.Println(string(output))
				} else {
					results, err := cl.ExtractFormsProba(htmlContent, threshold)
					if err != nil {
						return err
					}
					slog.Debug("Form classification completed", "forms", len(results), "duration", time.Since(start))
					if len(results) == 0 {
						fmt.Println("No forms found.")
						return nil
					}
					output, _ := json.MarshalIndent(results, "", "  ")
					fmt.Println(string(output))
				}
			} else {
				pageResult, pageErr := cl.ExtractPageType(htmlContent)
				if pageErr == nil {
					slog.Debug("Page+form classification completed", "duration", time.Since(start))
					output, _ := json.MarshalIndent(pageResult, "", "  ")
					fmt.Println(string(output))
				} else {
					results, err := cl.ExtractForms(htmlContent)
					if err != nil {
						return err
					}
					slog.Debug("Form classification completed", "forms", len(results), "duration", time.Since(start))
					if len(results) == 0 {
						fmt.Println("No forms found.")
						return nil
					}
					output, _ := json.MarshalIndent(results, "", "  ")
					fmt.Println(string(output))
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&modelPath, "model", "", "Path to model file (default: auto-detect or download)")
	cmd.Flags().Float64Var(&threshold, "threshold", 0.05, "Minimum probability threshold")
	cmd.Flags().BoolVar(&proba, "proba", false, "Show probabilities")
	cmd.Flags().BoolVar(&render, "render", false, "Render JavaScript-driven pages in a headless browser")
	cmd.Flags().IntVar(&renderTimeout, "timeout", 30, "Render browser timeout in seconds")
	return cmd
}

func isStdinTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

func loadModel(modelPath string) (*dit.Classifier, error) {
	if modelPath != "" {
		slog.Debug("Loading custom model", "path", modelPath)
		return dit.Load(modelPath)
	}
	return dit.New()
}

type fetchOptions struct {
	render  bool
	timeout time.Duration
}

func fetchHTML(target string, opts fetchOptions) (string, error) {
	if isURL(target) {
		if opts.render {
			return fetchHTMLRender(target, opts.timeout)
		}
		return fetchHTMLPlain(target)
	}
	if opts.render {
		slog.Debug("Render flag ignored for non-URL target", "target", target)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		return "", fmt.Errorf("read file: %w", err)
	}
	return string(data), nil
}

func fetchHTMLPlain(target string) (string, error) {
	resp, err := http.Get(target)
	if err != nil {
		return "", fmt.Errorf("fetch URL: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}
	return string(body), nil
}

func fetchHTMLRender(target string, timeout time.Duration) (string, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	ctx, cancel = chromedp.NewContext(ctx)
	defer cancel()

	var htmlContent string
	err := chromedp.Run(ctx,
		chromedp.Navigate(target),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.ActionFunc(func(ctx context.Context) error {
			waitCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			_ = chromedp.Run(waitCtx,
				chromedp.WaitVisible("form, input", chromedp.ByQuery),
			)
			_ = chromedp.Run(ctx, chromedp.Sleep(500*time.Millisecond))
			return nil
		}),
		chromedp.OuterHTML("html", &htmlContent, chromedp.ByQuery),
	)
	if err != nil {
		return "", fmt.Errorf("render browser: %w", err)
	}
	return htmlContent, nil
}

func isURL(target string) bool {
	return strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")
}

func readFromStdin(opts fetchOptions) (string, string, error) {
	slog.Debug("Reading from stdin")
	body, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", "", fmt.Errorf("read stdin: %w", err)
	}
	content := strings.TrimSpace(string(body))
	if content == "" {
		return "", "", fmt.Errorf("stdin is empty")
	}

	if isURL(content) {
		slog.Debug("Stdin contains URL", "url", content)
		if opts.render && opts.timeout <= 0 {
			return "", "", fmt.Errorf("--timeout must be a positive integer")
		}
		html, err := fetchHTML(content, opts)
		if err != nil {
			return "", "", err
		}
		return html, content, nil
	}

	return content, "stdin", nil
}
