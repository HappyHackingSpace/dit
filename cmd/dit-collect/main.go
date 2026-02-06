package main

import (
	"bufio"
	"crypto/md5"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// seedEntry represents a single entry in the seed file (JSONL).
type seedEntry struct {
	URL          string `json:"url"`
	ExpectedType string `json:"expected_type"`
	Mangle       bool   `json:"mangle,omitempty"`
}

// pageIndexEntry matches the data/pages/index.json format.
type pageIndexEntry struct {
	URL      string `json:"url"`
	PageType string `json:"page_type"`
}

var version = "dev"

func main() {
	var (
		outputDir  string
		seedFile   string
		timeout    int
		delay      int
		userAgent  string
		verbose    bool
		maxPages   int
		mangleOnly bool
	)

	rootCmd := &cobra.Command{
		Use:     "dit-collect",
		Short:   "Collect HTML pages for page type classifier training",
		Version: version,
	}

	collectCmd := &cobra.Command{
		Use:   "collect",
		Short: "Fetch pages from seed URLs and save to data/pages/",
		Example: `  dit-collect collect --seed seeds.jsonl --output data/pages
  dit-collect collect --seed seeds.jsonl --output data/pages --mangle-only
  dit-collect collect --seed seeds.jsonl --output data/pages --delay 2000`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if verbose {
				slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
			}

			seeds, err := loadSeeds(seedFile)
			if err != nil {
				return fmt.Errorf("load seeds: %w", err)
			}
			slog.Info("Loaded seeds", "count", len(seeds))

			index, err := loadIndex(outputDir)
			if err != nil {
				return fmt.Errorf("load index: %w", err)
			}

			client := &http.Client{
				Timeout: time.Duration(timeout) * time.Second,
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					if len(via) >= 5 {
						return fmt.Errorf("too many redirects")
					}
					return nil
				},
			}

			htmlDir := filepath.Join(outputDir, "html")
			if err := os.MkdirAll(htmlDir, 0755); err != nil {
				return fmt.Errorf("create html dir: %w", err)
			}

			collected := 0
			for _, seed := range seeds {
				if maxPages > 0 && collected >= maxPages {
					break
				}

				if !mangleOnly {
					if err := fetchAndSave(client, seed.URL, seed.ExpectedType, userAgent, outputDir, index); err != nil {
						slog.Warn("Failed to fetch", "url", seed.URL, "error", err)
					} else {
						collected++
						slog.Info("Collected", "url", seed.URL, "type", seed.ExpectedType, "total", collected)
					}
				}

				// URL mangling for soft-404/error detection
				if seed.Mangle {
					mangledURL := manglePath(seed.URL)
					if mangledURL != "" {
						if maxPages > 0 && collected >= maxPages {
							break
						}
						time.Sleep(time.Duration(delay) * time.Millisecond)

						status, err := fetchAndSaveMangled(client, mangledURL, userAgent, outputDir, index)
						if err != nil {
							slog.Warn("Failed to fetch mangled", "url", mangledURL, "error", err)
						} else {
							collected++
							pageType := "soft_404"
							if status == 404 {
								pageType = "error"
							}
							slog.Info("Collected mangled", "url", mangledURL, "status", status, "type", pageType, "total", collected)
						}
					}
				}

				if delay > 0 {
					time.Sleep(time.Duration(delay) * time.Millisecond)
				}
			}

			if err := saveIndex(outputDir, index); err != nil {
				return fmt.Errorf("save index: %w", err)
			}

			slog.Info("Collection complete", "total", collected, "index_entries", len(index))
			return nil
		},
	}

	collectCmd.Flags().StringVar(&seedFile, "seed", "", "Path to seed file (JSONL)")
	collectCmd.Flags().StringVar(&outputDir, "output", "data/pages", "Output directory")
	collectCmd.Flags().IntVar(&timeout, "timeout", 30, "HTTP timeout in seconds")
	collectCmd.Flags().IntVar(&delay, "delay", 1000, "Delay between requests in milliseconds")
	collectCmd.Flags().StringVar(&userAgent, "user-agent", "Mozilla/5.0 (compatible; dit-collect/1.0)", "User-Agent header")
	collectCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	collectCmd.Flags().IntVar(&maxPages, "max", 0, "Maximum pages to collect (0 = unlimited)")
	collectCmd.Flags().BoolVar(&mangleOnly, "mangle-only", false, "Only collect mangled URLs (soft-404/error)")
	_ = collectCmd.MarkFlagRequired("seed")

	genSeedCmd := &cobra.Command{
		Use:   "gen-seeds",
		Short: "Generate seed file from common URL patterns",
		Example: `  dit-collect gen-seeds --domains domains.txt --output seeds.jsonl
  dit-collect gen-seeds --domains domains.txt --output seeds.jsonl --types login,registration`,
		RunE: func(cmd *cobra.Command, args []string) error {
			domainsFile, _ := cmd.Flags().GetString("domains")
			output, _ := cmd.Flags().GetString("output")
			types, _ := cmd.Flags().GetString("types")

			domains, err := loadLines(domainsFile)
			if err != nil {
				return fmt.Errorf("load domains: %w", err)
			}

			typeList := strings.Split(types, ",")
			typePatterns := getTypePatterns()

			f, err := os.Create(output)
			if err != nil {
				return err
			}
			defer f.Close()

			enc := json.NewEncoder(f)
			count := 0
			for _, domain := range domains {
				domain = strings.TrimSpace(domain)
				if domain == "" {
					continue
				}
				if !strings.HasPrefix(domain, "http") {
					domain = "https://" + domain
				}

				for _, tp := range typeList {
					tp = strings.TrimSpace(tp)
					paths, ok := typePatterns[tp]
					if !ok {
						continue
					}
					for _, path := range paths {
						seed := seedEntry{
							URL:          domain + path,
							ExpectedType: tp,
							Mangle:       tp == "error" || tp == "soft_404",
						}
						if err := enc.Encode(seed); err != nil {
							return err
						}
						count++
					}
				}

				// Also add the homepage as landing
				if containsType(typeList, "landing") {
					seed := seedEntry{URL: domain, ExpectedType: "landing", Mangle: true}
					if err := enc.Encode(seed); err != nil {
						return err
					}
					count++
				}
			}

			fmt.Printf("Generated %d seed entries to %s\n", count, output)
			return nil
		},
	}
	genSeedCmd.Flags().String("domains", "", "File with domain list (one per line)")
	genSeedCmd.Flags().String("output", "seeds.jsonl", "Output seed file")
	genSeedCmd.Flags().String("types", "login,registration,search,contact,password_reset,error,soft_404,admin,landing", "Page types to generate seeds for")
	_ = genSeedCmd.MarkFlagRequired("domains")

	rootCmd.AddCommand(collectCmd, genSeedCmd)

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadSeeds(path string) ([]seedEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var seeds []seedEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var s seedEntry
		if err := json.Unmarshal([]byte(line), &s); err != nil {
			slog.Warn("Skipping invalid seed line", "line", line, "error", err)
			continue
		}
		seeds = append(seeds, s)
	}
	return seeds, scanner.Err()
}

func loadLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func loadIndex(dir string) (map[string]pageIndexEntry, error) {
	path := filepath.Join(dir, "index.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]pageIndexEntry), nil
		}
		return nil, err
	}
	var index map[string]pageIndexEntry
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, err
	}
	return index, nil
}

func saveIndex(dir string, index map[string]pageIndexEntry) error {
	data, err := json.MarshalIndent(index, "", "    ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "index.json"), data, 0644)
}

func fetchHTML(client *http.Client, rawURL, userAgent string) (string, int, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()

	// Limit body size to 5MB
	body := make([]byte, 0, 1024*1024)
	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
			if len(body) > 5*1024*1024 {
				break
			}
		}
		if err != nil {
			break
		}
	}

	return string(body), resp.StatusCode, nil
}

func fetchAndSave(client *http.Client, rawURL, pageType, userAgent, outputDir string, index map[string]pageIndexEntry) error {
	html, status, err := fetchHTML(client, rawURL, userAgent)
	if err != nil {
		return err
	}
	if status >= 400 {
		return fmt.Errorf("HTTP %d", status)
	}
	if len(html) < 100 {
		return fmt.Errorf("response too short (%d bytes)", len(html))
	}

	filename := saveHTMLFile(html, rawURL, outputDir)
	index[filename] = pageIndexEntry{
		URL:      rawURL,
		PageType: pageType,
	}
	return nil
}

func fetchAndSaveMangled(client *http.Client, mangledURL, userAgent, outputDir string, index map[string]pageIndexEntry) (int, error) {
	html, status, err := fetchHTML(client, mangledURL, userAgent)
	if err != nil {
		return 0, err
	}
	if len(html) < 100 {
		return status, fmt.Errorf("response too short (%d bytes)", len(html))
	}

	// Only save if it's a soft-404 (200) or actual 404
	if status != 200 && status != 404 {
		return status, fmt.Errorf("unexpected status %d for mangled URL", status)
	}

	pageType := "soft_404"
	if status == 404 {
		pageType = "error"
	}

	filename := saveHTMLFile(html, mangledURL, outputDir)
	index[filename] = pageIndexEntry{
		URL:      mangledURL,
		PageType: pageType,
	}
	return status, nil
}

func saveHTMLFile(html, rawURL, outputDir string) string {
	hash := fmt.Sprintf("%x", md5.Sum([]byte(rawURL)))
	filename := "html/" + hash[:12] + ".html"
	path := filepath.Join(outputDir, filename)
	_ = os.MkdirAll(filepath.Dir(path), 0755)
	_ = os.WriteFile(path, []byte(html), 0644)
	return filename
}

// manglePath inserts a random lowercase letter at a random position in the URL path.
func manglePath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	path := u.Path
	if path == "" || path == "/" {
		path = "/index"
	}

	// Find the last segment
	lastSlash := strings.LastIndex(path, "/")
	if lastSlash < 0 {
		lastSlash = 0
	}
	segment := path[lastSlash+1:]
	if segment == "" {
		segment = "page"
		path = path + segment
		lastSlash = strings.LastIndex(path, "/")
		segment = path[lastSlash+1:]
	}

	// Insert random char at random position
	pos := rand.IntN(len(segment) + 1)
	ch := byte('a' + rand.IntN(26))
	mangled := segment[:pos] + string(ch) + segment[pos:]

	u.Path = path[:lastSlash+1] + mangled
	return u.String()
}

func getTypePatterns() map[string][]string {
	return map[string][]string{
		"login":          {"/login", "/signin", "/account/login", "/wp-login.php", "/user/login", "/auth/login"},
		"registration":   {"/register", "/signup", "/join", "/create-account", "/user/register"},
		"search":         {"/search", "/search?q=test", "/?s=test"},
		"contact":        {"/contact", "/contact-us", "/about/contact"},
		"password_reset": {"/forgot-password", "/reset-password", "/account/recover", "/password/reset"},
		"admin":          {"/admin", "/wp-admin", "/dashboard", "/admin/login"},
		"error":          {"/this-page-does-not-exist-404-test", "/nonexistent-page-xyz"},
		"soft_404":       {"/this-page-does-not-exist-404-test"},
	}
}

func containsType(types []string, tp string) bool {
	for _, t := range types {
		if strings.TrimSpace(t) == tp {
			return true
		}
	}
	return false
}
