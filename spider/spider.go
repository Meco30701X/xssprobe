package spider

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/Meco30701X/domxss/compliance"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// Config holds crawler configuration
type Config struct {
	MaxPages    int           // Max pages to crawl
	MaxDepth    int           // Max link depth
	Timeout     time.Duration // Per-page timeout
	SameDomain  bool          // Only crawl same domain
	AuthCookies []string
	Headers     map[string]string
	Compliance  *compliance.ComplianceContext // Compliance checks
}

// DefaultConfig returns default crawler config
func DefaultConfig() *Config {
	return &Config{
		MaxPages:   50,
		MaxDepth:   3,
		Timeout:    15 * time.Second,
		SameDomain: true,
	}
}

// Page represents a discovered page
type Page struct {
	URL        string
	Depth      int
	Title      string
	StatusCode int
}

// CrawlResult holds crawl results
type CrawlResult struct {
	StartURL string
	Pages    []Page
	Errors   []string
}

// Crawler manages the crawling process
type Crawler struct {
	config    *Config
	visited   map[string]bool
	pages     []Page
	errors    []string
	mu        sync.Mutex
	baseHost  string
	baseProto string
	sem       chan struct{}
}

// NewCrawler creates a new crawler
func NewCrawler(config *Config) *Crawler {
	if config == nil {
		config = DefaultConfig()
	}
	return &Crawler{
		config:  config,
		visited: make(map[string]bool),
		sem:     make(chan struct{}, 5), // max 5 concurrent
	}
}

// Crawl starts crawling from the given URL
func (c *Crawler) Crawl(startURL string) *CrawlResult {
	parsed, err := url.Parse(startURL)
	if err != nil {
		return &CrawlResult{
			StartURL: startURL,
			Errors:   []string{"invalid URL: " + err.Error()},
		}
	}

	c.baseHost = parsed.Host
	c.baseProto = parsed.Scheme

	result := &CrawlResult{StartURL: startURL}

	// Normalize start URL
	if !strings.HasSuffix(startURL, "/") {
		startURL = startURL + "/"
	}

	c.crawlPage(startURL, 0)

	result.Pages = c.pages
	result.Errors = c.errors
	return result
}

func (c *Crawler) crawlPage(pageURL string, depth int) {
	// Check limits
	if depth > c.config.MaxDepth {
		return
	}

	// Compliance check
	if c.config.Compliance != nil {
		if err := c.config.Compliance.CheckURL(pageURL, "spider"); err != nil {
			c.mu.Lock()
			c.errors = append(c.errors, fmt.Sprintf("compliance: %s: %v", pageURL, err))
			c.mu.Unlock()
			return
		}
	}

	c.mu.Lock()
	if len(c.pages) >= c.config.MaxPages {
		c.mu.Unlock()
		return
	}
	if c.visited[pageURL] {
		c.mu.Unlock()
		return
	}
	c.visited[pageURL] = true
	c.mu.Unlock()

	c.sem <- struct{}{}
	defer func() { <-c.sem }()

	// Fetch page and extract links
	ctx, cancel := context.WithTimeout(context.Background(), c.config.Timeout)
	defer cancel()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("enable-javascript", true),
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	taskCtx, taskCancel := chromedp.NewContext(allocCtx)
	defer taskCancel()

	// Apply auth
	if len(c.config.AuthCookies) > 0 || len(c.config.Headers) > 0 {
		var actions []chromedp.Action
		for _, cookie := range c.config.AuthCookies {
			parts := strings.SplitN(cookie, "=", 2)
			if len(parts) == 2 {
				actions = append(actions, network.SetCookie(parts[0], parts[1]).WithPath("/"))
			}
		}
		if len(c.config.Headers) > 0 {
			headerMap := network.Headers{}
			for k, v := range c.config.Headers {
				headerMap[k] = v
			}
			actions = append(actions, network.SetExtraHTTPHeaders(headerMap))
		}
		if len(actions) > 0 {
			chromedp.Run(taskCtx, actions...)
		}
	}

	// Extract links and title
	var links []string
	var title string
	var html string

	jsExtractLinks := `
		(function() {
			var links = [];
			var seen = {};
			document.querySelectorAll('a[href]').forEach(function(el) {
				try {
					var href = el.href;
					if (href && !seen[href] && !href.startsWith('javascript:') && !href.startsWith('mailto:') && !href.startsWith('tel:') && !href.startsWith('#')) {
						seen[href] = true;
						links.push(href);
					}
				} catch(e) {}
			});
			// Also extract form actions
			document.querySelectorAll('form[action]').forEach(function(el) {
				try {
					var action = el.action;
					if (action && !seen[action]) {
						seen[action] = true;
						links.push(action);
					}
				} catch(e) {}
			});
			return JSON.stringify(links);
		})()
	`

	jsGetTitle := `document.title || ''`

	err := chromedp.Run(taskCtx,
		chromedp.Navigate(pageURL),
		chromedp.Sleep(2*time.Second),
		chromedp.Evaluate(jsExtractLinks, &links),
		chromedp.Evaluate(jsGetTitle, &title),
		chromedp.InnerHTML("html", &html),
	)

	if err != nil {
		c.mu.Lock()
		c.errors = append(c.errors, fmt.Sprintf("%s: %v", pageURL, err))
		c.mu.Unlock()
		return
	}

	// Add page to results
	c.mu.Lock()
	c.pages = append(c.pages, Page{
		URL:   pageURL,
		Depth: depth,
		Title: title,
	})
	pageCount := len(c.pages)
	c.mu.Unlock()

	fmt.Printf("  [%d] %s (depth=%d)\n", pageCount, truncateURL(pageURL, 60), depth)

	// Process discovered links
	var wg sync.WaitGroup
	for _, link := range links {
		normalized := normalizeURL(link)
		if normalized == "" {
			continue
		}

		// Check same domain
		if c.config.SameDomain {
			linkParsed, err := url.Parse(normalized)
			if err != nil {
				continue
			}
			if linkParsed.Host != c.baseHost {
				continue
			}
		}

		// Skip non-HTML resources
		if isStaticResource(normalized) {
			continue
		}

		c.mu.Lock()
		alreadyVisited := c.visited[normalized]
		atLimit := len(c.pages) >= c.config.MaxPages
		c.mu.Unlock()

		if alreadyVisited || atLimit {
			continue
		}

		wg.Add(1)
		go func(u string, d int) {
			defer wg.Done()
			c.crawlPage(u, d+1)
		}(normalized, depth)
	}
	wg.Wait()
}

func normalizeURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	// Remove fragment
	parsed.Fragment = ""

	// Normalize
	normalized := parsed.String()

	// Remove trailing slash for consistency (except root)
	if len(normalized) > 1 && strings.HasSuffix(normalized, "/") {
		normalized = strings.TrimSuffix(normalized, "/")
	}

	return normalized
}

func isStaticResource(u string) bool {
	extensions := []string{
		".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg",
		".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4",
		".mp3", ".avi", ".pdf", ".zip", ".tar", ".gz",
	}

	lower := strings.ToLower(u)
	for _, ext := range extensions {
		if strings.Contains(lower, ext+"?") || strings.HasSuffix(lower, ext) {
			return true
		}
	}

	// Skip API endpoints that return JSON
	if strings.Contains(lower, "/api/") && strings.Contains(lower, "/v") {
		return true
	}

	return false
}

func truncateURL(u string, maxLen int) string {
	if len(u) <= maxLen {
		return u
	}
	return u[:maxLen-3] + "..."
}

// PrintSummary prints crawl results summary
func PrintSummary(result *CrawlResult) {
	fmt.Printf("\n═══════════════════════════════════\n")
	fmt.Printf("Crawl Summary\n")
	fmt.Printf("═══════════════════════════════════\n")
	fmt.Printf("Start URL: %s\n", result.StartURL)
	fmt.Printf("Pages found: %d\n", len(result.Pages))

	if len(result.Errors) > 0 {
		fmt.Printf("Errors: %d\n", len(result.Errors))
	}

	if len(result.Pages) > 0 {
		fmt.Printf("\nPages:\n")
		for i, page := range result.Pages {
			fmt.Printf("  %d. [depth=%d] %s\n", i+1, page.Depth, page.URL)
		}
	}
}

// ExtractURLs returns just the URLs from crawl results
func ExtractURLs(result *CrawlResult) []string {
	var urls []string
	for _, page := range result.Pages {
		urls = append(urls, page.URL)
	}
	return urls
}

// CrawlWithChromedp uses chromedp for SPA-aware crawling
func CrawlWithChromedp(startURL string, config *Config) *CrawlResult {
	if config == nil {
		config = DefaultConfig()
	}

	crawler := NewCrawler(config)

	// For SPA sites, we need to use chromedp to render and discover links
	// The crawlPage method already uses chromedp internally
	return crawler.Crawl(startURL)
}

// QuickCrawl does a fast crawl with limited depth
func QuickCrawl(startURL string, maxPages int) *CrawlResult {
	config := DefaultConfig()
	config.MaxPages = maxPages
	config.MaxDepth = 2
	config.Timeout = 10 * time.Second

	crawler := NewCrawler(config)
	return crawler.Crawl(startURL)
}

// DeepCrawl does a thorough crawl with more depth
func DeepCrawl(startURL string, maxPages int) *CrawlResult {
	config := DefaultConfig()
	config.MaxPages = maxPages
	config.MaxDepth = 5
	config.Timeout = 20 * time.Second

	crawler := NewCrawler(config)
	return crawler.Crawl(startURL)
}
