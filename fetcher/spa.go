package fetcher

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Meco30701X/xssprobe/compliance"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// disableCORSFlag controls whether browser same-origin policy is disabled
var disableCORSFlag bool

// SetDisableCORS sets whether to disable browser same-origin policy
func SetDisableCORS(disable bool) {
	disableCORSFlag = disable
}

// SPAConfig holds configuration for SPA rendering
type SPAConfig struct {
	WaitTime    time.Duration // Time to wait for JS rendering
	ScrollPage  bool          // Scroll page to trigger lazy loading
	AuthCookies []string      // Cookies for authenticated pages
	Headers     map[string]string
	Compliance  *compliance.ComplianceContext
}

// SPAResult holds the result of SPA rendering
type SPAResult struct {
	RenderedHTML    string
	InlineScripts   []string
	ExternalScripts []string
	DynamicScripts  []string // Scripts injected after page load
	RenderedURL     string   // Final URL after redirects/routing
}

// DefaultSPAConfig returns a default SPA configuration
func DefaultSPAConfig() *SPAConfig {
	return &SPAConfig{
		WaitTime:   5 * time.Second,
		ScrollPage: true,
	}
}

// FetchPageSPA renders a page with chromedp and extracts content
func FetchPageSPA(targetURL string, config *SPAConfig) (*SPAResult, error) {
	if config == nil {
		config = DefaultSPAConfig()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("enable-javascript", true),
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"),
	)
	if disableCORSFlag {
		opts = append(opts, chromedp.Flag("disable-web-security", true))
	}
	if proxyURL != "" {
		opts = append(opts, chromedp.Flag("proxy-server", proxyURL))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	taskCtx, taskCancel := chromedp.NewContext(allocCtx)
	defer taskCancel()

	// Fetch interception needs an initialized CDP target. Initialize Chrome
	// before enabling the request policy; otherwise Fetch.enable can fail with
	// "invalid context" on the first browser operation.
	if err := chromedp.Run(taskCtx, chromedp.Navigate("about:blank")); err != nil {
		return nil, fmt.Errorf("browser startup failed: %w", err)
	}
	if err := compliance.InstallBrowserPolicy(taskCtx, targetURL, config.AuthCookies, config.Headers, config.Compliance, nil); err != nil {
		return nil, fmt.Errorf("browser policy setup failed: %w", err)
	}

	// Collect dynamically injected scripts (mutex-protected for concurrent access)
	var mu sync.Mutex
	var dynamicScripts []string
	chromedp.ListenTarget(taskCtx, func(ev interface{}) {
		if e, ok := ev.(*network.EventRequestWillBeSent); ok {
			if strings.HasSuffix(e.Request.URL, ".js") || strings.Contains(e.Request.URL, ".js?") {
				mu.Lock()
				dynamicScripts = append(dynamicScripts, e.Request.URL)
				mu.Unlock()
			}
		}
	})

	result := &SPAResult{}

	// JS to extract all scripts from rendered DOM
	jsExtractScripts := `
		(function() {
			var result = {inline: [], external: []};
			document.querySelectorAll('script').forEach(function(el) {
				if (el.src) {
					result.external.push(el.src);
				} else if (el.textContent && el.textContent.trim().length > 0) {
					result.inline.push(el.textContent);
				}
			});
			return JSON.stringify(result);
		})()
	`

	var scriptJSON string
	var renderedHTML string
	var currentURL string

	actions := []chromedp.Action{
		chromedp.Navigate(targetURL),
		chromedp.Sleep(config.WaitTime),
	}

	// Scroll page to trigger lazy loading if enabled
	if config.ScrollPage {
		actions = append(actions, chromedp.Evaluate(`
			(function() {
				var height = document.body.scrollHeight;
				var step = window.innerHeight;
				for (var i = 0; i < height; i += step) {
					window.scrollTo(0, i);
				}
				window.scrollTo(0, 0);
			})()
		`, nil))
		actions = append(actions, chromedp.Sleep(2*time.Second))
	}

	actions = append(actions,
		chromedp.Evaluate(jsExtractScripts, &scriptJSON),
		chromedp.InnerHTML("html", &renderedHTML),
		chromedp.Evaluate(`window.location.href`, &currentURL),
	)

	err := chromedp.Run(taskCtx, actions...)
	if err != nil {
		return nil, fmt.Errorf("SPA render failed: %w", err)
	}

	result.RenderedHTML = renderedHTML
	result.RenderedURL = currentURL

	// Parse script JSON
	if scriptJSON != "" {
		var scripts struct {
			Inline   []string `json:"inline"`
			External []string `json:"external"`
		}
		if err := json.Unmarshal([]byte(scriptJSON), &scripts); err == nil {
			result.InlineScripts = scripts.Inline
			result.ExternalScripts = scripts.External
		}
	}

	// Deduplicate dynamic scripts
	seen := make(map[string]bool)
	for _, s := range result.ExternalScripts {
		seen[s] = true
	}
	for _, s := range dynamicScripts {
		if !seen[s] {
			result.DynamicScripts = append(result.DynamicScripts, s)
			seen[s] = true
		}
	}

	return result, nil
}

// IsSPA checks if a page is likely a SPA based on indicators
func IsSPA(html string) bool {
	indicators := []string{
		"id=\"app\"",
		"id=\"root\"",
		"id=\"__next\"",
		"id=\"__nuxt\"",
		"data-reactroot",
		"ng-app",
		"v-cloak",
		"__vue__",
		"__NEXT_DATA__",
		"__NUXT__",
		"_app.config.js",
	}

	lower := strings.ToLower(html)
	for _, indicator := range indicators {
		if strings.Contains(lower, strings.ToLower(indicator)) {
			return true
		}
	}

	// Check for minimal HTML with just a root div (common SPA pattern)
	bodyRe := regexp.MustCompile(`(?is)<body[^>]*>(.*?)</body>`)
	bodyMatch := bodyRe.FindStringSubmatch(html)
	if len(bodyMatch) > 1 {
		body := strings.TrimSpace(bodyMatch[1])
		// If body is very short and has a single root div, likely SPA
		if len(body) < 500 && strings.Contains(body, `id="`) {
			return true
		}
	}

	return false
}

// ExtractSPARoutes extracts client-side routes from JavaScript
func ExtractSPARoutes(scripts []string) []string {
	var routes []string
	seen := make(map[string]bool)

	// Common route patterns
	routePatterns := []*regexp.Regexp{
		// React Router
		regexp.MustCompile(`path\s*:\s*["']([^"']+)["']`),
		// Vue Router
		regexp.MustCompile(`path\s*:\s*["']([^"']+)["']`),
		// Angular Router
		regexp.MustCompile(`path\s*:\s*["']([^"']+)["']`),
		// Generic route definitions
		regexp.MustCompile(`["']/[a-zA-Z][a-zA-Z0-9/-]*["']`),
	}

	for _, script := range scripts {
		for _, re := range routePatterns {
			matches := re.FindAllStringSubmatch(script, -1)
			for _, m := range matches {
				if len(m) > 1 {
					route := m[1]
					if !seen[route] && len(route) > 1 && route != "/" {
						routes = append(routes, route)
						seen[route] = true
					}
				}
			}
		}
	}

	return routes
}
