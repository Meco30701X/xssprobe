package fetcher

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	"github.com/Meco30701X/xssprobe/compliance"
)

// proxyURL stores the HTTP proxy URL (empty = no proxy)
var proxyURL string
var allowedScope string

// SetProxy sets the HTTP proxy for all requests
func SetProxy(proxy string) {
	proxyURL = proxy
}

// SetScope applies the configured host scope to direct HTTP fetches and redirects.
func SetScope(scope string) { allowedScope = scope }

// httpClient creates an http.Client with optional proxy
func httpClient() *http.Client {
	client := &http.Client{Timeout: 15 * time.Second}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := compliance.ValidateScope(req.URL.String(), allowedScope); err != nil {
			return err
		}
		if len(via) >= 10 { return fmt.Errorf("stopped after 10 redirects") }
		return nil
	}
	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err == nil {
			client.Transport = &http.Transport{
				Proxy: http.ProxyURL(proxy),
			}
		}
	}
	return client
}

// FetchPage fetches a URL and returns the HTML content
// limiter can be nil; if provided, rate limit is applied before the request
func FetchPage(fetchURL string, limiter *compliance.RateLimiter) (string, error) {
	if err := compliance.ValidateScope(fetchURL, allowedScope); err != nil {
		return "", err
	}
	if limiter != nil {
		limiter.Wait()
	}
	client := httpClient()
	previousRedirectCheck := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if limiter != nil {
			limiter.Wait()
		}
		return previousRedirectCheck(req, via)
	}
	resp, err := client.Get(fetchURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch %s: %w", fetchURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d from %s", resp.StatusCode, fetchURL)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	return string(body), nil
}

// ExtractInlineScripts extracts inline <script> content from HTML
func ExtractInlineScripts(html string) []string {
	re := regexp.MustCompile(`(?is)<script[^>]*>(.*?)</script>`)
	matches := re.FindAllStringSubmatch(html, -1)

	var scripts []string
	for _, m := range matches {
		if len(m) > 1 {
			script := m[1]
			if len(script) > 0 {
				scripts = append(scripts, script)
			}
		}
	}
	return scripts
}

// ExtractScriptURLs extracts external script src URLs from HTML
func ExtractScriptURLs(html string, baseURL string) []string {
	re := regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)
	matches := re.FindAllStringSubmatch(html, -1)

	var urls []string
	for _, m := range matches {
		if len(m) > 1 {
			u := m[1]
			if len(u) == 0 {
				continue
			}
			// Handle relative URLs
			if u[0] == '/' {
				// Absolute path: prepend origin
				parsed, err := url.Parse(baseURL)
				if err == nil {
					u = parsed.Scheme + "://" + parsed.Host + u
				}
			} else if u[0] != 'h' {
				// Relative path: resolve against base URL
				parsed, err := url.Parse(baseURL)
				if err == nil {
					resolved := parsed.ResolveReference(&url.URL{Path: u})
					u = resolved.String()
				}
			}
			urls = append(urls, u)
		}
	}
	return urls
}

// FetchScript fetches an external JavaScript file
// limiter can be nil; if provided, rate limit is applied before the request
func FetchScript(url string, limiter *compliance.RateLimiter) (string, error) {
	return FetchPage(url, limiter)
}
