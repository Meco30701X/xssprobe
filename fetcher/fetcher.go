package fetcher

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

// FetchPage fetches a URL and returns the HTML content
func FetchPage(url string) (string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
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
			url := m[1]
			// Handle relative URLs
			if len(url) > 0 && url[0] == '/' {
				url = baseURL + url
			}
			urls = append(urls, url)
		}
	}
	return urls
}

// FetchScript fetches an external JavaScript file
func FetchScript(url string) (string, error) {
	return FetchPage(url)
}
