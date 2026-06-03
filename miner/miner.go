package miner

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// ParamSource tracks where a parameter was discovered
type ParamSource string

const (
	SourceForm    ParamSource = "form"
	SourceURL     ParamSource = "url"
	SourceJS      ParamSource = "js"
	SourceWordlist ParamSource = "wordlist"
	SourceManual  ParamSource = "manual"
)

// DiscoveredParam represents a discovered parameter
type DiscoveredParam struct {
	Name   string
	Source ParamSource
	// Form-specific
	FormAction string // form action URL
	InputType  string // input type (text, hidden, etc.)
	// URL-specific
	ExampleValue string // example value seen in URL
}

// MineParamsFromHTML extracts parameters from HTML content
func MineParamsFromHTML(html string) []DiscoveredParam {
	var params []DiscoveredParam
	seen := make(map[string]bool)

	// 1. Extract from <input name="...">
	inputRe := regexp.MustCompile(`(?i)<input[^>]+name\s*=\s*["']([^"']+)["'][^>]*>`)
	typeRe := regexp.MustCompile(`(?i)type\s*=\s*["']([^"']+)["']`)
	for _, m := range inputRe.FindAllStringSubmatch(html, -1) {
		name := strings.TrimSpace(m[1])
		if name != "" && !seen[name] {
			seen[name] = true
			// Try to extract type
			inputType := "text"
			if tm := typeRe.FindStringSubmatch(m[0]); tm != nil {
				inputType = tm[1]
			}
			params = append(params, DiscoveredParam{
				Name:      name,
				Source:    SourceForm,
				InputType: inputType,
			})
		}
	}

	// 2. Extract from <select name="...">
	selectRe := regexp.MustCompile(`(?i)<select[^>]+name\s*=\s*["']([^"']+)["']`)
	for _, m := range selectRe.FindAllStringSubmatch(html, -1) {
		name := strings.TrimSpace(m[1])
		if name != "" && !seen[name] {
			seen[name] = true
			params = append(params, DiscoveredParam{
				Name:   name,
				Source: SourceForm,
			})
		}
	}

	// 3. Extract from <textarea name="...">
	textareaRe := regexp.MustCompile(`(?i)<textarea[^>]+name\s*=\s*["']([^"']+)["']`)
	for _, m := range textareaRe.FindAllStringSubmatch(html, -1) {
		name := strings.TrimSpace(m[1])
		if name != "" && !seen[name] {
			seen[name] = true
			params = append(params, DiscoveredParam{
				Name:   name,
				Source: SourceForm,
			})
		}
	}

	// 4. Extract from <form action="?param=value">
	formActionRe := regexp.MustCompile(`(?i)<form[^>]+action\s*=\s*["']([^"']+)["']`)
	for _, m := range formActionRe.FindAllStringSubmatch(html, -1) {
		action := m[1]
		if strings.Contains(action, "?") {
			actionParams := extractURLParams(action)
			for _, p := range actionParams {
				if !seen[p] {
					seen[p] = true
					params = append(params, DiscoveredParam{
						Name:      p,
						Source:    SourceForm,
						FormAction: action,
					})
				}
			}
		}
	}

	// 5. Extract from <a href="?param=value">
	linkRe := regexp.MustCompile(`(?i)<a[^>]+href\s*=\s*["']([^"']+)["']`)
	for _, m := range linkRe.FindAllStringSubmatch(html, -1) {
		href := m[1]
		if strings.Contains(href, "?") {
			linkParams := extractURLParams(href)
			for _, p := range linkParams {
				if !seen[p] {
					seen[p] = true
					params = append(params, DiscoveredParam{
						Name:   p,
						Source: SourceURL,
					})
				}
			}
		}
	}

	// 6. Extract from common JS patterns
	jsParams := extractJSParams(html)
	for _, p := range jsParams {
		if !seen[p] {
			seen[p] = true
			params = append(params, DiscoveredParam{
				Name:   p,
				Source: SourceJS,
			})
		}
	}

	return params
}

// extractURLParams extracts parameter names from a URL string
func extractURLParams(rawURL string) []string {
	var params []string

	// Find query string
	idx := strings.Index(rawURL, "?")
	if idx == -1 {
		return params
	}
	query := rawURL[idx+1:]

	// Remove fragment
	if fragIdx := strings.Index(query, "#"); fragIdx != -1 {
		query = query[:fragIdx]
	}

	parsed, err := url.ParseQuery(query)
	if err != nil {
		return params
	}

	for k := range parsed {
		k = strings.TrimSpace(k)
		if k != "" {
			params = append(params, k)
		}
	}

	return params
}

// extractJSParams extracts parameter-like names from JavaScript code
func extractJSParams(js string) []string {
	var params []string
	seen := make(map[string]bool)

	// Pattern 1: .get('param') - covers URLSearchParams.get, params.get, query.get, etc.
	getRe := regexp.MustCompile(`\.\s*get\s*\(\s*['"](\w+)['"]\s*\)`)
	for _, m := range getRe.FindAllStringSubmatch(js, -1) {
		name := m[1]
		if !seen[name] {
			seen[name] = true
			params = append(params, name)
		}
	}

	// Pattern 2: getParameter('param') or getParameter("param")
	gpRe := regexp.MustCompile(`getParameter\s*\(\s*['"](\w+)['"]\s*\)`)
	for _, m := range gpRe.FindAllStringSubmatch(js, -1) {
		name := m[1]
		if !seen[name] {
			seen[name] = true
			params = append(params, name)
		}
	}

	// Pattern 3: params['key'] or params["key"] or query['key'] etc.
	bracketRe := regexp.MustCompile(`\w+\s*\[\s*['"](\w+)['"]\s*\]`)
	for _, m := range bracketRe.FindAllStringSubmatch(js, -1) {
		name := m[1]
		if !seen[name] {
			seen[name] = true
			params = append(params, name)
		}
	}

	// Pattern 4: URL parameter extraction functions
	// e.g., function getUrlParam(name) { ... }
	funcParamRe := regexp.MustCompile(`function\s+\w*[Pp]aram\w*\s*\(\s*['"](\w+)['"]\s*\)`)
	for _, m := range funcParamRe.FindAllStringSubmatch(js, -1) {
		name := m[1]
		if !seen[name] {
			seen[name] = true
			params = append(params, name)
		}
	}

	return params
}

// GetDefaultWordlist returns a list of commonly used parameter names
func GetDefaultWordlist() []string {
	return []string{
		// Search & Query
		"q", "query", "search", "keyword", "term", "text",
		// IDs & References
		"id", "uid", "user_id", "userId", "item", "ref", "referer", "redirect",
		// Navigation
		"page", "p", "pg", "offset", "limit", "sort", "order", "dir",
		// Input & Data
		"input", "data", "value", "val", "name", "title", "content", "body",
		// URLs & Callbacks
		"url", "uri", "link", "href", "callback", "cb", "redirect_uri", "return", "next", "continue", "dest", "destination",
		// Forms
		"email", "phone", "address", "message", "comment", "subject", "subject",
		// API
		"token", "key", "api_key", "apiKey", "access_token", "code", "state",
		// Actions
		"action", "cmd", "command", "exec", "run", "do", "act",
		// Language & Locale
		"lang", "locale", "language", "country", "region",
		// Misc
		"type", "format", "mode", "view", "tab", "section", "category", "tag",
		"file", "path", "dir", "folder", "src", "source", "target", "from", "to",
	}
}

// MergeParams merges discovered params with manual params, removing duplicates
func MergeParams(discovered []DiscoveredParam, manual []string) []DiscoveredParam {
	seen := make(map[string]bool)
	var result []DiscoveredParam

	// Add discovered first
	for _, p := range discovered {
		if !seen[p.Name] {
			seen[p.Name] = true
			result = append(result, p)
		}
	}

	// Add manual params
	for _, name := range manual {
		name = strings.TrimSpace(name)
		if name != "" && !seen[name] {
			seen[name] = true
			result = append(result, DiscoveredParam{
				Name:   name,
				Source: SourceManual,
			})
		}
	}

	return result
}

// AddWordlistParams adds wordlist parameters that aren't already discovered
func AddWordlistParams(discovered []DiscoveredParam, wordlist []string) []DiscoveredParam {
	seen := make(map[string]bool)
	var result []DiscoveredParam

	// Copy discovered
	for _, p := range discovered {
		seen[p.Name] = true
		result = append(result, p)
	}

	// Add wordlist params not already found
	for _, name := range wordlist {
		name = strings.TrimSpace(name)
		if name != "" && !seen[name] {
			seen[name] = true
			result = append(result, DiscoveredParam{
				Name:   name,
				Source: SourceWordlist,
			})
		}
	}

	return result
}

// ParamNames returns just the parameter names
func ParamNames(params []DiscoveredParam) []string {
	var names []string
	for _, p := range params {
		names = append(names, p.Name)
	}
	return names
}

// PrintDiscoveredParams prints discovered parameters in a readable format
func PrintDiscoveredParams(params []DiscoveredParam) {
	if len(params) == 0 {
		fmt.Println("  No parameters discovered")
		return
	}

	// Group by source
	forms := filterBySource(params, SourceForm)
	urls := filterBySource(params, SourceURL)
	js := filterBySource(params, SourceJS)
	wordlist := filterBySource(params, SourceWordlist)
	manual := filterBySource(params, SourceManual)

	if len(forms) > 0 {
		fmt.Printf("  Form inputs (%d): ", len(forms))
		for i, p := range forms {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Print(p.Name)
		}
		fmt.Println()
	}

	if len(urls) > 0 {
		fmt.Printf("  URL params (%d): ", len(urls))
		for i, p := range urls {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Print(p.Name)
		}
		fmt.Println()
	}

	if len(js) > 0 {
		fmt.Printf("  JS params (%d): ", len(js))
		for i, p := range js {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Print(p.Name)
		}
		fmt.Println()
	}

	if len(manual) > 0 {
		fmt.Printf("  Manual (%d): ", len(manual))
		for i, p := range manual {
			if i > 0 {
				fmt.Print(", ")
			}
			fmt.Print(p.Name)
		}
		fmt.Println()
	}

	if len(wordlist) > 0 {
		fmt.Printf("  Wordlist (%d): %d additional common params\n", len(wordlist), len(wordlist))
	}
}

func filterBySource(params []DiscoveredParam, source ParamSource) []DiscoveredParam {
	var result []DiscoveredParam
	for _, p := range params {
		if p.Source == source {
			result = append(result, p)
		}
	}
	return result
}
