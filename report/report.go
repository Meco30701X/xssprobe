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

// suggestPayload returns a concrete payload suggestion based on the sink type
func suggestPayload(sinkFunc string) string {
	lower := strings.ToLower(sinkFunc)
	switch {
	case strings.Contains(lower, "document.write") || strings.Contains(lower, "writeln"):
		return `<script>alert(1)</script>`
	case strings.Contains(lower, "innerhtml") || strings.Contains(lower, "outerhtml"):
		return `<img src=x onerror=alert(1)>`
	case strings.Contains(lower, "eval") || strings.Contains(lower, "function(") || strings.Contains(lower, "new function"):
		return `alert(1)`
	case strings.Contains(lower, "settimeout") || strings.Contains(lower, "setinterval"):
		return `alert(1)`
	case strings.Contains(lower, "insertadjacenthtml"):
		return `<img src=x onerror=alert(1)>`
	case strings.Contains(lower, ".html("):
		return `<img src=x onerror=alert(1)>`
	case strings.Contains(lower, "setattribute"):
		return `alert(1)`
	default:
		return `<script>alert(1)</script>`
	}
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

		// Show actionable injection details for URL-parameter-based findings
		paramName := extractParamName(f.Source)
		if paramName != "" && targetPage != "" {
			payload := suggestPayload(f.Sink)
			injectionURL := buildInjectionURL(targetPage, paramName, payload)
			if injectionURL != "" {
				fmt.Printf("\n    🔗 Injection URL:\n       %s\n", injectionURL)
				fmt.Printf("    💡 Suggested payload: %s\n", payload)
				fmt.Printf("    📌 Parameter: %s\n", paramName)
			}
		} else if paramName != "" {
			// No page URL available (standalone JS scan), just show parameter and payload
			payload := suggestPayload(f.Sink)
			fmt.Printf("\n    💡 Suggested payload: %s\n", payload)
			fmt.Printf("    📌 Parameter: %s (append ?%s=<payload> to page URL)\n", paramName, paramName)
		}

		fmt.Println()
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
