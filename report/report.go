package report

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Meco30701X/domxss/scanner"
	"github.com/Meco30701X/domxss/verifier"
)

// PrintFindings prints findings to stdout in a readable format
func PrintFindings(findings []scanner.Finding, sourceURL string) {
	if len(findings) == 0 {
		fmt.Printf("[✓] %s - No DOM XSS issues found\n", sourceURL)
		return
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
