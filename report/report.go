package report

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Meco30701X/domxss/scanner"
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
		fmt.Println()
	}
}

// OutputJSON writes findings to a JSON file
func OutputJSON(findings []scanner.Finding, filename string) error {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}
