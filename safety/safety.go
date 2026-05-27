package safety

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// SafetyMode controls how stored XSS testing behaves
type SafetyMode struct {
	DryRun   bool // Only detect inputs, don't submit anything
	Safe     bool // Use only harmless canary payloads
	Confirm  bool // Ask for confirmation before each submission
}

// DefaultSafety returns the safest mode (dry-run)
func DefaultSafety() *SafetyMode {
	return &SafetyMode{
		DryRun:  true,
		Safe:    true,
		Confirm: true,
	}
}

// CanaryPrefix is the prefix for safe test payloads
const CanaryPrefix = "DOMXSS_TEST"

// GenerateSafeCanary creates a harmless, unique canary string
func GenerateSafeCanary() string {
	return fmt.Sprintf("%s_%s", CanaryPrefix, "x7k2m9p4")
}

// IsSafePayload checks if a payload is safe (no dangerous code)
func IsSafePayload(payload string) bool {
	dangerous := []string{
		"alert(", "confirm(", "prompt(",
		"onerror", "onload", "onfocus", "onclick",
		"onmouseover", "ontoggle", "onstart",
		"<script", "</script>",
		"javascript:", "data:text/html",
		"eval(", "Function(",
		"document.cookie", "document.domain",
		"window.location", "location.href",
		"fetch(", "XMLHttpRequest",
		"<iframe", "<embed", "<object",
	}

	lower := strings.ToLower(payload)
	for _, d := range dangerous {
		if strings.Contains(lower, strings.ToLower(d)) {
			return false
		}
	}
	return true
}

// GetSafePayloads returns only harmless payloads for testing
func GetSafePayloads() []string {
	return []string{
		// Plain text canary - no HTML, no JS
		GenerateSafeCanary(),
		// Simple text with angle brackets (tests HTML encoding)
		"<DOMXSS_TEST>",
		// Text with quotes (tests attribute escaping)
		`"DOMXSS_TEST"`,
		`'DOMXSS_TEST'`,
		// Text with special chars (tests various filters)
		`DOMXSS<TEST>"'&`,
		// Unicode test
		`DOMXSS_T€ST`,
		// Null byte test
		"DOMXSS\x00TEST",
	}
}

// ConfirmPrompt asks the user for confirmation
func ConfirmPrompt(action string, details string) bool {
	fmt.Printf("\n  ⚠️  ACTION: %s\n", action)
	fmt.Printf("  DETAILS: %s\n", details)
	fmt.Print("  Proceed? [y/N]: ")

	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))

	return response == "y" || response == "yes"
}

// PrintDryRunReport shows what would be done without doing it
func PrintDryRunReport(inputs []InputInfo, hasBackendFilter bool) {
	fmt.Println("\n╔═══════════════════════════════════════════════════════════╗")
	fmt.Println("║                    DRY RUN REPORT                        ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════╣")
	fmt.Println("║  No data was submitted to the server.                    ║")
	fmt.Println("║  This report shows analysis results only.                ║")
	fmt.Println("╚═══════════════════════════════════════════════════════════╝")

	if len(inputs) == 0 {
		fmt.Println("\n  [✓] No input fields detected on this page.")
		return
	}

	fmt.Printf("\n  Found %d input field(s):\n\n", len(inputs))
	for i, input := range inputs {
		risk := assessInputRisk(input)
		riskColor := map[string]string{
			"high":   "\033[31m",
			"medium": "\033[33m",
			"low":    "\033[32m",
		}
		reset := "\033[0m"
		fmt.Printf("  %d. [%s%s%s] %s (%s)\n",
			i+1, riskColor[risk.Level], risk.Level, reset,
			input.Selector, input.Tag)
		fmt.Printf("     Risk: %s\n", risk.Reason)
		fmt.Printf("     Recommendation: %s\n\n", risk.Recommendation)
	}

	if hasBackendFilter {
		fmt.Println("  [!] Backend filtering detected - payloads may be sanitized.")
	} else {
		fmt.Println("  [!] No backend filtering detected - high risk of XSS.")
	}
}

// InputInfo represents a detected input field
type InputInfo struct {
	Selector    string
	Tag         string
	Name        string
	Placeholder string
	HasFrontend bool // Has frontend validation
}

// RiskAssessment represents the risk level of an input
type RiskAssessment struct {
	Level          string
	Reason         string
	Recommendation string
}

// assessInputRisk evaluates the risk level of an input field
func assessInputRisk(input InputInfo) RiskAssessment {
	// textarea is higher risk (often used for comments, posts)
	if input.Tag == "textarea" {
		return RiskAssessment{
			Level:  "high",
			Reason: "Textarea is commonly used for user-generated content that gets rendered",
			Recommendation: "Manual verification recommended: check if input is rendered via innerHTML/outerHTML",
		}
	}

	// contenteditable is high risk
	if input.Tag == "div" || input.Tag == "span" {
		return RiskAssessment{
			Level:  "high",
			Reason: "Contenteditable element - content is directly in DOM",
			Recommendation: "Check if content is sanitized before rendering",
		}
	}

	// Check placeholder for clues
	placeholder := strings.ToLower(input.Placeholder)
	if strings.Contains(placeholder, "comment") || strings.Contains(placeholder, "review") ||
		strings.Contains(placeholder, "post") || strings.Contains(placeholder, "message") {
		return RiskAssessment{
			Level:  "high",
			Reason: "Placeholder suggests user-generated content",
			Recommendation: "High priority for manual XSS testing",
		}
	}

	return RiskAssessment{
		Level:  "medium",
		Reason: "Standard input field - risk depends on how data is rendered",
		Recommendation: "Check server-side handling and output encoding",
	}
}

// PrintSafetyInfo shows safety information
func PrintSafetyInfo(mode *SafetyMode) {
	fmt.Println("\n  Safety Configuration:")
	if mode.DryRun {
		fmt.Println("    ✓ Dry-run mode: No data will be submitted")
	}
	if mode.Safe {
		fmt.Println("    ✓ Safe payloads: Only harmless canary strings")
	}
	if mode.Confirm {
		fmt.Println("    ✓ Confirmation required before each action")
	}
	if !mode.DryRun && !mode.Safe {
		fmt.Println("    ⚠ WARNING: Using real XSS payloads with server submission!")
		fmt.Println("    ⚠ Only use on systems you have authorization to test.")
	}
}
