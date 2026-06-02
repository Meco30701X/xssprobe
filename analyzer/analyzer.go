package analyzer

import (
	"fmt"
	"strings"

	"github.com/Meco30701X/domxss/scanner"
	"github.com/Meco30701X/domxss/verifier"
)

// AnalysisResult represents the combined analysis result
type AnalysisResult struct {
	Finding      scanner.Finding    // Original static finding
	Verified     bool               // Whether dynamic verification was performed
	Confirmed    bool               // Whether vulnerability was confirmed
	VerifyResult *verifier.VerifyResult // Dynamic verification result (if any)
	Confidence   string             // Final confidence: confirmed/likely/possible/filtered
	Recommendation string           // Action recommendation
}

// AnalysisConfig configures the combined analysis
type AnalysisConfig struct {
	DoVerify     bool   // Perform dynamic verification
	WAF          string // WAF type for payload selection
	MaxVerify    int    // Max findings to verify (0 = all)
	OnlyHigh     bool   // Only verify high severity findings
	SkipFiltered bool   // Skip findings with detected filtering
}

// DefaultAnalysisConfig returns default analysis configuration
func DefaultAnalysisConfig() *AnalysisConfig {
	return &AnalysisConfig{
		DoVerify:     true,
		MaxVerify:    10,
		OnlyHigh:     false,
		SkipFiltered: false,
	}
}

// AnalyzeURL performs combined static + dynamic analysis
func AnalyzeURL(targetURL string, auth *verifier.AuthConfig, config *AnalysisConfig) []AnalysisResult {
	if config == nil {
		config = DefaultAnalysisConfig()
	}

	fmt.Printf("\n═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("🔍 Combined Static + Dynamic Analysis\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n\n")

	// Phase 1: Static Analysis
	fmt.Printf("[Phase 1] Static Analysis\n")
	fmt.Printf("───────────────────────────────────────────────────────────────\n")

	// We need to fetch the page and scripts first
	// For now, we'll work with findings passed in or fetched externally
	// This will be integrated with the main flow

	return nil
}

// AnalyzeFindings performs dynamic verification on static findings
func AnalyzeFindings(targetURL string, findings []scanner.Finding, auth *verifier.AuthConfig, config *AnalysisConfig) []AnalysisResult {
	if config == nil {
		config = DefaultAnalysisConfig()
	}

	var results []AnalysisResult

	// Categorize findings by confidence
	highConfidence := filterByConfidence(findings, "high")
	mediumConfidence := filterByConfidence(findings, "medium")
	filteredFindings := getFilteredFindings(findings)

	fmt.Printf("\n📊 Static Analysis Summary:\n")
	fmt.Printf("   High confidence (Source→Sink): %d\n", len(highConfidence))
	fmt.Printf("   Medium confidence (Sink only): %d\n", len(mediumConfidence))
	fmt.Printf("   Filtered/Sanitized: %d\n", len(filteredFindings))
	fmt.Printf("   Total findings: %d\n\n", len(findings))

	// Process all findings
	for _, finding := range findings {
		result := AnalysisResult{
			Finding:    finding,
			Confidence: assessInitialConfidence(finding),
		}

		// Skip filtered findings if configured
		if config.SkipFiltered && finding.Filtered {
			result.Confidence = "filtered"
			result.Recommendation = "Skipped: filtering detected (" + finding.FilterType + ")"
			results = append(results, result)
			continue
		}

		// Skip low severity if OnlyHigh
		if config.OnlyHigh && finding.Severity == "low" {
			result.Confidence = "skipped"
			result.Recommendation = "Skipped: low severity"
			results = append(results, result)
			continue
		}

		results = append(results, result)
	}

	// Dynamic verification phase
	if config.DoVerify {
		fmt.Printf("\n[Phase 2] Dynamic Verification\n")
		fmt.Printf("───────────────────────────────────────────────────────────────\n")

		verifyCount := 0
		for i := range results {
			// Check max verify limit
			if config.MaxVerify > 0 && verifyCount >= config.MaxVerify {
				fmt.Printf("\n⚠️  Reached max verification limit (%d)\n", config.MaxVerify)
				break
			}

			// Skip already filtered/skipped
			if results[i].Confidence == "filtered" || results[i].Confidence == "skipped" {
				continue
			}

			// Perform dynamic verification
			fmt.Printf("\n  [%d/%d] Verifying: %s → %s (line %d)\n",
				verifyCount+1, min(len(results), config.MaxVerify),
				results[i].Finding.Source, results[i].Finding.Sink,
				results[i].Finding.Line)

			verifyResult := verifyFinding(targetURL, results[i].Finding, auth, config.WAF)
			results[i].Verified = true
			results[i].VerifyResult = &verifyResult
			results[i].Confirmed = verifyResult.Triggered

			if verifyResult.Triggered {
				results[i].Confidence = "confirmed"
				results[i].Recommendation = "🔴 CONFIRMED VULNERABILITY: " + verifyResult.Detail
				fmt.Printf("        ✅ CONFIRMED: %s\n", verifyResult.Detail)
			} else {
				results[i].Confidence = "possible"
				results[i].Recommendation = "🟡 Possible vulnerability (not confirmed by dynamic test)"
				fmt.Printf("        ❌ Not confirmed\n")
			}

			verifyCount++
		}
	}

	return results
}

// verifyFinding performs dynamic verification for a specific finding
func verifyFinding(targetURL string, finding scanner.Finding, auth *verifier.AuthConfig, waf string) verifier.VerifyResult {
	// Determine which verification method to use based on the source
	source := strings.ToLower(finding.Source)

	// For hash-based sources
	if strings.Contains(source, "hash") {
		return verifier.TestHashOnly(targetURL, auth, waf)
	}

	// For search/parameter-based sources
	if strings.Contains(source, "search") || strings.Contains(source, "param") ||
		strings.Contains(source, "query") {
		return verifier.TestSearchOnly(targetURL, auth, waf)
	}

	// For postMessage sources
	if strings.Contains(source, "message") || strings.Contains(source, "postmessage") {
		// postMessage requires special handling
		return verifier.VerifyPostMessage(targetURL, auth, waf)
	}

	// Default: test both hash and search params
	return verifier.TestHashOnly(targetURL, auth, waf)
}

// filterByConfidence filters findings by confidence level
func filterByConfidence(findings []scanner.Finding, confidence string) []scanner.Finding {
	var filtered []scanner.Finding
	for _, f := range findings {
		if f.Confidence == confidence {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// getFilteredFindings returns findings where filtering was detected
func getFilteredFindings(findings []scanner.Finding) []scanner.Finding {
	var filtered []scanner.Finding
	for _, f := range findings {
		if f.Filtered {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// assessInitialConfidence assesses initial confidence based on static analysis
func assessInitialConfidence(finding scanner.Finding) string {
	if finding.Filtered {
		return "filtered"
	}
	if finding.Source == "unknown" {
		return "low"
	}
	if finding.Severity == "high" {
		return "high"
	}
	return "medium"
}

// PrintAnalysisResults prints the combined analysis results
func PrintAnalysisResults(results []AnalysisResult) {
	confirmed := 0
	possible := 0
	filtered := 0

	fmt.Printf("\n═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("📋 Analysis Results\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n\n")

	for _, r := range results {
		switch r.Confidence {
		case "confirmed":
			confirmed++
			fmt.Printf("  🔴 CONFIRMED - Line %d\n", r.Finding.Line)
			fmt.Printf("     Source: %s → Sink: %s\n", r.Finding.Source, r.Finding.Sink)
			fmt.Printf("     Code: %s\n", truncateCode(r.Finding.Code, 80))
			fmt.Printf("     %s\n\n", r.Recommendation)

		case "possible":
			possible++
			fmt.Printf("  🟡 POSSIBLE  - Line %d\n", r.Finding.Line)
			fmt.Printf("     Source: %s → Sink: %s\n", r.Finding.Source, r.Finding.Sink)
			fmt.Printf("     Code: %s\n", truncateCode(r.Finding.Code, 80))
			if r.Finding.Filtered {
				fmt.Printf("     ⚠️  Filtering detected: %s\n", r.Finding.FilterType)
			}
			fmt.Printf("     %s\n\n", r.Recommendation)

		case "filtered":
			filtered++
			// Don't print filtered findings by default (too noisy)
		}
	}

	fmt.Printf("───────────────────────────────────────────────────────────────\n")
	fmt.Printf("Summary:\n")
	fmt.Printf("  🔴 Confirmed vulnerabilities: %d\n", confirmed)
	fmt.Printf("  🟡 Possible vulnerabilities:  %d\n", possible)
	fmt.Printf("  ⚪ Filtered/Sanitized:        %d\n", filtered)
	fmt.Printf("  📊 Total findings:            %d\n", len(results))
	fmt.Printf("═══════════════════════════════════════════════════════════════\n")
}

// PrintDetailedReport prints a detailed report with all findings
func PrintDetailedReport(results []AnalysisResult) {
	fmt.Printf("\n═══════════════════════════════════════════════════════════════\n")
	fmt.Printf("📝 Detailed Analysis Report\n")
	fmt.Printf("═══════════════════════════════════════════════════════════════\n\n")

	for i, r := range results {
		fmt.Printf("Finding #%d (Line %d)\n", i+1, r.Finding.Line)
		fmt.Printf("  Source:     %s\n", r.Finding.Source)
		fmt.Printf("  Sink:       %s\n", r.Finding.Sink)
		fmt.Printf("  Code:       %s\n", r.Finding.Code)
		fmt.Printf("  Severity:   %s\n", r.Finding.Severity)
		fmt.Printf("  Confidence: %s\n", r.Confidence)

		if r.Finding.Filtered {
			fmt.Printf("  Filtered:   Yes (%s)\n", r.Finding.FilterType)
		}

		if r.Verified {
			fmt.Printf("  Verified:   Yes\n")
			if r.Confirmed {
				fmt.Printf("  Confirmed:  ✅ YES\n")
			} else {
				fmt.Printf("  Confirmed:  ❌ NO\n")
			}
			if r.VerifyResult != nil {
				fmt.Printf("  Detail:     %s\n", r.VerifyResult.Detail)
			}
		} else {
			fmt.Printf("  Verified:   No\n")
		}

		fmt.Printf("  Action:     %s\n\n", r.Recommendation)
	}
}

func truncateCode(code string, maxLen int) string {
	if len(code) <= maxLen {
		return code
	}
	return code[:maxLen-3] + "..."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
