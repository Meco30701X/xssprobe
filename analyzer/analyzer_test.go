package analyzer

import (
	"strings"
	"testing"

	"github.com/Meco30701X/xssprobe/scanner"
)

func TestSinkOnlyHeuristicRemainsManualReviewLead(t *testing.T) {
	results := AnalyzeFindings("https://example.test/", []scanner.Finding{{
		Source:     "unknown",
		Sink:       "setTimeout",
		Severity:   "low",
		Confidence: "low",
	}}, nil, &AnalysisConfig{DoVerify: true, MaxVerify: 10})
	if len(results) != 1 {
		t.Fatalf("analysis result count = %d, want 1", len(results))
	}
	if results[0].Verified || results[0].Confidence != "low" || !strings.Contains(results[0].Recommendation, "Manual review lead") {
		t.Fatalf("sink-only result was promoted: %+v", results[0])
	}
}

func TestUnimplementedDynamicReplayIsNotPromotedToPossible(t *testing.T) {
	results := AnalyzeFindings("https://example.test/", []scanner.Finding{{
		Source:     "XMLHttpRequest",
		Sink:       "eval",
		Severity:   "medium",
		Confidence: "medium",
	}}, nil, &AnalysisConfig{DoVerify: true, MaxVerify: 10})
	if len(results) != 1 {
		t.Fatalf("analysis result count = %d, want 1", len(results))
	}
	result := results[0]
	if !result.Verified || result.VerifyResult == nil || !result.VerifyResult.Error {
		t.Fatalf("unsupported replay should be marked incomplete: %+v", result)
	}
	if result.Confidence != "medium" || strings.Contains(result.Recommendation, "Possible vulnerability") {
		t.Fatalf("incomplete replay was promoted: %+v", result)
	}
}
