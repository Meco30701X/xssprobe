package waf

import (
	"testing"
)

func TestBuildProbeURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com", "https://example.com?q=<script>alert(1)</script>"},
		{"https://example.com/page", "https://example.com/page?q=<script>alert(1)</script>"},
		{"https://example.com?q=existing", "https://example.com?q=existing&q=<script>alert(1)</script>"},
	}

	for _, tt := range tests {
		result := buildProbeURL(tt.input)
		if result != tt.expected {
			t.Errorf("buildProbeURL(%s) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

func TestGetRecommendedWAF(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"cloudflare", "cloudflare"},
		{"Cloudflare", "cloudflare"},
		{"aws", "aws"},
		{"modsec", "modsec"},
		{"modsecurity", "modsec"},
		{"akamai", "generic"},
		{"imperva", "generic"},
		{"sucuri", "generic"},
		{"f5", "generic"},
		{"unknown", ""},
	}

	for _, tt := range tests {
		result := GetRecommendedWAF(tt.input)
		if result != tt.expected {
			t.Errorf("GetRecommendedWAF(%s) = %s, want %s", tt.input, result, tt.expected)
		}
	}
}

func TestGetWAFSignatures(t *testing.T) {
	sigs := getWAFSignatures()

	if len(sigs) == 0 {
		t.Error("expected non-empty WAF signatures")
	}

	// Check that major WAFs are included
	expectedWAFs := []string{"cloudflare", "aws", "modsec", "akamai", "imperva", "sucuri", "f5"}
	for _, wafName := range expectedWAFs {
		found := false
		for _, sig := range sigs {
			if sig.Name == wafName {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing WAF signature: %s", wafName)
		}
	}
}

func TestWAFSignature_Structure(t *testing.T) {
	sigs := getWAFSignatures()

	for _, sig := range sigs {
		if sig.Name == "" {
			t.Error("WAF signature has empty name")
		}

		// Each signature should have at least one detection method
		hasHeaders := len(sig.Headers) > 0
		hasBody := len(sig.BodyMatch) > 0
		hasStatus := len(sig.StatusCodes) > 0

		if !hasHeaders && !hasBody && !hasStatus {
			t.Errorf("WAF %s has no detection methods", sig.Name)
		}
	}
}
