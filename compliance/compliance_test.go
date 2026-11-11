package compliance

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

func TestValidateScope(t *testing.T) {
	tests := []struct {
		url       string
		scope     string
		wantError bool
	}{
		{"https://example.com", "example.com", false},
		{"https://example.com/path", "example.com", false},
		{"https://sub.example.com", "example.com", false},                                   // Subdomain match
		{"https://other.com", "example.com", true},                                          // Different domain
		{"https://example.com", "", false},                                                  // No scope restriction
		{"https://example.com:8080", "example.com", false},                                  // With port
		{"https://code.jquery.com/jquery.js", "aiwadongdemumu.com, code.jquery.com", false}, // Explicit dependency
		{"https://static.example.com", "other.com, example.com", false},                     // Listed subdomain
		{"https://evilcode.jquery.com", "aiwadongdemumu.com, code.jquery.com", true},        // No suffix confusion
		{"https://other.com", "aiwadongdemumu.com, code.jquery.com", true},
	}

	for _, tt := range tests {
		err := ValidateScope(tt.url, tt.scope)
		if (err != nil) != tt.wantError {
			t.Errorf("ValidateScope(%s, %s) error = %v, wantError %v",
				tt.url, tt.scope, err, tt.wantError)
		}
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		url      string
		expected string
	}{
		{"https://example.com/path", "example.com"},
		{"https://sub.example.com:8080", "sub.example.com"},
		{"http://example.com", "example.com"},
		{"invalid", ""},
	}

	for _, tt := range tests {
		result := ExtractDomain(tt.url)
		if result != tt.expected {
			t.Errorf("ExtractDomain(%s) = %s, want %s", tt.url, result, tt.expected)
		}
	}
}

func TestNewRateLimiter(t *testing.T) {
	limiter := NewRateLimiter(10)

	if limiter == nil {
		t.Error("expected non-nil limiter")
	}

	if limiter.rate != 10 {
		t.Errorf("rate = %f, want 10", limiter.rate)
	}
}

func TestRateLimiter_SetRate(t *testing.T) {
	limiter := NewRateLimiter(10)
	limiter.SetRate(20)

	if limiter.rate != 20 {
		t.Errorf("rate = %f, want 20", limiter.rate)
	}
}

func TestRobotsRules_IsAllowed(t *testing.T) {
	rules := &RobotsRules{
		Exists:    true,
		Disallows: []string{"/admin", "/private"},
		Allows:    []string{"/admin/public"},
	}

	tests := []struct {
		path    string
		allowed bool
	}{
		{"/public", true},
		{"/admin", false},
		{"/admin/secret", false},
		{"/admin/public", true}, // Allow overrides disallow
		{"/private/page", false},
	}

	for _, tt := range tests {
		result := rules.IsAllowed(tt.path)
		if result != tt.allowed {
			t.Errorf("IsAllowed(%s) = %v, want %v", tt.path, result, tt.allowed)
		}
	}
}

func TestRobotsRules_NoExists(t *testing.T) {
	rules := &RobotsRules{
		Exists: false,
	}

	// If robots.txt doesn't exist, everything is allowed
	if !rules.IsAllowed("/admin") {
		t.Error("expected allowed when robots.txt doesn't exist")
	}
}

func TestNewAuditLogger(t *testing.T) {
	// Test with nil logger
	var logger *AuditLogger
	logger.Log(AuditEntry{URL: "test"}) // Should not panic
}

func TestAuditURLRedactsCredentialsAndSensitiveQueryValues(t *testing.T) {
	input := "https://" + "alice" + ":" + "pw" + "@example.test/path?search=hello&access_token=stub-token&api_key=stub-key#fragment"
	got := sanitizeAuditURL(input)
	for _, forbidden := range []string{"alice", "pw", "stub-token", "stub-key", "fragment"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("sanitized audit URL still contains %q: %s", forbidden, got)
		}
	}
	for _, required := range []string{"https://example.test/path", "search=hello", "access_token=%5BREDACTED%5D", "api_key=%5BREDACTED%5D"} {
		if !strings.Contains(got, required) {
			t.Errorf("sanitized audit URL missing %q: %s", required, got)
		}
	}
}

func TestAuditReasonRedactsEmbeddedURLs(t *testing.T) {
	urlWithCredentials := "https://" + "user" + ":" + "pw" + "@example.test/?token=stub-token"
	got := sanitizeAuditText("request failed for " + urlWithCredentials + ": timeout")
	for _, forbidden := range []string{"user", "pw", "stub-token"} {
		if strings.Contains(got, forbidden) {
			t.Errorf("sanitized audit reason still contains %q: %s", forbidden, got)
		}
	}
}

func TestAuditLoggerRestrictsExistingFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose POSIX file permission bits")
	}
	path := t.TempDir() + "/audit.jsonl"
	if err := os.WriteFile(path, []byte("{}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	logger, err := NewAuditLogger(path, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Errorf("audit file permissions = %04o, want 0600", got)
	}
}

func TestConfirmLegalUsage(t *testing.T) {
	// Skip confirmation
	if !ConfirmLegalUsage(true) {
		t.Error("expected true when skipConfirm is true")
	}
}

func TestNewCompliance(t *testing.T) {
	cfg := ComplianceConfig{
		Scope:     "example.com",
		RateLimit: 5,
	}

	cc, err := NewCompliance(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if cc == nil {
		t.Error("expected non-nil compliance context")
	}

	config := cc.GetConfig()
	if config.Scope != "example.com" {
		t.Errorf("scope = %s, want example.com", config.Scope)
	}
	if config.RateLimit != 5 {
		t.Errorf("rateLimit = %d, want 5", config.RateLimit)
	}
}
