package compliance

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateScope checks if a URL's host matches the allowed scope
// Supports subdomain matching: api.target.com matches scope "target.com"
func ValidateScope(rawURL, allowedScope string) error {
	if allowedScope == "" {
		return nil // no scope restriction
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}

	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("URL has no host: %s", rawURL)
	}

	// Exact match
	if strings.EqualFold(host, allowedScope) {
		return nil
	}

	// Subdomain match: host ends with .scope
	if strings.HasSuffix(strings.ToLower(host), "."+strings.ToLower(allowedScope)) {
		return nil
	}

	return fmt.Errorf("scope violation: host '%s' not in scope '%s'", host, allowedScope)
}

// ExtractDomain extracts the base domain from a URL for scope auto-detection
func ExtractDomain(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}
