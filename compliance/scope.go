package compliance

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateScope checks if a URL's host matches one of the allowed scopes.
// allowedScope accepts comma-separated domains. Each entry supports
// subdomain matching: api.target.com matches "target.com".
func ValidateScope(rawURL, allowedScope string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}

	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("URL has no host: %s", rawURL)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("unsupported URL scheme: %s", parsed.Scheme)
	}
	if allowedScope == "" {
		return nil // no host restriction
	}

	host = strings.TrimSuffix(strings.ToLower(host), ".")

	for _, scope := range strings.Split(allowedScope, ",") {
		scope = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(scope)), ".")
		if scope == "" {
			continue
		}
		// Exact match or subdomain match.
		if host == scope || strings.HasSuffix(host, "."+scope) {
			return nil
		}
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
