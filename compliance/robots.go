package compliance

import (
	"bufio"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// RobotsRules holds parsed robots.txt rules for a domain
type RobotsRules struct {
	Disallows []string   // Disallow path prefixes
	Allows    []string   // Allow path prefixes (override disallows)
	Delays    int        // Crawl-delay in seconds
	FetchedAt time.Time  // When rules were fetched
	Exists    bool       // Whether robots.txt existed
}

// RobotsCache caches robots.txt rules per domain
type RobotsCache struct {
	cache map[string]*RobotsRules
	mu    sync.Mutex
}

// NewRobotsCache creates a new robots cache
func NewRobotsCache() *RobotsCache {
	return &RobotsCache{
		cache: make(map[string]*RobotsRules),
	}
}

// GetRobots fetches and caches robots.txt rules for a URL's domain
func (rc *RobotsCache) GetRobots(rawURL string, limiters ...*RateLimiter) (*RobotsRules, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}

	domain := parsed.Scheme + "://" + parsed.Host

	rc.mu.Lock()
	if rules, ok := rc.cache[domain]; ok {
		rc.mu.Unlock()
		return rules, nil
	}
	rc.mu.Unlock()

	// Fetch robots.txt
	var limiter *RateLimiter
	if len(limiters) > 0 {
		limiter = limiters[0]
	}
	rules, err := fetchRobotsFile(domain, limiter)
	if err != nil {
		// If we can't fetch robots.txt, assume everything is allowed
		rules = &RobotsRules{Exists: false}
	}

	rc.mu.Lock()
	rc.cache[domain] = rules
	rc.mu.Unlock()

	return rules, nil
}

func fetchRobotsFile(baseURL string, limiter *RateLimiter) (*RobotsRules, error) {
	robotsURL := strings.TrimSuffix(baseURL, "/") + "/robots.txt"

	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		// Do not allow robots.txt redirects to silently fetch a different origin.
		return http.ErrUseLastResponse
	}}
	if limiter != nil {
		limiter.Wait()
	}
	resp, err := client.Get(robotsURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	rules := &RobotsRules{
		FetchedAt: time.Now(),
		Exists:    resp.StatusCode == 200,
	}

	if resp.StatusCode != 200 {
		return rules, nil
	}

	// Parse robots.txt
	scanner := bufio.NewScanner(resp.Body)
	inUserAgent := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split into directive and value
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		directive := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch directive {
		case "user-agent":
			// Match * (all agents) or xssprobe
			inUserAgent = value == "*" || strings.Contains(strings.ToLower(value), "xssprobe")
		case "disallow":
			if inUserAgent && value != "" {
				rules.Disallows = append(rules.Disallows, value)
			}
		case "allow":
			if inUserAgent && value != "" {
				rules.Allows = append(rules.Allows, value)
		}
		case "crawl-delay":
			if inUserAgent {
				var delay int
				fmt.Sscanf(value, "%d", &delay)
				if delay > 0 {
					rules.Delays = delay
				}
			}
		}
	}

	return rules, nil
}

// IsAllowed checks if a URL path is allowed by robots.txt rules
// Allow directives take precedence over Disallow for matching paths
func (r *RobotsRules) IsAllowed(urlPath string) bool {
	if !r.Exists {
		return true // no robots.txt means everything is allowed
	}

	// Check allow rules first (they take precedence)
	for _, allow := range r.Allows {
		if strings.HasPrefix(urlPath, allow) {
			return true
		}
	}

	// Check disallow rules
	for _, disallow := range r.Disallows {
		if strings.HasPrefix(urlPath, disallow) {
			return false
		}
	}

	return true
}

// GetCrawlDelay returns the crawl delay in seconds, or 0 if not specified
func (r *RobotsRules) GetCrawlDelay() int {
	return r.Delays
}
