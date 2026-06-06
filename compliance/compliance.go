package compliance

import (
	"fmt"
	"net/url"
	"time"
)

// ComplianceConfig holds all compliance-related configuration
type ComplianceConfig struct {
	Scope         string // Allowed domain scope
	RateLimit     int    // Requests per second
	AuditLogPath  string // Path to audit log file
	RespectRobots bool   // Whether to respect robots.txt
	Version       string // Application version for audit log
}

// ComplianceContext manages all compliance checks
type ComplianceContext struct {
	config      ComplianceConfig
	Limiter     *RateLimiter
	Audit       *AuditLogger
	RobotsCache *RobotsCache
}

// NewCompliance creates a new compliance context from config
func NewCompliance(cfg ComplianceConfig) (*ComplianceContext, error) {
	ctx := &ComplianceContext{
		config:      cfg,
		Limiter:     NewRateLimiter(cfg.RateLimit),
		RobotsCache: NewRobotsCache(),
	}

	// Setup audit logger if path specified
	if cfg.AuditLogPath != "" {
		logger, err := NewAuditLogger(cfg.AuditLogPath, cfg.Version)
		if err != nil {
			return nil, fmt.Errorf("failed to create audit log: %v", err)
		}
		ctx.Audit = logger
	}

	return ctx, nil
}

// CheckURL performs all compliance checks before a request
// Returns nil if allowed, error if blocked
func (c *ComplianceContext) CheckURL(rawURL string, requestType string) error {
	start := time.Now()

	// 1. Scope check
	if err := ValidateScope(rawURL, c.config.Scope); err != nil {
		if c.Audit != nil {
			c.Audit.LogBlocked(rawURL, requestType, "scope")
		}
		return err
	}

	// 2. Robots.txt check
	if c.config.RespectRobots {
		parsed, err := url.Parse(rawURL)
		if err == nil {
			rules, err := c.RobotsCache.GetRobots(rawURL)
			if err == nil && !rules.IsAllowed(parsed.Path) {
				if c.Audit != nil {
					c.Audit.LogBlocked(rawURL, requestType, "robots")
				}
				return fmt.Errorf("robots.txt disallows: %s", parsed.Path)
			}

			// Apply crawl delay if specified
			if rules != nil && rules.GetCrawlDelay() > 0 {
				delay := time.Duration(rules.GetCrawlDelay()) * time.Second
				time.Sleep(delay)
			}
		}
	}

	// 3. Rate limit
	c.Limiter.Wait()

	// 4. Log allowed request
	if c.Audit != nil {
		c.Audit.LogAllowed(rawURL, requestType, 0, time.Since(start))
	}

	return nil
}

// CheckURLWithStatus performs compliance checks and logs with HTTP status code
func (c *ComplianceContext) CheckURLWithStatus(rawURL string, requestType string, statusCode int) error {
	start := time.Now()

	// Same checks as CheckURL but with status code logging
	if err := ValidateScope(rawURL, c.config.Scope); err != nil {
		if c.Audit != nil {
			c.Audit.LogBlocked(rawURL, requestType, "scope")
		}
		return err
	}

	if c.config.RespectRobots {
		parsed, err := url.Parse(rawURL)
		if err == nil {
			rules, err := c.RobotsCache.GetRobots(rawURL)
			if err == nil && !rules.IsAllowed(parsed.Path) {
				if c.Audit != nil {
					c.Audit.LogBlocked(rawURL, requestType, "robots")
				}
				return fmt.Errorf("robots.txt disallows: %s", parsed.Path)
			}
		}
	}

	c.Limiter.Wait()

	if c.Audit != nil {
		c.Audit.LogAllowed(rawURL, requestType, statusCode, time.Since(start))
	}

	return nil
}

// LogError logs a request error to the audit log
func (c *ComplianceContext) LogError(rawURL, requestType, reason string) {
	if c.Audit != nil {
		c.Audit.LogError(rawURL, requestType, reason)
	}
}

// Close cleans up compliance resources
func (c *ComplianceContext) Close() {
	if c.Audit != nil {
		c.Audit.Close()
	}
}

// GetConfig returns the current compliance configuration
func (c *ComplianceContext) GetConfig() ComplianceConfig {
	return c.config
}
