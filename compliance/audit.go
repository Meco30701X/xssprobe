package compliance

import (
	"encoding/json"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	URL         string    `json:"url"`
	RequestType string    `json:"request_type"` // fetch/spider/verify/script
	StatusCode  int       `json:"status_code,omitempty"`
	Result      string    `json:"result"`           // allowed/blocked/error/success
	Reason      string    `json:"reason,omitempty"` // scope/robots/rate/ok
	Duration    string    `json:"duration,omitempty"`
}

// AuditLogger writes structured audit logs
type AuditLogger struct {
	file    *os.File
	encoder *json.Encoder
	mu      sync.Mutex
}

// NewAuditLogger creates a new audit logger writing to the given path
func NewAuditLogger(path string, appVersion string) (*AuditLogger, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	// OpenFile's mode is ignored for an existing file. Tighten it before writing
	// so audit logs do not inherit broad permissions from an older run.
	if err := file.Chmod(0600); err != nil {
		file.Close()
		return nil, err
	}

	// Write header line
	header := map[string]string{
		"event":     "audit_start",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   appVersion,
	}
	encoder := json.NewEncoder(file)
	if err := encoder.Encode(header); err != nil {
		file.Close()
		return nil, err
	}

	return &AuditLogger{
		file:    file,
		encoder: encoder,
	}, nil
}

// Log writes an audit entry
func (a *AuditLogger) Log(entry AuditEntry) {
	if a == nil {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}
	entry.URL = sanitizeAuditURL(entry.URL)
	entry.Reason = sanitizeAuditText(entry.Reason)
	a.encoder.Encode(entry)
}

var auditURLPattern = regexp.MustCompile(`(?i)https?://[^\s"'<>]+`)

func sanitizeAuditURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "[invalid URL]"
	}
	// Userinfo is never needed to understand which endpoint was requested.
	u.User = nil
	if u.RawQuery != "" {
		values, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			u.RawQuery = "[REDACTED]"
		} else {
			for key := range values {
				if isSensitiveQueryKey(key) {
					values[key] = []string{"[REDACTED]"}
				}
			}
			u.RawQuery = values.Encode()
		}
	}
	if u.Fragment != "" || u.RawFragment != "" {
		u.Fragment = "[REDACTED]"
		u.RawFragment = ""
	}
	return u.String()
}

func isSensitiveQueryKey(key string) bool {
	key = strings.ToLower(key)
	key = strings.NewReplacer("-", "", "_", "", ".", "").Replace(key)
	for _, marker := range []string{
		"token", "secret", "password", "passwd", "authorization", "credential",
		"apikey", "accesskey", "privatekey", "key", "signature", "sig", "session",
		"cookie", "ticket", "jwt", "assertion", "code", "state", "nonce", "auth",
	} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

func sanitizeAuditText(value string) string {
	return auditURLPattern.ReplaceAllStringFunc(value, func(candidate string) string {
		trimmed := strings.TrimRight(candidate, ".,;:!?)]}")
		return sanitizeAuditURL(trimmed) + candidate[len(trimmed):]
	})
}

// LogAllowed logs an allowed request
func (a *AuditLogger) LogAllowed(urlStr, requestType string, statusCode int, duration time.Duration) {
	a.Log(AuditEntry{
		URL:         urlStr,
		RequestType: requestType,
		StatusCode:  statusCode,
		Result:      "allowed",
		Reason:      "ok",
		Duration:    duration.String(),
	})
}

// LogBlocked logs a blocked request with reason
func (a *AuditLogger) LogBlocked(urlStr, requestType, reason string) {
	a.Log(AuditEntry{
		URL:         urlStr,
		RequestType: requestType,
		Result:      "blocked",
		Reason:      reason,
	})
}

// LogError logs a request error
func (a *AuditLogger) LogError(urlStr, requestType, reason string) {
	a.Log(AuditEntry{
		URL:         urlStr,
		RequestType: requestType,
		Result:      "error",
		Reason:      reason,
	})
}

// Close closes the audit log file
func (a *AuditLogger) Close() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	// Write closing entry
	a.encoder.Encode(map[string]string{
		"event":     "audit_end",
		"timestamp": time.Now().Format(time.RFC3339),
	})
	a.file.Close()
}
