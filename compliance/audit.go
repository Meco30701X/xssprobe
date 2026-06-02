package compliance

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	Timestamp   time.Time `json:"timestamp"`
	URL         string    `json:"url"`
	RequestType string    `json:"request_type"` // fetch/spider/verify/script
	StatusCode  int       `json:"status_code,omitempty"`
	Result      string    `json:"result"` // allowed/blocked/error/success
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
func NewAuditLogger(path string) (*AuditLogger, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	// Write header line
	header := map[string]string{
		"event":     "audit_start",
		"timestamp": time.Now().Format(time.RFC3339),
		"version":   "1.0",
	}
	encoder := json.NewEncoder(file)
	encoder.Encode(header)

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
	a.encoder.Encode(entry)
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
