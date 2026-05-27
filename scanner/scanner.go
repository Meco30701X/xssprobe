package scanner

import (
	"fmt"
	"regexp"
	"strings"
)

// Finding represents a potential DOM XSS vulnerability
type Finding struct {
	Source   string
	Sink     string
	Code     string
	Line     int
	Severity string
}

// TaintTracker tracks variable assignments from sources
type TaintTracker struct {
	// varName → source name (e.g. "hash" → "location.hash")
	taintedVars map[string]string
}

func NewTaintTracker() *TaintTracker {
	return &TaintTracker{
		taintedVars: make(map[string]string),
	}
}

// assignRe matches: var/let/const x = ... or x = ...
var assignRe = regexp.MustCompile(`(?:(?:var|let|const)\s+)?(\w+)\s*=\s*(.+)`)

// TrackLine updates the taint map based on variable assignments
func (t *TaintTracker) TrackLine(line string) {
	matches := assignRe.FindStringSubmatch(line)
	if matches == nil {
		return
	}
	varName := matches[1]
	value := matches[2]

	for _, src := range getSources() {
		if src.Re.MatchString(value) {
			t.taintedVars[varName] = src.Name
			return
		}
	}

	// Check if RHS contains a tainted variable
	// e.g. var y = x; where x is tainted
	for taintedVar, sourceName := range t.taintedVars {
		if strings.Contains(value, taintedVar) {
			t.taintedVars[varName] = sourceName + "(via "+taintedVar+")"
			return
		}
	}

	// Variable reassigned to something safe — remove taint
	delete(t.taintedVars, varName)
}

// GetTaintedVar checks if a variable is tainted, returns source name and true if so
func (t *TaintTracker) GetTaintedVar(varName string) (string, bool) {
	src, ok := t.taintedVars[varName]
	return src, ok
}

// GetTaintedVars returns all currently tainted variables
func (t *TaintTracker) GetTaintedVars() map[string]string {
	return t.taintedVars
}

// ScanJS analyzes JavaScript content for DOM XSS patterns
func ScanJS(jsContent string) []Finding {
	var findings []Finding
	lines := strings.Split(jsContent, "\n")

	tracker := NewTaintTracker()

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// === Pass 1: Same-line source→sink detection ===
		for _, pattern := range getVulnerablePatterns() {
			if pattern.SourceRe.MatchString(trimmed) && pattern.SinkRe.MatchString(trimmed) {
				severity := "high"
				if isFiltered(trimmed) {
					severity = "low"
				}
				findings = append(findings, Finding{
					Source:   pattern.SourceName,
					Sink:     pattern.SinkName,
					Code:     trimmed,
					Line:     i + 1,
					Severity: severity,
				})
			}
		}

		// === Pass 2: Cross-line taint tracking ===
		// Track variable assignments
		tracker.TrackLine(trimmed)

		// Check if any sink uses a tainted variable
		for _, sink := range getSinks() {
			if !sink.Re.MatchString(trimmed) {
				continue
			}

			// Check if the sink line references any tainted variable
			for taintedVar, sourceName := range tracker.GetTaintedVars() {
				if strings.Contains(trimmed, taintedVar) {
					// Avoid duplicate with same-line detection
					alreadyFound := false
					for _, f := range findings {
						if f.Line == i+1 && f.Sink == sink.Name && f.Source != "unknown" {
							alreadyFound = true
							break
						}
					}
					if !alreadyFound {
						severity := "high"
						if isFiltered(trimmed) {
							severity = "low"
						}
						findings = append(findings, Finding{
							Source:   sourceName,
							Sink:     sink.Name,
							Code:     trimmed,
							Line:     i + 1,
							Severity: severity,
						})
					}
					break
				}
			}
		}

		// === Pass 3: Standalone sink detection (fallback) ===
		for _, sink := range getSinks() {
			if sink.Re.MatchString(trimmed) {
				alreadyFound := false
				for _, f := range findings {
					if f.Line == i+1 && f.Sink == sink.Name {
						alreadyFound = true
						break
					}
				}
				if !alreadyFound {
					findings = append(findings, Finding{
						Source:   "unknown",
						Sink:     sink.Name,
						Code:     trimmed,
						Line:     i + 1,
						Severity: "medium",
					})
				}
			}
		}
	}

	return findings
}

type vulnerablePattern struct {
	SourceRe   *regexp.Regexp
	SinkRe     *regexp.Regexp
	SourceName string
	SinkName   string
}

func getVulnerablePatterns() []vulnerablePattern {
	var patterns []vulnerablePattern

	for _, src := range getSources() {
		for _, sink := range getSinks() {
			patterns = append(patterns, vulnerablePattern{
				SourceRe:   src.Re,
				SinkRe:     sink.Re,
				SourceName: src.Name,
				SinkName:   sink.Name,
			})
		}
	}

	return patterns
}

type pattern struct {
	Name string
	Re   *regexp.Regexp
}

func getSources() []pattern {
	return []pattern{
		{"location.hash", regexp.MustCompile(`location\.hash`)},
		{"location.search", regexp.MustCompile(`location\.search`)},
		{"location.href", regexp.MustCompile(`location\.href`)},
		{"location.pathname", regexp.MustCompile(`location\.pathname`)},
		{"document.URL", regexp.MustCompile(`document\.URL`)},
		{"document.documentURI", regexp.MustCompile(`document\.documentURI`)},
		{"document.referrer", regexp.MustCompile(`document\.referrer`)},
		{"window.name", regexp.MustCompile(`window\.name`)},
		{"postMessage", regexp.MustCompile(`postMessage|addEventListener\s*\(\s*['""]message['""]`)},
	}
}

func getSinks() []pattern {
	return []pattern{
		{"eval", regexp.MustCompile(`eval\s*\(`)},
		{"setTimeout", regexp.MustCompile(`setTimeout\s*\(`)},
		{"setInterval", regexp.MustCompile(`setInterval\s*\(`)},
		{"Function", regexp.MustCompile(`new\s+Function\s*\(`)},
		{"innerHTML", regexp.MustCompile(`\.innerHTML\s*=`)},
		{"outerHTML", regexp.MustCompile(`\.outerHTML\s*=`)},
		{"document.write", regexp.MustCompile(`document\.write\s*\(|document\.writeln\s*\(`)},
		{"jQuery.html", regexp.MustCompile(`\.html\s*\(`)},
		{"jQuery.append", regexp.MustCompile(`\.append\s*\(`)},
		{"insertAdjacentHTML", regexp.MustCompile(`insertAdjacentHTML\s*\(`)},
	}
}

func isFiltered(line string) bool {
	filters := []string{
		"encodeURI", "encodeURIComponent", "escape",
		"sanitize", "encode", "htmlEncode", "xss",
		"DOMPurify", "innerText", "textContent",
		"replace(/<", "replace(/>",
	}

	lower := strings.ToLower(line)
	for _, f := range filters {
		if strings.Contains(lower, strings.ToLower(f)) {
			return true
		}
	}
	return false
}

// DebugTaint prints the current taint state (for development)
func DebugTaint(jsContent string) {
	lines := strings.Split(jsContent, "\n")
	tracker := NewTaintTracker()

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}
		tracker.TrackLine(trimmed)
		if len(tracker.GetTaintedVars()) > 0 {
			fmt.Printf("Line %d: tainted vars = %v\n", i+1, tracker.GetTaintedVars())
		}
	}
}
