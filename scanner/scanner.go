package scanner

import (
	"fmt"
	"regexp"
	"strings"
)

// Finding represents a potential DOM XSS vulnerability
type Finding struct {
	Source      string
	Sink        string
	Code        string
	Line        int
	Severity    string
	Filtered    bool     // Whether filtering was detected
	FilterType  string   // Type of filtering detected
	Confidence  string   // Confidence level: high/medium/low
}

// TaintTracker tracks variable assignments from sources
type TaintTracker struct {
	// varName → source name (e.g. "hash" → "location.hash")
	taintedVars map[string]string
	// varName → filter info (if the variable was filtered/sanitized)
	filteredVars map[string]FilterInfo
}

func NewTaintTracker() *TaintTracker {
	return &TaintTracker{
		taintedVars:   make(map[string]string),
		filteredVars:  make(map[string]FilterInfo),
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

	// Check if the value is being filtered/sanitized
	filterInfo := detectFilter(line)
	if filterInfo.IsFiltered {
		// Mark this variable as filtered
		t.filteredVars[varName] = filterInfo
	}

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
			// Propagate filter status if the source was filtered
			if filter, ok := t.filteredVars[taintedVar]; ok {
				t.filteredVars[varName] = filter
			}
			return
		}
	}

	// Variable reassigned to something safe — remove taint
	delete(t.taintedVars, varName)
	delete(t.filteredVars, varName)
}

// IsVarFiltered checks if a variable has been filtered/sanitized
func (t *TaintTracker) IsVarFiltered(varName string) (FilterInfo, bool) {
	filter, ok := t.filteredVars[varName]
	return filter, ok
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
				filterInfo := detectFilter(trimmed)
				severity := "high"
				confidence := "high"
				if filterInfo.IsFiltered {
					severity = "low"
					confidence = "low"
				}
				findings = append(findings, Finding{
					Source:     pattern.SourceName,
					Sink:       pattern.SinkName,
					Code:       trimmed,
					Line:       i + 1,
					Severity:   severity,
					Filtered:   filterInfo.IsFiltered,
					FilterType: filterInfo.Type + ":" + filterInfo.Method,
					Confidence: confidence,
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
						// Check if the tainted variable was filtered in a previous line
						filterInfo, isFiltered := tracker.IsVarFiltered(taintedVar)
						if !isFiltered {
							// Also check current line for filtering
							filterInfo = detectFilter(trimmed)
						}
						severity := "high"
						confidence := "high"
						if filterInfo.IsFiltered {
							severity = "low"
							confidence = "low"
						}
						filterType := ""
						if filterInfo.IsFiltered {
							filterType = filterInfo.Type + ":" + filterInfo.Method
						}
						findings = append(findings, Finding{
							Source:     sourceName,
							Sink:       sink.Name,
							Code:       trimmed,
							Line:       i + 1,
							Severity:   severity,
							Filtered:   filterInfo.IsFiltered,
							FilterType: filterType,
							Confidence: confidence,
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

// FilterInfo contains details about detected filtering
type FilterInfo struct {
	IsFiltered bool
	Type       string // encoding, sanitization, dom-safe, regex-replace, library
	Method     string // Specific method name
}

// detectFilter analyzes code for filtering/sanitization patterns
func detectFilter(line string) FilterInfo {
	lower := strings.ToLower(line)

	// 1. URL Encoding
	urlEncoders := []struct {
		pattern string
		name    string
	}{
		{"encodeuricomponent", "encodeURIComponent"},
		{"encodeuri", "encodeURI"},
		{"escape(", "escape()"},
	}
	for _, e := range urlEncoders {
		if strings.Contains(lower, e.pattern) {
			return FilterInfo{true, "encoding", e.name}
		}
	}

	// 2. HTML Encoding
	htmlEncoders := []struct {
		pattern string
		name    string
	}{
		{"htmlencode", "htmlEncode"},
		{"htmlescape", "htmlEscape"},
		{"escapehtml", "escapeHTML"},
		{"tohtml", "toHTML"},
		{"&lt;", "HTML entity"},
		{"&gt;", "HTML entity"},
		{"&#", "HTML entity"},
	}
	for _, e := range htmlEncoders {
		if strings.Contains(lower, e.pattern) {
			return FilterInfo{true, "encoding", e.name}
		}
	}

	// 3. Sanitization Libraries
	sanitizers := []struct {
		pattern string
		name    string
	}{
		{"dompurify", "DOMPurify"},
		{"sanitize", "sanitize"},
		{"xss-filters", "xss-filters"},
		{"securefilters", "secureFilters"},
		{"bleach", "bleach"},
		{"jsoup", "jsoup"},
		{"antiSamy", "antiSamy"},
		{"htmlsanitize", "htmlSanitize"},
	}
	for _, s := range sanitizers {
		if strings.Contains(lower, s.pattern) {
			return FilterInfo{true, "sanitization", s.name}
		}
	}

	// 4. Safe DOM Methods (innerText, textContent)
	safeDOM := []struct {
		pattern string
		name    string
	}{
		{"innertext", "innerText"},
		{"textcontent", "textContent"},
		{"createTextNode", "createTextNode"},
		{"setattribute", "setAttribute"}, // for non-dangerous attributes
	}
	for _, d := range safeDOM {
		if strings.Contains(lower, d.pattern) {
			return FilterInfo{true, "dom-safe", d.name}
		}
	}

	// 5. Regex-based Filtering (replace with regex)
	regexFilters := []struct {
		pattern string
		name    string
	}{
		{"replace(/<", "regex strip tags"},
		{"replace(/>", "regex strip tags"},
		{"replace(/script", "regex strip script"},
		{"replace(/on\\w+", "regex strip events"},
		{"replace(/javascript:", "regex strip js protocol"},
		{".replace(.*<.*>)", "regex strip tags"},
	}
	for _, r := range regexFilters {
		if strings.Contains(lower, r.pattern) {
			return FilterInfo{true, "regex-replace", r.name}
		}
	}

	// 6. Validation/Whitelist
	validators := []struct {
		pattern string
		name    string
	}{
		{"whitelist", "whitelist validation"},
		{"allowlist", "allowlist validation"},
		{"validurl", "URL validation"},
		{"isurl", "URL validation"},
		{"validemail", "email validation"},
	}
	for _, v := range validators {
		if strings.Contains(lower, v.pattern) {
			return FilterInfo{true, "validation", v.name}
		}
	}

	// 7. Content Security Policy indicators
	cspIndicators := []struct {
		pattern string
		name    string
	}{
		{"content-security-policy", "CSP"},
		{"nonce=", "CSP nonce"},
		{"strict-dynamic", "CSP strict-dynamic"},
	}
	for _, c := range cspIndicators {
		if strings.Contains(lower, c.pattern) {
			return FilterInfo{true, "csp", c.name}
		}
	}

	return FilterInfo{false, "", ""}
}

// isFiltered is a simple check if filtering exists (backward compatible)
func isFiltered(line string) bool {
	return detectFilter(line).IsFiltered
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
