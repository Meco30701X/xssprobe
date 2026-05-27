package scanner

import (
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

// ScanJS analyzes JavaScript content for DOM XSS patterns
func ScanJS(jsContent string) []Finding {
	var findings []Finding
	lines := strings.Split(jsContent, "\n")

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") {
			continue
		}

		// Check for source-to-sink patterns
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

		// Check for standalone sinks that might be dangerous
		for _, sink := range getSinks() {
			if sink.Re.MatchString(trimmed) {
				// Only flag if it's not already caught by source-sink pattern
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
