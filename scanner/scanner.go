package scanner

import (
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
		// === Location Sources ===
		{"location.hash", regexp.MustCompile(`location\.hash`)},
		{"location.search", regexp.MustCompile(`location\.search`)},
		{"location.href", regexp.MustCompile(`location\.href`)},
		{"location.pathname", regexp.MustCompile(`location\.pathname`)},
		{"location.origin", regexp.MustCompile(`location\.origin`)},
		{"location.protocol", regexp.MustCompile(`location\.protocol`)},
		{"location.host", regexp.MustCompile(`location\.host`)},
		{"location.hostname", regexp.MustCompile(`location\.hostname`)},
		{"location.port", regexp.MustCompile(`location\.port`)},
		{"location.assign", regexp.MustCompile(`location\.assign\s*\(`)},
		{"location.replace", regexp.MustCompile(`location\.replace\s*\(`)},

		// === Document Sources ===
		{"document.URL", regexp.MustCompile(`document\.URL`)},
		{"document.documentURI", regexp.MustCompile(`document\.documentURI`)},
		{"document.referrer", regexp.MustCompile(`document\.referrer`)},
		{"document.baseURI", regexp.MustCompile(`document\.baseURI`)},
		{"document.cookie", regexp.MustCompile(`document\.cookie`)},
		{"document.domain", regexp.MustCompile(`document\.domain`)},

		// === Window Sources ===
		{"window.name", regexp.MustCompile(`window\.name`)},
		{"window.location", regexp.MustCompile(`window\.location`)},
		{"window.opener", regexp.MustCompile(`window\.opener`)},
		{"window.parent", regexp.MustCompile(`window\.parent`)},
		{"window.top", regexp.MustCompile(`window\.top`)},
		{"window.frames", regexp.MustCompile(`window\.frames`)},

		// === URL/HTTP Sources ===
		{"postMessage", regexp.MustCompile(`postMessage|addEventListener\s*\(\s*['"]message['"]`)},
		{"XMLHttpRequest", regexp.MustCompile(`XMLHttpRequest|\.responseText|\.response\b`)},
		{"fetch", regexp.MustCompile(`fetch\s*\(|\.then\s*\(|\.json\s*\(`)},
		{"URL", regexp.MustCompile(`new\s+URL\s*\(|URL\.parse|URLSearchParams`)},
		{"FormData", regexp.MustCompile(`FormData|\.get\s*\(|\.getAll\s*\(`)},

		// === DOM Element Sources ===
		{"element.value", regexp.MustCompile(`\.value\b`)},
		{"element.textContent", regexp.MustCompile(`\.textContent\b`)},
		{"element.innerText", regexp.MustCompile(`\.innerText\b`)},
		{"element.innerHTML", regexp.MustCompile(`\.innerHTML\b`)},
		{"element.getAttribute", regexp.MustCompile(`\.getAttribute\s*\(`)},
		{"element.dataset", regexp.MustCompile(`\.dataset\b|\.dataset\.`)},
		{"element.src", regexp.MustCompile(`\.src\b`)},
		{"element.action", regexp.MustCompile(`\.action\b`)},
		{"element.href", regexp.MustCompile(`\.href\b`)},

		// === Input/Form Sources ===
		{"input.value", regexp.MustCompile(`(?:input|textarea|select)\S*\.value`)},
		{"form.elements", regexp.MustCompile(`\.elements\[|\.elements\.`)},
		{"FormData.get", regexp.MustCompile(`FormData.*\.get\s*\(`)},

		// === Storage Sources ===
		{"localStorage", regexp.MustCompile(`localStorage\.getItem\s*\(|localStorage\[`)},
		{"sessionStorage", regexp.MustCompile(`sessionStorage\.getItem\s*\(|sessionStorage\[`)},
		{"indexedDB", regexp.MustCompile(`indexedDB|IDBKeyRange`)},

		// === API/Function Return Sources ===
		{"decodeURI", regexp.MustCompile(`decodeURI\s*\(|decodeURIComponent\s*\(`)},
		{"String.fromCharCode", regexp.MustCompile(`String\.fromCharCode\s*\(`)},
		{"JSON.parse", regexp.MustCompile(`JSON\.parse\s*\(`)},
		{"atob", regexp.MustCompile(`atob\s*\(`)},

		// === jQuery Sources ===
		{"jQuery.param", regexp.MustCompile(`\$\.param\s*\(|jQuery\.param\s*\(`)},
		{"jQuery.val", regexp.MustCompile(`\$\(.*\)\.val\s*\(`)},
		{"jQuery.text", regexp.MustCompile(`\$\(.*\)\.text\s*\(`)},
		{"jQuery.html", regexp.MustCompile(`\$\(.*\)\.html\s*\(`)},
		{"jQuery.attr", regexp.MustCompile(`\$\(.*\)\.attr\s*\(`)},

		// === React/Vue/Angular Sources ===
		{"React dangerouslySetInnerHTML", regexp.MustCompile(`dangerouslySetInnerHTML`)},
		{"Vue v-html", regexp.MustCompile(`v-html|__html`)},
		{"Angular [innerHTML]", regexp.MustCompile(`\[innerHTML\]|\[outerHTML\]`)},
		{"Angular $sce", regexp.MustCompile(`\$sce\.trustAs|trustAsHtml`)},

		// === Template/Interpolation ===
		{"template literal", regexp.MustCompile("`[^`]*\\$\\{")},

		// === Web API Sources ===
		{"BroadcastChannel", regexp.MustCompile(`BroadcastChannel|\.postMessage`)},
		{"ServiceWorker", regexp.MustCompile(`ServiceWorker|navigator\.serviceWorker`)},
		{"WebRTC", regexp.MustCompile(`RTCPeerConnection|createDataChannel`)},
		{"Geolocation", regexp.MustCompile(`getCurrentPosition|watchPosition`)},
	}
}

func getSinks() []pattern {
	return []pattern{
		// === Code Execution Sinks ===
		{"eval", regexp.MustCompile(`eval\s*\(`)},
		{"setTimeout", regexp.MustCompile(`setTimeout\s*\(`)},
		{"setInterval", regexp.MustCompile(`setInterval\s*\(`)},
		{"Function", regexp.MustCompile(`new\s+Function\s*\(|Function\s*\(`)},
		{"script.src", regexp.MustCompile(`\.src\s*=`)},
		{"script.text", regexp.MustCompile(`\.text\s*=|\.textContent\s*=|\.innerText\s*=`)},

		// === DOM Manipulation Sinks ===
		{"innerHTML", regexp.MustCompile(`\.innerHTML\s*=`)},
		{"outerHTML", regexp.MustCompile(`\.outerHTML\s*=`)},
		{"document.write", regexp.MustCompile(`document\.write\s*\(|document\.writeln\s*\(`)},
		{"insertAdjacentHTML", regexp.MustCompile(`insertAdjacentHTML\s*\(`)},
		{"insertBefore", regexp.MustCompile(`insertBefore\s*\(`)},
		{"appendChild", regexp.MustCompile(`appendChild\s*\(`)},
		{"replaceChild", regexp.MustCompile(`replaceChild\s*\(`)},
		{"cloneNode", regexp.MustCompile(`cloneNode\s*\(`)},

		// === Attribute Sinks ===
		{"setAttribute", regexp.MustCompile(`\.setAttribute\s*\(`)},
		{"setAttributeNS", regexp.MustCompile(`\.setAttributeNS\s*\(`)},
		{"createAttribute", regexp.MustCompile(`createAttribute\s*\(`)},
		{"createAttributeNS", regexp.MustCompile(`createAttributeNS\s*\(`)},

		// === Navigation Sinks ===
		{"window.open", regexp.MustCompile(`window\.open\s*\(`)},
		{"location.href", regexp.MustCompile(`location\.href\s*=|window\.location\s*=|document\.location\s*=`)},
		{"location.assign", regexp.MustCompile(`location\.assign\s*\(`)},
		{"location.replace", regexp.MustCompile(`location\.replace\s*\(`)},
		{"meta.refresh", regexp.MustCompile(`http-equiv.*refresh|content.*url=`)},

		// === Document/Element Creation Sinks ===
		{"document.createElement", regexp.MustCompile(`createElement\s*\(`)},
		{"document.createElementNS", regexp.MustCompile(`createElementNS\s*\(`)},
		{"document.createDocumentFragment", regexp.MustCompile(`createDocumentFragment\s*\(`)},

		// === jQuery Sinks ===
		{"jQuery.html", regexp.MustCompile(`\.html\s*\(`)},
		{"jQuery.append", regexp.MustCompile(`\.append\s*\(`)},
		{"jQuery.prepend", regexp.MustCompile(`\.prepend\s*\(`)},
		{"jQuery.after", regexp.MustCompile(`\.after\s*\(`)},
		{"jQuery.before", regexp.MustCompile(`\.before\s*\(`)},
		{"jQuery.replaceWith", regexp.MustCompile(`\.replaceWith\s*\(`)},
		{"jQuery.wrap", regexp.MustCompile(`\.wrap\s*\(`)},
		{"jQuery.htmlPrefilter", regexp.MustCompile(`\.htmlPrefilter\s*\(`)},

		// === React Sinks ===
		{"React dangerouslySetInnerHTML", regexp.MustCompile(`dangerouslySetInnerHTML`)},

		// === Vue Sinks ===
		{"Vue v-html", regexp.MustCompile(`v-html`)},

		// === Angular Sinks ===
		{"Angular [innerHTML]", regexp.MustCompile(`\[innerHTML\]|\[outerHTML\]`)},
		{"Angular $compile", regexp.MustCompile(`\$compile\s*\(`)},

		// === Cookie Sinks ===
		{"document.cookie", regexp.MustCompile(`document\.cookie\s*=`)},

		// === Storage Sinks ===
		{"localStorage.setItem", regexp.MustCompile(`localStorage\.setItem\s*\(|localStorage\[`)},
		{"sessionStorage.setItem", regexp.MustCompile(`sessionStorage\.setItem\s*\(|sessionStorage\[`)},

		// === Ajax/Fetch Sinks ===
		{"$.ajax", regexp.MustCompile(`\$\.ajax\s*\(|jQuery\.ajax\s*\(`)},
		{"$.get", regexp.MustCompile(`\$\.get\s*\(|jQuery\.get\s*\(`)},
		{"$.post", regexp.MustCompile(`\$\.post\s*\(|jQuery\.post\s*\(`)},
		{"fetch.body", regexp.MustCompile(`fetch\s*\(.*body`)},

		// === WebSocket Sinks ===
		{"WebSocket.send", regexp.MustCompile(`\.send\s*\(`)},

		// === Message Sinks ===
		{"postMessage", regexp.MustCompile(`\.postMessage\s*\(`)},
		{"BroadcastChannel", regexp.MustCompile(`BroadcastChannel.*\.postMessage`)},

		// === DOM Clobbering Sinks ===
		{"document.getElementById", regexp.MustCompile(`getElementById\s*\(`)},
		{"document.getElementsByName", regexp.MustCompile(`getElementsByName\s*\(`)},
		{"document.querySelector", regexp.MustCompile(`querySelector\s*\(`)},
		{"document.getElementsByClassName", regexp.MustCompile(`getElementsByClassName\s*\(`)},
		{"document.getElementsByTagName", regexp.MustCompile(`getElementsByTagName\s*\(`)},

		// === Prototype Pollution Sinks ===
		{"Object.assign", regexp.MustCompile(`Object\.assign\s*\(`)},
		{"Object.setPrototypeOf", regexp.MustCompile(`Object\.setPrototypeOf\s*\(`)},
		{"__proto__", regexp.MustCompile(`__proto__|constructor\.prototype`)},
		{"$.extend", regexp.MustCompile(`\$\.extend\s*\(|jQuery\.extend\s*\(`)},
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
