package scanner

import (
	"testing"
)

func TestScanJS_SourceSinkDetection(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		minFind  int
	}{
		{
			name:    "location.hash to innerHTML",
			code:    `el.innerHTML = location.hash;`,
			minFind: 1,
		},
		{
			name:    "location.search to eval",
			code:    `eval(location.search);`,
			minFind: 1,
		},
		{
			name:    "no vulnerability",
			code:    `var x = "hello";`,
			minFind: 0,
		},
		{
			name:    "sink only (unknown source)",
			code:    `el.innerHTML = someVar;`,
			minFind: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ScanJS(tt.code)
			if len(findings) < tt.minFind {
				t.Errorf("ScanJS() found %d findings, want at least %d", len(findings), tt.minFind)
			}
		})
	}
}

func TestScanJS_FilterDetection(t *testing.T) {
	tests := []struct {
		name       string
		code       string
		filtered   bool
		filterType string
	}{
		{
			name:       "encodeURIComponent",
			code:       `var x = encodeURIComponent(location.hash); el.innerHTML = x;`,
			filtered:   true,
			filterType: "encoding:encodeURIComponent",
		},
		{
			name:       "DOMPurify",
			code:       `var x = DOMPurify.sanitize(location.hash); el.innerHTML = x;`,
			filtered:   true,
			filterType: "sanitization:DOMPurify",
		},
		{
			name:     "no filter",
			code:     `el.innerHTML = location.hash;`,
			filtered: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := ScanJS(tt.code)
			if len(findings) == 0 {
				t.Fatal("expected at least one finding")
			}

			if findings[0].Filtered != tt.filtered {
				t.Errorf("Filtered = %v, want %v", findings[0].Filtered, tt.filtered)
			}

			if tt.filtered && findings[0].FilterType != tt.filterType {
				t.Errorf("FilterType = %s, want %s", findings[0].FilterType, tt.filterType)
			}
		})
	}
}

func TestScanJS_CrossLineTaint(t *testing.T) {
	code := `
		var userInput = location.hash;
		var processed = userInput;
		el.innerHTML = processed;
	`

	findings := ScanJS(code)

	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	// Should detect the cross-line taint
	found := false
	for _, f := range findings {
		if f.Source != "" && f.Source != "unknown" {
			found = true
			break
		}
	}

	if !found {
		t.Error("expected source detection in cross-line taint")
	}
}

func TestTaintTracker_TrackLine(t *testing.T) {
	tracker := NewTaintTracker()

	// Track a tainted assignment
	tracker.TrackLine("var x = location.hash;")

	// Check if x is tainted
	source, ok := tracker.GetTaintedVar("x")
	if !ok {
		t.Error("expected x to be tainted")
	}
	if source != "location.hash" {
		t.Errorf("source = %s, want location.hash", source)
	}

	// Track propagation
	tracker.TrackLine("var y = x;")

	source, ok = tracker.GetTaintedVar("y")
	if !ok {
		t.Error("expected y to be tainted")
	}
}

func TestTaintTracker_SafeReassignment(t *testing.T) {
	tracker := NewTaintTracker()

	tracker.TrackLine("var x = location.hash;")
	tracker.TrackLine("x = 'safe value';")

	_, ok := tracker.GetTaintedVar("x")
	if ok {
		t.Error("expected x to be untainted after safe reassignment")
	}
}

func TestDetectFilter(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		filtered bool
		typ      string
	}{
		{"encodeURIComponent", `x = encodeURIComponent(y)`, true, "encoding"},
		{"encodeURI", `x = encodeURI(y)`, true, "encoding"},
		{"escape", `x = escape(y)`, true, "encoding"},
		{"DOMPurify", `x = DOMPurify.sanitize(y)`, true, "sanitization"},
		{"innerText", `el.innerText = y`, true, "dom-safe"},
		{"textContent", `el.textContent = y`, true, "dom-safe"},
		{"no filter", `el.innerHTML = y`, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := detectFilter(tt.line)
			if info.IsFiltered != tt.filtered {
				t.Errorf("IsFiltered = %v, want %v", info.IsFiltered, tt.filtered)
			}
			if tt.filtered && info.Type != tt.typ {
				t.Errorf("Type = %s, want %s", info.Type, tt.typ)
			}
		})
	}
}

func TestGetSources(t *testing.T) {
	sources := getSources()

	if len(sources) == 0 {
		t.Error("expected non-empty sources")
	}

	// Check for common sources
	commonSources := []string{
		"location.hash", "location.search", "document.referrer",
		"window.name", "postMessage",
	}

	sourceNames := make(map[string]bool)
	for _, s := range sources {
		sourceNames[s.Name] = true
	}

	for _, name := range commonSources {
		if !sourceNames[name] {
			t.Errorf("missing source: %s", name)
		}
	}
}

func TestGetSinks(t *testing.T) {
	sinks := getSinks()

	if len(sinks) == 0 {
		t.Error("expected non-empty sinks")
	}

	// Check for common sinks
	commonSinks := []string{
		"eval", "innerHTML", "outerHTML", "document.write",
		"setTimeout", "insertAdjacentHTML",
	}

	sinkNames := make(map[string]bool)
	for _, s := range sinks {
		sinkNames[s.Name] = true
	}

	for _, name := range commonSinks {
		if !sinkNames[name] {
			t.Errorf("missing sink: %s", name)
		}
	}
}
