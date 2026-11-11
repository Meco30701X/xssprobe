package verifier

import (
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/Meco30701X/xssprobe/payloads"
)

func TestGetTestPayloads_CustomOnly(t *testing.T) {
	custom := []payloads.Payload{{Value: `"<img src=x onerror="window.xssTriggered=true">`}}
	config := NewPayloadConfig(custom, true)
	config.CustomOnly = true

	got := getTestPayloads("generic", config, true)
	if !reflect.DeepEqual(got, []string{custom[0].Value}) {
		t.Fatalf("custom-only payloads = %#v, want only %#v", got, custom)
	}
}

func TestIncludeTargetURLParamsPrioritizesExistingQueryInputs(t *testing.T) {
	got := includeTargetURLParams("https://example.test/search?tag=b&query=seed&tag=a", []string{"q", "query"})
	want := []string{"query", "tag", "q"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("URL parameter order = %#v, want %#v", got, want)
	}
}

func TestIncludeTargetURLParamContextsCopiesAndAddsQueryInputs(t *testing.T) {
	original := map[string]string{"search": "html"}
	got := includeTargetURLParamContexts("https://example.test/?query=seed", original)
	if got["search"] != "html" || got["query"] != "" {
		t.Fatalf("merged contexts = %#v", got)
	}
	if len(original) != 1 {
		t.Fatalf("input context map was mutated: %#v", original)
	}
}

func TestGetHashTestPayloadsUsesOneSafeMarkerPerContext(t *testing.T) {
	got := getHashTestPayloads(nil)
	if len(got) != 4 {
		t.Fatalf("hash canary count = %d, want 4 representative contexts", len(got))
	}
	for _, payload := range got {
		if !strings.Contains(payload, "window.xssTriggered=true") {
			t.Errorf("hash test payload is not a marker canary: %q", payload)
		}
	}
}

func TestGetHashTestPayloadsHonorsCustomOnly(t *testing.T) {
	custom := []payloads.Payload{{Value: "hash-custom-a"}, {Value: "hash-custom-b"}}
	config := NewPayloadConfig(custom, true)
	config.CustomOnly = true
	got := getHashTestPayloads(config)
	if !reflect.DeepEqual(got, []string{"hash-custom-a", "hash-custom-b"}) {
		t.Fatalf("custom-only hash payloads = %#v", got)
	}
}

func TestGetTestPayloads_MergesCustomAndCanariesByDefault(t *testing.T) {
	custom := []payloads.Payload{{Value: "custom-marker"}}
	got := getTestPayloads("", NewPayloadConfig(custom, true), false)
	if len(got) <= 1 || got[0] != custom[0].Value {
		t.Fatalf("merged payloads should start with custom payload and include built-ins; got %d", len(got))
	}
}

func TestGetTestPayloadsByContext_CustomOnly(t *testing.T) {
	custom := []payloads.Payload{{Value: "context-marker"}}
	config := NewPayloadConfig(custom, true)
	config.CustomOnly = true
	got := getTestPayloadsByContext("html", "generic", config)
	if !reflect.DeepEqual(got, []string{custom[0].Value}) {
		t.Fatalf("context custom-only payloads = %#v, want only %#v", got, custom)
	}
}

func TestIsSafeClickCanary(t *testing.T) {
	want := "javascript:window.xssTriggered=true/*" + Canary + "*/"
	if !isSafeClickCanary(want) {
		t.Fatal("expected the marker-only javascript URL to be considered safe to activate")
	}
	for _, payload := range []string{`<a href=` + want + `>x</a>`, `<a href="` + want + `">x</a>`} {
		if target, ok := safeClickCanaryTarget(payload); !ok || target != want {
			t.Errorf("safe anchor canary not recognized: target=%q ok=%v", target, ok)
		}
	}
	for _, payload := range []string{
		"javascript:alert(1)",
		"javascript:window.location='https://example.invalid'",
		"javascript:document.cookie",
		`<a href="javascript:alert(1)">x</a>`,
		`<a href="javascript:window.xssTriggered=true/*` + Canary + `*/;fetch('/collect')">x</a>`,
	} {
		if isSafeClickCanary(payload) {
			t.Errorf("unsafe javascript URL was allowed for automatic activation: %q", payload)
		}
	}
}

func TestSafeHoverCanaryExact(t *testing.T) {
	handler := "window.xssTriggered=true/*" + Canary + "*/"
	payload := "x\" onmouseover=\"" + handler + "\" x=\""
	attribute, gotHandler, ok := safeHoverCanaryExact(payload)
	if !ok || attribute != "onmouseover" || gotHandler != handler {
		t.Fatalf("safe hover canary = (%q, %q, %v)", attribute, gotHandler, ok)
	}
	unsafe := []string{
		"x\" onmouseover=\"alert(1)\" x=\"",
		"x\" onmouseover=\"window.location='https://example.invalid'\" x=\"",
		"x\" onmouseover=\"" + handler + ";fetch('/collect')\" x=\"",
	}
	for _, payload := range unsafe {
		if _, _, ok := safeHoverCanaryExact(payload); ok {
			t.Errorf("unsafe hover canary accepted: %q", payload)
		}
	}
}

func TestSafeFocusCanary(t *testing.T) {
	got := safeFocusCanary("x\" autofocus onfocus=\"window.xssTriggered=true/*" + Canary + "*/")
	if !got {
		t.Fatal("expected exact marker-only focus handler to be safe")
	}
	for _, payload := range []string{
		"x\" autofocus onfocus=\"alert(1)",
		"x\" autofocus onfocus=\"window.location='https://example.invalid'",
		"x\" autofocus onfocus=\"window.xssTriggered=true/*" + Canary + "*/;fetch('/collect')",
	} {
		if safeFocusCanary(payload) {
			t.Errorf("unsafe focus payload accepted: %q", payload)
		}
	}
}

func TestWithURLFragmentUsesFragmentEscapingAndReplacesExistingHash(t *testing.T) {
	got := withURLFragment("https://example.test/page?q=1#old", `<img src=x onerror="window.xssTriggered=true">`)
	want := "https://example.test/page?q=1#%3Cimg%20src=x%20onerror=%22window.xssTriggered=true%22%3E"
	if got != want {
		t.Fatalf("fragment URL = %q, want %q", got, want)
	}
	if strings.Contains(got, "+") {
		t.Fatalf("fragment URL must not use query-style plus for spaces: %q", got)
	}
}

func TestWithPathSuffixPreservesQueryAndFragment(t *testing.T) {
	got, err := withPathSuffix("https://example.test/lab/invalid?q=seed#keep", `<img src=x onerror="window.xssTriggered=true">`)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Path != `/lab/invalid<img src=x onerror="window.xssTriggered=true">` {
		t.Fatalf("mutated path = %q", parsed.Path)
	}
	if parsed.Query().Get("q") != "seed" || parsed.Fragment != "keep" {
		t.Fatalf("query or fragment was changed: %s", got)
	}
}

func TestSafeHoverCanary(t *testing.T) {
	payload := `x" onmouseover="window.xssTriggered=true/*` + Canary + `*/" x="`
	attribute, handler, ok := safeHoverCanary(payload)
	if !ok || attribute != "onmouseover" || handler != "window.xssTriggered=true/*"+Canary+"*/" {
		t.Fatalf("safe hover canary = (%q, %q, %v)", attribute, handler, ok)
	}
	for _, unsafe := range []string{
		`x" onmouseover="alert(1)" x="`,
		`x" onmouseover="window.location='https://example.invalid'" x="`,
		`x" onmouseover="window.xssTriggered=true/*` + Canary + `*/;fetch('/collect')" x="`,
	} {
		if _, _, ok := safeHoverCanary(unsafe); ok {
			t.Errorf("unsafe hover payload accepted: %q", unsafe)
		}
	}
}
