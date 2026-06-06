package verifier

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Meco30701X/xssprobe/compliance"
	"github.com/Meco30701X/xssprobe/payloads"
	"github.com/Meco30701X/xssprobe/safety"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
)

// VerifyResult represents the result of a dynamic verification
type VerifyResult struct {
	Payload   string `json:"payload"`
	Source    string `json:"source"`
	Triggered bool   `json:"triggered"`
	Detail    string `json:"detail"`
}

// AuthConfig holds authentication info for requests
type AuthConfig struct {
	Cookies []string          // e.g. ["session=abc123", "token=xyz"]
	Headers map[string]string // e.g. {"Authorization": "Bearer xxx"}
}

// Canary is a unique string used to detect if payload reaches the DOM
const Canary = "xXssCanary42x"

// disableCORSFlag controls whether browser same-origin policy is disabled
var disableCORSFlag bool

// SetDisableCORS sets whether to disable browser same-origin policy
func SetDisableCORS(disable bool) {
	disableCORSFlag = disable
}

// proxyURL stores the HTTP proxy URL
var proxyFlag string

// SetProxy sets the HTTP proxy for chromedp
func SetProxy(proxy string) {
	proxyFlag = proxy
}

// PayloadConfig holds custom payload configuration (thread-safe)
type PayloadConfig struct {
	CustomPayloads []payloads.Payload
	CustomFirst    bool
}

// NewPayloadConfig creates a new PayloadConfig
func NewPayloadConfig(custom []payloads.Payload, first bool) *PayloadConfig {
	return &PayloadConfig{
		CustomPayloads: custom,
		CustomFirst:    first,
	}
}

// getTestPayloads returns the payload strings to test, optionally filtered by WAF
func getTestPayloads(waf string, config *PayloadConfig) []string {
	var result []string

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

	if waf != "" {
		// Add WAF-specific bypass payloads
		for _, p := range payloads.GetPayloadsByWAF(waf) {
			result = append(result, p.Value)
		}
	} else {
		// Add a selection of base payloads (not all, to keep scan time reasonable)
		base := payloads.GetBasePayloads()
		// Use up to 20 base payloads
		limit := 20
		if len(base) < limit {
			limit = len(base)
		}
		for i := 0; i < limit; i++ {
			result = append(result, base[i].Value)
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

// getTestPayloadsByContext returns payloads selected by injection context and WAF
func getTestPayloadsByContext(contextType string, waf string, config *PayloadConfig) []string {
	var result []string

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
func newChromeContext(ctx context.Context, auth *AuthConfig, disableCORS bool) (context.Context, context.CancelFunc) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
	)
	if disableCORS {
		opts = append(opts, chromedp.Flag("disable-web-security", true))
	}
	if proxyFlag != "" {
		opts = append(opts, chromedp.Flag("proxy-server", proxyFlag))
	}

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	taskCtx, taskCancel := chromedp.NewContext(allocCtx)

	// Apply auth if provided
	if auth != nil {
		var actions []chromedp.Action

		// Set cookies
		for _, cookie := range auth.Cookies {
			parts := strings.SplitN(cookie, "=", 2)
			if len(parts) == 2 {
				actions = append(actions, network.SetCookie(parts[0], parts[1]).
					WithDomain(extractDomain(ctx)).
					WithPath("/"))
			}
		}

		// Set custom headers
		if len(auth.Headers) > 0 {
			headerMap := network.Headers{}
			for k, v := range auth.Headers {
				headerMap[k] = v
			}
			actions = append(actions, network.SetExtraHTTPHeaders(headerMap))
		}

		if len(actions) > 0 {
			if err := chromedp.Run(taskCtx, actions...); err != nil {
				// Auth setup failed, continue without auth
				fmt.Printf("  [!] Warning: auth setup failed: %v\n", err)
			}
		}
	}

	combinedCancel := func() {
		taskCancel()
		allocCancel()
	}

	return taskCtx, combinedCancel
}

// extractDomain extracts domain from context (unused, cookie domain auto-applies)
func extractDomain(ctx context.Context) string {
	// Empty string makes cookie apply to the current page's domain
	return ""
}

// VerifyURL tests a URL for reflected DOM XSS
func VerifyURL(targetURL string, auth *AuthConfig, waf string, limiter *compliance.RateLimiter, config *PayloadConfig) []VerifyResult {
	// Default parameters for backward compatibility
	defaultParams := []string{"q", "search", "id", "page", "input", "name", "s"}
	return VerifyURLWithParams(targetURL, auth, waf, defaultParams, limiter, config)
}

// VerifyURLWithParams tests a URL for reflected DOM XSS with custom parameters
func VerifyURLWithParams(targetURL string, auth *AuthConfig, waf string, params []string, limiter *compliance.RateLimiter, config *PayloadConfig) []VerifyResult {
	var results []VerifyResult
	testPayloads := getTestPayloads(waf, config)

	if len(params) == 0 {
		params = []string{"q", "search", "id", "page", "input", "name", "s"}
	}

	for _, payload := range testPayloads {
		// Test hash fragment
		r := testHash(targetURL, payload, auth, limiter)
		results = append(results, r)

		// Test each parameter
		for _, param := range params {
			r = testSearchParam(targetURL, param, payload, auth, limiter)
			results = append(results, r)
		}
	}

	return results
}

// VerifyURLWithContext tests a URL with context-aware payload selection
func VerifyURLWithContext(targetURL string, auth *AuthConfig, waf string, paramContexts map[string]string, limiter *compliance.RateLimiter, config *PayloadConfig) []VerifyResult {
	var results []VerifyResult

	// Test hash fragment with default payloads
	testPayloads := getTestPayloads(waf, config)
	for _, payload := range testPayloads[:min(5, len(testPayloads))] {
		r := testHash(targetURL, payload, auth, limiter)
		results = append(results, r)
	}

	// Test each parameter with context-aware payloads
	for param, ctxType := range paramContexts {
		// Get context-specific payloads
		contextPayloads := getTestPayloadsByContext(ctxType, waf, config)
		if len(contextPayloads) == 0 {
			contextPayloads = testPayloads[:min(10, len(testPayloads))]
		}

		fmt.Printf("    Testing '%s' (context: %s) with %d payloads\n", param, ctxType, len(contextPayloads))

		for _, payload := range contextPayloads {
			r := testSearchParam(targetURL, param, payload, auth, limiter)
			results = append(results, r)
		}
	}

	return results
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func testHash(baseURL, payload string, auth *AuthConfig, limiter *compliance.RateLimiter) VerifyResult {
	result := VerifyResult{Payload: payload, Source: "hash"}
	testURL := baseURL + "#" + url.QueryEscape(payload)

	if limiter != nil {
		limiter.Wait()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	taskCtx, taskCancel := newChromeContext(ctx, auth, disableCORSFlag)
	defer taskCancel()

	chromedp.ListenTarget(taskCtx, func(ev interface{}) {
		if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			result.Triggered = true
			result.Detail = "alert() dialog triggered"
		}
	})

	var domContent string
	var jsTriggered bool

	err := chromedp.Run(taskCtx,
		chromedp.Navigate(testURL),
		chromedp.Sleep(2*time.Second),
		chromedp.Evaluate(`window.xssTriggered || false`, &jsTriggered),
		chromedp.InnerHTML("html", &domContent),
	)

	if err != nil {
		// Check if alert was triggered before the error
		if result.Triggered {
			// alert() was triggered - this is a confirmed XSS
			return result
		}
		result.Detail = "navigation error: " + err.Error()
		return result
	}

	if jsTriggered {
		result.Triggered = true
		result.Detail = "JavaScript execution confirmed (window.xssTriggered=true)"
	} else if result.Triggered {
		// alert() dialog was triggered - already set by event listener
	} else if strings.Contains(domContent, Canary) {
		if isCanaryExecutable(domContent, Canary) {
			result.Triggered = true
			result.Detail = "Canary in executable position (script/event handler)"
		} else {
			result.Triggered = false
			result.Detail = "Input reflected but not in executable position"
		}
	}

	return result
}

func testSearchParam(baseURL, param, payload string, auth *AuthConfig, limiter *compliance.RateLimiter) VerifyResult {
	result := VerifyResult{Payload: payload, Source: "search:" + param}

	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		result.Detail = "invalid URL"
		return result
	}

	q := parsedURL.Query()
	q.Set(param, payload)
	parsedURL.RawQuery = q.Encode()
	testURL := parsedURL.String()

	if limiter != nil {
		limiter.Wait()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	taskCtx, taskCancel := newChromeContext(ctx, auth, disableCORSFlag)
	defer taskCancel()

	chromedp.ListenTarget(taskCtx, func(ev interface{}) {
		if _, ok := ev.(*page.EventJavascriptDialogOpening); ok {
			result.Triggered = true
			result.Detail = "alert() dialog triggered"
		}
	})

	var domContent string
	var jsTriggered bool

	err = chromedp.Run(taskCtx,
		chromedp.Navigate(testURL),
		chromedp.Sleep(2*time.Second),
		chromedp.Evaluate(`window.xssTriggered || false`, &jsTriggered),
		chromedp.InnerHTML("html", &domContent),
	)

	if err != nil {
		// Check if alert was triggered before the error
		if result.Triggered {
			// alert() was triggered - this is a confirmed XSS
			return result
		}
		result.Detail = "navigation error: " + err.Error()
		return result
	}

	if jsTriggered {
		result.Triggered = true
		result.Detail = "JavaScript execution confirmed (window.xssTriggered=true)"
	} else if result.Triggered {
		// alert() dialog was triggered - already set by event listener
		// Keep existing detail
	} else if strings.Contains(domContent, Canary) {
		// Canary found in DOM - but is it in an executable position?
		// Check if canary is inside <script> tags or event handlers
		if isCanaryExecutable(domContent, Canary) {
			result.Triggered = true
			result.Detail = "Canary in executable position (script/event handler)"
		} else {
			// Canary is just reflected text, not executable XSS
			result.Triggered = false
			result.Detail = "Input reflected but not in executable position"
		}
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

// VerifyStoredXSS tests for stored DOM XSS with safety controls
func VerifyStoredXSS(targetURL string, auth *AuthConfig, waf string, safetyMode *safety.SafetyMode, limiter *compliance.RateLimiter) ([]VerifyResult, bool) {
	var results []VerifyResult

	// Safety: print configuration
	safety.PrintSafetyInfo(safetyMode)

	if limiter != nil {
		limiter.Wait()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	taskCtx, taskCancel := newChromeContext(ctx, auth, disableCORSFlag)
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
			Source: "stored", Detail: "failed to load page: " + err.Error(),
		})
		return results, false
	}

	inputs := parseInputSelectors(inputJSON)

	if len(inputs) == 0 {
		results = append(results, VerifyResult{
			Source: "stored", Detail: "no input fields found on page",
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
		if limiter != nil {
			limiter.Wait()
		}

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
					Source: "stored", Payload: "canary", Triggered: true,
					Detail: "JavaScript executed after page reload (stored XSS confirmed)",
				})
			} else if strings.Contains(afterHTML, Canary) {
				results = append(results, VerifyResult{
					Source: "stored", Payload: "canary", Triggered: true,
					Detail: "Payload persisted in DOM after reload (stored HTML injection)",
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
		return result
	}

	if jsTriggered {
		result.Triggered = true
		result.Detail = "JS executed after form submission via " + input.Selector
	} else if strings.Contains(domContent, Canary) {
		result.Triggered = true
		result.Detail = "Payload reflected in DOM via " + input.Selector
	}

	return result
}

// TestHashOnly tests only hash-based XSS (for analyzer)
func TestHashOnly(targetURL string, auth *AuthConfig, waf string, config *PayloadConfig) VerifyResult {
	payloads := getTestPayloads(waf, config)
	if len(payloads) == 0 {
		return VerifyResult{Source: "hash", Detail: "no payloads available"}
	}

	// Use first canary payload
	payload := payloads[0]
	return testHash(targetURL, payload, auth, nil)
}

// TestSearchOnly tests only search parameter XSS (for analyzer)
func TestSearchOnly(targetURL string, auth *AuthConfig, waf string, config *PayloadConfig) VerifyResult {
	payloads := getTestPayloads(waf, config)
	if len(payloads) == 0 {
		return VerifyResult{Source: "search", Detail: "no payloads available"}
	}

	payload := payloads[0]
	params := []string{"q", "search", "id", "page", "input", "name", "s"}

	for _, param := range params {
		r := testSearchParam(targetURL, param, payload, auth, nil)
		if r.Triggered {
			return r
		}
	}

	return VerifyResult{Source: "search", Payload: payload, Detail: "not triggered"}
}

// VerifyPostMessage tests postMessage-based XSS
func VerifyPostMessage(targetURL string, auth *AuthConfig, waf string, limiter *compliance.RateLimiter) VerifyResult {
	result := VerifyResult{Source: "postMessage", Payload: Canary}

	if limiter != nil {
		limiter.Wait()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	taskCtx, taskCancel := newChromeContext(ctx, auth, disableCORSFlag)
	defer taskCancel()

	// Inject postMessage listener and trigger
	jsPostMessage := `
		(function() {
			var triggered = false;
			window.addEventListener('message', function(e) {
				try {
					// Try to execute the message data
					var data = e.data;
					if (typeof data === 'string' && data.indexOf('` + Canary + `') !== -1) {
						window.xssTriggered = true;
						triggered = true;
					}
				} catch(ex) {}
			});

			// Send message to self
			var payload = '<img src=x onerror="window.xssTriggered=true">';
			window.postMessage(payload, '*');

			return triggered;
		})()
	`

	var domContent string
	var jsTriggered bool

	err := chromedp.Run(taskCtx,
		chromedp.Navigate(targetURL),
		chromedp.Sleep(2*time.Second),
		chromedp.Evaluate(jsPostMessage, nil),
		chromedp.Sleep(1*time.Second),
		chromedp.Evaluate(`window.xssTriggered || false`, &jsTriggered),
		chromedp.InnerHTML("html", &domContent),
	)

	if err != nil {
		result.Detail = "error: " + err.Error()
		return result
	}

	if jsTriggered {
		result.Triggered = true
		result.Detail = "postMessage XSS confirmed"
	} else if strings.Contains(domContent, Canary) {
		result.Triggered = true
		result.Detail = "Canary found in DOM via postMessage"
	} else {
		result.Detail = "postMessage not triggered"
	}

	return result
}

// PrintResults prints verification results
func PrintResults(results []VerifyResult) {
	confirmed := 0
	for _, r := range results {
		if r.Triggered {
			confirmed++
			fmt.Printf("  [\033[31mCONFIRMED\033[0m] Source: %s | Payload: %s\n", r.Source, r.Payload)
			fmt.Printf("             %s\n", r.Detail)
		}
	}
	if confirmed == 0 {
		fmt.Println("  [✓] No DOM XSS confirmed by dynamic analysis")
	} else {
		fmt.Printf("\n  [!] %d payload(s) confirmed exploitable\n", confirmed)
	}
}
