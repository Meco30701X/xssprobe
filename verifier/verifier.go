package verifier

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Meco30701X/domxss/payloads"
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

// getTestPayloads returns the payload strings to test, optionally filtered by WAF
func getTestPayloads(waf string) []string {
	var result []string

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

	return result
}

// newChromeContext creates a chromedp context with optional auth config
func newChromeContext(ctx context.Context, auth *AuthConfig) (context.Context, context.CancelFunc) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-web-security", true),
	)

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
			chromedp.Run(taskCtx, actions...)
		}
	}

	combinedCancel := func() {
		taskCancel()
		allocCancel()
	}

	return taskCtx, combinedCancel
}

func extractDomain(ctx context.Context) string {
	return ""
}

// VerifyURL tests a URL for reflected DOM XSS
func VerifyURL(targetURL string, auth *AuthConfig, waf string) []VerifyResult {
	var results []VerifyResult
	testPayloads := getTestPayloads(waf)

	for _, payload := range testPayloads {
		r := testHash(targetURL, payload, auth)
		results = append(results, r)

		for _, param := range []string{"q", "search", "id", "page", "input", "name", "s"} {
			r = testSearchParam(targetURL, param, payload, auth)
			results = append(results, r)
		}
	}

	return results
}

func testHash(baseURL, payload string, auth *AuthConfig) VerifyResult {
	result := VerifyResult{Payload: payload, Source: "hash"}
	testURL := baseURL + "#" + url.QueryEscape(payload)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	taskCtx, taskCancel := newChromeContext(ctx, auth)
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
		result.Detail = "navigation error: " + err.Error()
		return result
	}

	if jsTriggered {
		result.Triggered = true
		result.Detail = "JavaScript execution confirmed (window.xssTriggered=true)"
	} else if strings.Contains(domContent, Canary) {
		result.Triggered = true
		result.Detail = "Canary string found in DOM (HTML injection confirmed)"
	}

	return result
}

func testSearchParam(baseURL, param, payload string, auth *AuthConfig) VerifyResult {
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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	taskCtx, taskCancel := newChromeContext(ctx, auth)
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
		result.Detail = "navigation error: " + err.Error()
		return result
	}

	if jsTriggered {
		result.Triggered = true
		result.Detail = "JavaScript execution confirmed"
	} else if strings.Contains(domContent, Canary) {
		result.Triggered = true
		result.Detail = "Canary string found in DOM"
	}

	return result
}

// VerifyStoredXSS tests for stored DOM XSS with optional auth
func VerifyStoredXSS(targetURL string, auth *AuthConfig, waf string) []VerifyResult {
	var results []VerifyResult

	// Get canary payloads for stored XSS testing
	canaryPayloads := payloads.GetCanaryPayloads(Canary)
	var testPayloads []string
	for _, p := range canaryPayloads {
		testPayloads = append(testPayloads, p.Value)
	}

	// Add WAF bypass payloads if specified
	if waf != "" {
		for _, p := range payloads.GetPayloadsByWAF(waf) {
			testPayloads = append(testPayloads, p.Value)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	taskCtx, taskCancel := newChromeContext(ctx, auth)
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
		return results
	}

	inputs := parseInputSelectors(inputJSON)

	if len(inputs) == 0 {
		results = append(results, VerifyResult{
			Source: "stored", Detail: "no input fields found on page",
		})
		return results
	}

	// Step 2: Fill and submit each input with each payload
	for _, input := range inputs {
		for _, payload := range testPayloads {
			r := testStoredInput(taskCtx, targetURL, input, payload)
			results = append(results, r)
		}
	}

	// Step 3: Reload and check persistence
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

	return results
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
