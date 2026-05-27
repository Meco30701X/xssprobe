package verifier

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/chromedp/cdproto/page"
)

// VerifyResult represents the result of a dynamic verification
type VerifyResult struct {
	Payload    string
	Source     string
	Triggered  bool
	Detail     string
}

// Canary is a unique string used to detect if payload reaches the DOM
const Canary = "xXssCanary42x"

// Payloads to test different source types
var Payloads = []string{
	// Basic canary injection
	Canary,
	// HTML injection
	`<img src=x onerror="window.xssTriggered=true">`,
	// Script injection
	`"><script>window.xssTriggered=true</script>`,
	// Event handler
	`"><svg/onload=window.xssTriggered=true>`,
}

// VerifyURL tests a URL for DOM XSS by injecting payloads into various sources
func VerifyURL(targetURL string) []VerifyResult {
	var results []VerifyResult

	for _, payload := range Payloads {
		// Test location.hash
		r := testWithChromedp(targetURL, "hash", payload)
		results = append(results, r)

		// Test location.search (common param names)
		for _, param := range []string{"q", "search", "id", "page", "input", "name", "s"} {
			r = testSearchParam(targetURL, param, payload)
			results = append(results, r)
		}
	}

	return results
}

// testWithChromedp navigates to a URL with a payload in the hash and checks for XSS trigger
func testWithChromedp(baseURL, source, payload string) VerifyResult {
	result := VerifyResult{
		Payload: payload,
		Source:  source,
	}

	var testURL string
	switch source {
	case "hash":
		testURL = baseURL + "#" + url.QueryEscape(payload)
	default:
		testURL = baseURL
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-web-security", true),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	taskCtx, taskCancel := chromedp.NewContext(allocCtx)
	defer taskCancel()

	// Listen for alert dialogs
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

// testSearchParam tests a specific query parameter for XSS
func testSearchParam(baseURL, param, payload string) VerifyResult {
	result := VerifyResult{
		Payload: payload,
		Source:  "search:" + param,
	}

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

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-web-security", true),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	taskCtx, taskCancel := chromedp.NewContext(allocCtx)
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

// VerifyStoredXSS tests for stored DOM XSS by filling forms with payloads
func VerifyStoredXSS(targetURL string) []VerifyResult {
	var results []VerifyResult

	canaryPayload := `<img src=x onerror="window.xssTriggered=true">` + Canary

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("disable-web-security", true),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	taskCtx, taskCancel := chromedp.NewContext(allocCtx)
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
			Source:    "stored",
			Payload:   "",
			Triggered: false,
			Detail:    "failed to load page: " + err.Error(),
		})
		return results
	}

	// Parse inputs from JSON
	inputs := parseInputSelectors(inputJSON)

	if len(inputs) == 0 {
		results = append(results, VerifyResult{
			Source:    "stored",
			Payload:   "",
			Triggered: false,
			Detail:    "no input fields found on page",
		})
		return results
	}

	// Step 2: For each input field, try filling and submitting
	for _, input := range inputs {
		r := testStoredInput(taskCtx, targetURL, input, canaryPayload)
		results = append(results, r)
	}

	// Step 3: Reload page and check if any payload persisted in DOM
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
				Source:    "stored",
				Payload:   canaryPayload,
				Triggered: true,
				Detail:    "JavaScript executed after page reload (stored XSS confirmed)",
			})
		} else if strings.Contains(afterHTML, Canary) {
			results = append(results, VerifyResult{
				Source:    "stored",
				Payload:   canaryPayload,
				Triggered: true,
				Detail:    "Payload persisted in DOM after reload (stored HTML injection)",
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

	// Simple parser for the JSON array
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
	// Skip whitespace
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
	if input.Tag == "textarea" {
		fillJS = fmt.Sprintf(`
			var el = document.querySelector(%q);
			if (el) { el.value = %q; el.dispatchEvent(new Event('input', {bubbles:true})); }
		`, input.Selector, payload)
	} else if input.Tag == "div" || input.Tag == "span" {
		// contenteditable
		fillJS = fmt.Sprintf(`
			var el = document.querySelector(%q);
			if (el) { el.innerHTML = %q; el.dispatchEvent(new Event('input', {bubbles:true})); }
		`, input.Selector, payload)
	} else {
		fillJS = fmt.Sprintf(`
			var el = document.querySelector(%q);
			if (el) { el.value = %q; el.dispatchEvent(new Event('input', {bubbles:true})); }
		`, input.Selector, payload)
	}

	// Fill the input and try to submit
	submitJS := fillJS + `
		var form = document.querySelector(` + fmt.Sprintf("%q", input.Selector) + `).closest('form');
		if (form) {
			var submitBtn = form.querySelector('button[type="submit"], input[type="submit"], button');
			if (submitBtn) submitBtn.click();
			else form.submit();
		}
	`

	var domContent string
	var jsTriggered bool

	err := chromedp.Run(ctx,
		chromedp.Evaluate(fillJS, nil),
		chromedp.Sleep(500*time.Millisecond),
		chromedp.Evaluate(submitJS, nil),
		chromedp.Sleep(3*time.Second),
		chromedp.Evaluate(`window.xssTriggered || false`, &jsTriggered),
		chromedp.InnerHTML("html", &domContent),
	)

	if err != nil {
		result.Detail = "error filling input: " + err.Error()
		return result
	}

	if jsTriggered {
		result.Triggered = true
		result.Detail = "JavaScript executed after form submission via " + input.Selector
	} else if strings.Contains(domContent, Canary) {
		result.Triggered = true
		result.Detail = "Payload reflected in DOM after submission via " + input.Selector
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
