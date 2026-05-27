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
