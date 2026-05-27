package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Meco30701X/domxss/crawler"
	"github.com/Meco30701X/domxss/fetcher"
	"github.com/Meco30701X/domxss/payloads"
	"github.com/Meco30701X/domxss/report"
	"github.com/Meco30701X/domxss/scanner"
	"github.com/Meco30701X/domxss/verifier"
)

type headerFlags map[string]string

func (h headerFlags) String() string { return fmt.Sprintf("%v", map[string]string(h)) }
func (h headerFlags) Set(value string) error {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) == 2 {
		h[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return nil
}

func main() {
	url := flag.String("u", "", "Target URL to scan")
	urlList := flag.String("l", "", "File containing URLs to scan (one per line)")
	file := flag.String("f", "", "Local JS file to scan")
	output := flag.String("o", "", "Output results to JSON file")
	verify := flag.Bool("verify", false, "Dynamic verification (reflected DOM XSS)")
	stored := flag.Bool("stored", false, "Test for stored DOM XSS")
	spa := flag.Bool("spa", false, "SPA mode: render page with headless browser")
	cookie := flag.String("cookie", "", "Cookie string (e.g. \"session=abc; token=xyz\")")
	waf := flag.String("waf", "", "Target WAF: cloudflare, aws, modsec, generic")
	threads := flag.Int("threads", 5, "Number of concurrent threads for batch scanning")
	waitTime := flag.Int("wait", 5, "Wait time in seconds for SPA rendering")
	headers := make(headerFlags)
	flag.Var(&headers, "H", "Custom header (repeatable, e.g. -H \"K: V\")")
	flag.Parse()

	if *url == "" && *urlList == "" && *file == "" {
		printUsage()
		os.Exit(1)
	}

	// Build auth config
	var auth *verifier.AuthConfig
	if *cookie != "" || len(headers) > 0 {
		auth = &verifier.AuthConfig{Headers: headers}
		if *cookie != "" {
			for _, c := range strings.Split(*cookie, ";") {
				c = strings.TrimSpace(c)
				if c != "" {
					auth.Cookies = append(auth.Cookies, c)
				}
			}
		}
		fmt.Printf("[*] Auth: %d cookie(s), %d header(s)\n", len(auth.Cookies), len(auth.Headers))
	}

	// Collect URLs to scan
	var urls []string
	if *url != "" {
		u := *url
		if !strings.HasPrefix(u, "http") {
			u = "https://" + u
		}
		urls = append(urls, u)
	}
	if *urlList != "" {
		listURLs, err := readURLFile(*urlList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading URL list: %v\n", err)
			os.Exit(1)
		}
		urls = append(urls, listURLs...)
	}

	// Scan local file (no batch needed)
	if *file != "" {
		scanLocalFile(*file, *output)
		return
	}

	// Payload info
	if *waf != "" {
		wafPayloads := payloads.GetPayloadsByWAF(*waf)
		fmt.Printf("[*] WAF mode: %s (%d bypass payloads loaded)\n", *waf, len(wafPayloads))
	}

	// Single URL or batch
	if len(urls) == 1 {
		scanURL(urls[0], auth, *waf, *verify, *stored, *spa, *waitTime, *output)
	} else if len(urls) > 1 {
		scanBatch(urls, auth, *waf, *verify, *stored, *spa, *waitTime, *output, *threads)
	}
}

func printUsage() {
	fmt.Println("DOMXSS - DOM XSS Detection Tool")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  domxss -u https://example.com                          # Static analysis")
	fmt.Println("  domxss -u URL -verify                                   # Reflected DOM XSS")
	fmt.Println("  domxss -u URL -stored                                   # Stored DOM XSS")
	fmt.Println("  domxss -u URL -spa                                      # SPA rendering mode")
	fmt.Println("  domxss -u URL -verify -waf cloudflare                   # WAF bypass mode")
	fmt.Println("  domxss -l urls.txt -threads 10                          # Batch scan")
	fmt.Println("  domxss -u URL -cookie \"session=abc\" -H \"Authorization: Bearer xxx\"")
	fmt.Println("  domxss -f script.js                                     # Scan local file")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -u          Target URL")
	fmt.Println("  -l          URL list file (one URL per line)")
	fmt.Println("  -f          Local JS file")
	fmt.Println("  -o          Output JSON file")
	fmt.Println("  -verify     Reflected DOM XSS verification")
	fmt.Println("  -stored     Stored DOM XSS detection")
	fmt.Println("  -spa        SPA mode: render page with headless browser")
	fmt.Println("  -waf        WAF type: cloudflare, aws, modsec, generic")
	fmt.Println("  -threads    Concurrent threads for batch (default: 5)")
	fmt.Println("  -wait       Wait time for SPA rendering in seconds (default: 5)")
	fmt.Println("  -cookie     Cookie string for auth")
	fmt.Println("  -H          Custom header (repeatable)")
	fmt.Println()
	fmt.Printf("Payload library: %d payloads available\n", payloads.Count())
}

func readURLFile(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var urls []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "http") {
			line = "https://" + line
		}
		urls = append(urls, line)
	}
	return urls, scanner.Err()
}

func scanLocalFile(filename, output string) {
	content, err := os.ReadFile(filename)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
		os.Exit(1)
	}
	findings := scanner.ScanJS(string(content))
	report.PrintFindings(findings, filename)
	if output != "" {
		report.OutputJSON(findings, output)
		fmt.Printf("\n[*] Results saved to %s\n", output)
	}
	if len(findings) > 0 {
		os.Exit(2)
	}
}

func scanURL(targetURL string, auth *verifier.AuthConfig, waf string, doVerify, doStored, doSPA bool, waitTime int, output string) {
	var allFindings []scanner.Finding
	var allVerifyResults []verifier.VerifyResult

	if doSPA {
		// SPA mode: render with headless browser
		fmt.Printf("[*] SPA mode: rendering %s with headless browser...\n", targetURL)

		spaConfig := &fetcher.SPAConfig{
			WaitTime:   time.Duration(waitTime) * time.Second,
			ScrollPage: true,
		}
		if auth != nil {
			spaConfig.AuthCookies = auth.Cookies
			spaConfig.Headers = auth.Headers
		}

		spaResult, err := fetcher.FetchPageSPA(targetURL, spaConfig)
		if err != nil {
			fmt.Fprintf(os.Stderr, "SPA render error: %v\n", err)
			return
		}

		fmt.Printf("[*] Rendered URL: %s\n", spaResult.RenderedURL)
		fmt.Printf("[*] Found %d inline scripts (rendered DOM)\n", len(spaResult.InlineScripts))
		fmt.Printf("[*] Found %d external scripts (rendered DOM)\n", len(spaResult.ExternalScripts))
		if len(spaResult.DynamicScripts) > 0 {
			fmt.Printf("[*] Found %d dynamically loaded scripts\n", len(spaResult.DynamicScripts))
		}

		// Scan inline scripts from rendered DOM
		for _, s := range spaResult.InlineScripts {
			allFindings = append(allFindings, scanner.ScanJS(s)...)
		}

		// Scan external scripts
		for _, sURL := range spaResult.ExternalScripts {
			js, err := fetcher.FetchScript(sURL)
			if err != nil {
				continue
			}
			allFindings = append(allFindings, scanner.ScanJS(js)...)
		}

		// Scan dynamically loaded scripts
		for _, sURL := range spaResult.DynamicScripts {
			js, err := fetcher.FetchScript(sURL)
			if err != nil {
				continue
			}
			allFindings = append(allFindings, scanner.ScanJS(js)...)
		}

		// Detect SPA routes
		routes := fetcher.ExtractSPARoutes(spaResult.InlineScripts)
		if len(routes) > 0 {
			fmt.Printf("[*] Detected %d SPA routes: %v\n", len(routes), routes)
		}

		// Check if SPA detected
		if fetcher.IsSPA(spaResult.RenderedHTML) {
			fmt.Println("[*] SPA framework detected")
		}
	} else {
		// Standard mode: HTTP fetch
		fmt.Printf("[*] Fetching %s ...\n", targetURL)
		html, err := fetcher.FetchPage(targetURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}

		// Auto-detect SPA and suggest -spa flag
		if fetcher.IsSPA(html) {
			fmt.Println("[!] SPA detected! Consider using -spa flag for better coverage")
		}

		scripts := fetcher.ExtractInlineScripts(html)
		fmt.Printf("[*] Found %d inline scripts\n", len(scripts))
		for _, s := range scripts {
			allFindings = append(allFindings, scanner.ScanJS(s)...)
		}

		scriptURLs := fetcher.ExtractScriptURLs(html, targetURL)
		fmt.Printf("[*] Found %d external scripts\n", len(scriptURLs))
		for _, sURL := range scriptURLs {
			js, err := fetcher.FetchScript(sURL)
			if err != nil {
				continue
			}
			allFindings = append(allFindings, scanner.ScanJS(js)...)
		}
	}

	report.PrintFindings(allFindings, targetURL)

	// Reflected DOM XSS
	if doVerify {
		fmt.Println("\n[*] Reflected DOM XSS verification...")
		results := verifier.VerifyURL(targetURL, auth, waf)
		allVerifyResults = append(allVerifyResults, results...)
		verifier.PrintResults(results)
	}

	// Stored DOM XSS
	if doStored {
		fmt.Println("\n[*] Stored DOM XSS detection...")
		crawlAuth := &crawler.AuthConfig{}
		if auth != nil {
			crawlAuth.Cookies = auth.Cookies
			crawlAuth.Headers = auth.Headers
		}
		crawlResult, err := crawler.DetectInputs(targetURL, crawlAuth)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠ %v\n", err)
		} else {
			crawler.PrintInputs(crawlResult)
			if len(crawlResult.Inputs) > 0 {
				fmt.Println("\n[*] Testing stored XSS...")
				results := verifier.VerifyStoredXSS(targetURL, auth, waf)
				allVerifyResults = append(allVerifyResults, results...)
				verifier.PrintResults(results)
			}
		}
	}

	// Save results
	if output != "" {
		if len(allVerifyResults) > 0 {
			report.OutputVerifiedJSON(allFindings, allVerifyResults, output)
		} else {
			report.OutputJSON(allFindings, output)
		}
		fmt.Printf("\n[*] Results saved to %s\n", output)
	}
}

func scanBatch(urls []string, auth *verifier.AuthConfig, waf string, doVerify, doStored, doSPA bool, waitTime int, output string, concurrency int) {
	fmt.Printf("[*] Batch scanning %d URLs with %d threads\n", len(urls), concurrency)

	var mu sync.Mutex
	var allFindings []scanner.Finding
	var allVerifyResults []verifier.VerifyResult
	scanned := 0

	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, targetURL := range urls {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fmt.Printf("\n[*] [%d/%d] Scanning %s\n", scanned+1, len(urls), u)

			var findings []scanner.Finding
			var verifyResults []verifier.VerifyResult

			if doSPA {
				// SPA mode
				spaConfig := &fetcher.SPAConfig{
					WaitTime:   time.Duration(waitTime) * time.Second,
					ScrollPage: true,
				}
				if auth != nil {
					spaConfig.AuthCookies = auth.Cookies
					spaConfig.Headers = auth.Headers
				}

				spaResult, err := fetcher.FetchPageSPA(u, spaConfig)
				if err != nil {
					fmt.Printf("  ⚠ SPA render error: %v\n", err)
					return
				}

				for _, s := range spaResult.InlineScripts {
					findings = append(findings, scanner.ScanJS(s)...)
				}
				for _, sURL := range spaResult.ExternalScripts {
					js, err := fetcher.FetchScript(sURL)
					if err != nil {
						continue
					}
					findings = append(findings, scanner.ScanJS(js)...)
				}
				for _, sURL := range spaResult.DynamicScripts {
					js, err := fetcher.FetchScript(sURL)
					if err != nil {
						continue
					}
					findings = append(findings, scanner.ScanJS(js)...)
				}
			} else {
				// Standard mode
				html, err := fetcher.FetchPage(u)
				if err != nil {
					fmt.Printf("  ⚠ %v\n", err)
					return
				}

				for _, s := range fetcher.ExtractInlineScripts(html) {
					findings = append(findings, scanner.ScanJS(s)...)
				}
				for _, sURL := range fetcher.ExtractScriptURLs(html, u) {
					js, err := fetcher.FetchScript(sURL)
					if err != nil {
						continue
					}
					findings = append(findings, scanner.ScanJS(js)...)
				}
			}

			if len(findings) > 0 {
				fmt.Printf("  [!] %d static findings\n", len(findings))
			}

			// Dynamic verification
			if doVerify {
				results := verifier.VerifyURL(u, auth, waf)
				verifyResults = append(verifyResults, results...)
				for _, r := range results {
					if r.Triggered {
						fmt.Printf("  [!] Confirmed: %s (%s)\n", r.Source, r.Detail)
					}
				}
			}

			// Stored XSS
			if doStored {
				crawlAuth := &crawler.AuthConfig{}
				if auth != nil {
					crawlAuth.Cookies = auth.Cookies
					crawlAuth.Headers = auth.Headers
				}
				crawlResult, err := crawler.DetectInputs(u, crawlAuth)
				if err == nil && len(crawlResult.Inputs) > 0 {
					results := verifier.VerifyStoredXSS(u, auth, waf)
					verifyResults = append(verifyResults, results...)
					for _, r := range results {
						if r.Triggered {
							fmt.Printf("  [!] Stored XSS: %s\n", r.Detail)
						}
					}
				}
			}

			mu.Lock()
			allFindings = append(allFindings, findings...)
			allVerifyResults = append(allVerifyResults, verifyResults...)
			scanned++
			mu.Unlock()
		}(targetURL)
	}

	wg.Wait()

	// Summary
	fmt.Printf("\n═══════════════════════════════════\n")
	fmt.Printf("Batch scan complete: %d URLs scanned\n", len(urls))
	fmt.Printf("Static findings: %d\n", len(allFindings))
	confirmed := 0
	for _, r := range allVerifyResults {
		if r.Triggered {
			confirmed++
		}
	}
	fmt.Printf("Confirmed XSS: %d\n", confirmed)

	// Save results
	if output != "" {
		if len(allVerifyResults) > 0 {
			report.OutputVerifiedJSON(allFindings, allVerifyResults, output)
		} else {
			report.OutputJSON(allFindings, output)
		}
		fmt.Printf("Results saved to %s\n", output)
	}
}
