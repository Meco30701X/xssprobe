package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Meco30701X/domxss/crawler"
	"github.com/Meco30701X/domxss/fetcher"
	"github.com/Meco30701X/domxss/report"
	"github.com/Meco30701X/domxss/scanner"
	"github.com/Meco30701X/domxss/verifier"
)

// headerFlags allows multiple -header flags
type headerFlags map[string]string

func (h headerFlags) String() string {
	return fmt.Sprintf("%v", map[string]string(h))
}

func (h headerFlags) Set(value string) error {
	parts := strings.SplitN(value, ":", 2)
	if len(parts) == 2 {
		h[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
	}
	return nil
}

func main() {
	url := flag.String("u", "", "Target URL to scan")
	file := flag.String("f", "", "Local JS file to scan")
	output := flag.String("o", "", "Output results to JSON file")
	verify := flag.Bool("verify", false, "Dynamic verification (reflected DOM XSS)")
	stored := flag.Bool("stored", false, "Test for stored DOM XSS (auto-detect forms, fill & submit)")
	cookie := flag.String("cookie", "", "Cookie string (e.g. \"session=abc; token=xyz\")")
	headers := make(headerFlags)
	flag.Var(&headers, "H", "Custom header (e.g. \"Authorization: Bearer xxx\"). Can be used multiple times.")
	flag.Parse()

	if *url == "" && *file == "" {
		fmt.Println("DOMXSS - DOM XSS Detection Tool")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  domxss -u https://example.com                          # Static analysis")
		fmt.Println("  domxss -u URL -verify                                   # Reflected DOM XSS")
		fmt.Println("  domxss -u URL -stored                                   # Stored DOM XSS")
		fmt.Println("  domxss -u URL -stored -cookie \"session=abc\" -H \"Authorization: Bearer xxx\"")
		fmt.Println("  domxss -f script.js                                     # Scan local file")
		fmt.Println("  domxss -u URL -o result.json                            # Export JSON")
		fmt.Println()
		fmt.Println("Flags:")
		fmt.Println("  -u          Target URL")
		fmt.Println("  -f          Local JS file")
		fmt.Println("  -o          Output JSON file")
		fmt.Println("  -verify     Reflected DOM XSS (headless browser)")
		fmt.Println("  -stored     Stored DOM XSS (form detection + auto-fill)")
		fmt.Println("  -cookie     Cookie string for authenticated testing")
		fmt.Println("  -H          Custom header (repeatable, e.g. -H \"K: V\")")
		os.Exit(1)
	}

	// Build auth config
	var auth *verifier.AuthConfig
	if *cookie != "" || len(headers) > 0 {
		auth = &verifier.AuthConfig{
			Headers: headers,
		}
		// Parse cookie string: "key1=val1; key2=val2" → ["key1=val1", "key2=val2"]
		if *cookie != "" {
			for _, c := range strings.Split(*cookie, ";") {
				c = strings.TrimSpace(c)
				if c != "" {
					auth.Cookies = append(auth.Cookies, c)
				}
			}
		}
		fmt.Printf("[*] Auth configured: %d cookie(s), %d header(s)\n", len(auth.Cookies), len(auth.Headers))
	}

	var allFindings []scanner.Finding
	var allVerifyResults []verifier.VerifyResult
	var targetName string

	if *file != "" {
		content, err := os.ReadFile(*file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading file: %v\n", err)
			os.Exit(1)
		}
		targetName = *file
		findings := scanner.ScanJS(string(content))
		allFindings = append(allFindings, findings...)
	}

	if *url != "" {
		targetName = *url
		if !strings.HasPrefix(*url, "http") {
			*url = "https://" + *url
		}

		fmt.Printf("[*] Fetching %s ...\n", *url)
		html, err := fetcher.FetchPage(*url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		scripts := fetcher.ExtractInlineScripts(html)
		fmt.Printf("[*] Found %d inline scripts\n", len(scripts))
		for _, s := range scripts {
			findings := scanner.ScanJS(s)
			allFindings = append(allFindings, findings...)
		}

		scriptURLs := fetcher.ExtractScriptURLs(html, *url)
		fmt.Printf("[*] Found %d external scripts\n", len(scriptURLs))
		for _, sURL := range scriptURLs {
			fmt.Printf("  → Fetching %s\n", sURL)
			js, err := fetcher.FetchScript(sURL)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠ %v\n", err)
				continue
			}
			findings := scanner.ScanJS(js)
			allFindings = append(allFindings, findings...)
		}
	}

	// Static analysis results
	report.PrintFindings(allFindings, targetName)

	// Reflected DOM XSS verification
	if *verify && *url != "" {
		fmt.Println("\n[*] Running reflected DOM XSS verification...")
		results := verifier.VerifyURL(*url, auth)
		allVerifyResults = append(allVerifyResults, results...)
		verifier.PrintResults(results)
	}

	// Stored DOM XSS testing
	if *stored && *url != "" {
		fmt.Println("\n[*] Running stored DOM XSS detection...")

		crawlAuth := &crawler.AuthConfig{}
		if auth != nil {
			crawlAuth.Cookies = auth.Cookies
			crawlAuth.Headers = auth.Headers
		}

		crawlResult, err := crawler.DetectInputs(*url, crawlAuth)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠ Crawl error: %v\n", err)
		} else {
			crawler.PrintInputs(crawlResult)

			if len(crawlResult.Inputs) > 0 {
				fmt.Println("\n[*] Testing stored XSS via form submission...")
				results := verifier.VerifyStoredXSS(*url, auth)
				allVerifyResults = append(allVerifyResults, results...)
				verifier.PrintResults(results)
			}
		}
	}

	// Save results
	if *output != "" {
		if len(allVerifyResults) > 0 {
			report.OutputVerifiedJSON(allFindings, allVerifyResults, *output)
		} else {
			report.OutputJSON(allFindings, *output)
		}
		fmt.Printf("\n[*] Results saved to %s\n", *output)
	}

	if len(allFindings) > 0 {
		os.Exit(2)
	}
}
