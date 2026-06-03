package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Meco30701X/domxss/analyzer"
	"github.com/Meco30701X/domxss/compliance"
	"github.com/Meco30701X/domxss/fetcher"
	"github.com/Meco30701X/domxss/miner"
	"github.com/Meco30701X/domxss/payloads"
	"github.com/Meco30701X/domxss/report"
	"github.com/Meco30701X/domxss/safety"
	"github.com/Meco30701X/domxss/scanner"
	"github.com/Meco30701X/domxss/spider"
	"github.com/Meco30701X/domxss/verifier"
	wafpkg "github.com/Meco30701X/domxss/waf"
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
	crawl := flag.Bool("crawl", false, "Auto-crawl site and scan all discovered pages")
	maxPages := flag.Int("max-pages", 50, "Max pages to crawl (with -crawl)")
	maxDepth := flag.Int("max-depth", 3, "Max crawl depth (with -crawl)")
	cookie := flag.String("cookie", "", "Cookie string (e.g. \"session=abc; token=xyz\")")
	waf := flag.String("waf", "", "Target WAF: cloudflare, aws, modsec, generic")
	autoWAF := flag.Bool("auto-waf", true, "Auto-detect WAF (default: true)")
	threads := flag.Int("threads", 5, "Number of concurrent threads for batch scanning")
	waitTime := flag.Int("wait", 5, "Wait time in seconds for SPA rendering")
	dryRun := flag.Bool("dry-run", false, "Dry-run: detect inputs but don't submit (safest)")
	safePayloads := flag.Bool("safe", false, "Use only harmless canary payloads")
	confirm := flag.Bool("confirm", false, "Ask for confirmation before each submission")
	// Combined analysis flag
	analyze := flag.Bool("analyze", false, "Combined static+dynamic analysis (lower false positives)")
	maxVerify := flag.Int("max-verify", 10, "Max findings to verify dynamically (with -analyze)")
	skipFiltered := flag.Bool("skip-filtered", false, "Skip findings with detected filtering (with -analyze)")
	// Parameter mining flags
	paramFlag := flag.String("param", "", "Comma-separated parameter names to test (e.g. \"id,name,email\")")
	mineParams := flag.Bool("mine", true, "Auto-discover parameters from HTML/JS (default: true)")
	useWordlist := flag.Bool("wordlist", false, "Add common parameter wordlist to discovered params")
	// Compliance flags
	scope := flag.String("scope", "", "Restrict scanning to this domain (e.g. target.com)")
	rateLimit := flag.Int("rate", 2, "Max requests per second (rate limiting)")
	auditLog := flag.String("audit", "", "Audit log file path (JSON lines)")
	respectRobots := flag.Bool("respect-robots", true, "Respect robots.txt rules")
	skipLegal := flag.Bool("yes", false, "Skip legal confirmation (for CI/CD automation)")
	headers := make(headerFlags)
	flag.Var(&headers, "H", "Custom header (repeatable, e.g. -H \"K: V\")")
	flag.Parse()

	// Legal confirmation
	if !compliance.ConfirmLegalUsage(*skipLegal) {
		os.Exit(0)
	}

	// Stdin pipe support (BETA) - read before checking args
	var urls []string
	if *url == "" && *urlList == "" && *file == "" {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			// stdin has data (pipe or redirect)
			fmt.Println("[!] Stdin pipe mode (BETA - experimental feature)")
			pipeScanner := bufio.NewScanner(os.Stdin)
			for pipeScanner.Scan() {
				line := strings.TrimSpace(pipeScanner.Text())
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if !strings.HasPrefix(line, "http") {
					line = "https://" + line
				}
				urls = append(urls, line)
			}
			if len(urls) > 0 {
				fmt.Printf("[*] Read %d URLs from stdin\n", len(urls))
			}
		}
	}

	if *url == "" && *urlList == "" && *file == "" && len(urls) == 0 {
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

	// Collect URLs to scan (from -u and -l flags)
	if *url != "" {
		u := *url
		if !strings.HasPrefix(u, "http") {
			u = "https://" + u
		}
		urls = append(urls, u)
		// Auto-detect scope from target URL if not specified
		if *scope == "" {
			*scope = compliance.ExtractDomain(u)
			if *scope != "" {
				fmt.Printf("[*] Auto-detected scope: %s\n", *scope)
			}
		}
	}
	if *urlList != "" {
		listURLs, err := readURLFile(*urlList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading URL list: %v\n", err)
			os.Exit(1)
		}
		urls = append(urls, listURLs...)
	}

	// Initialize compliance context
	complianceCfg := compliance.ComplianceConfig{
		Scope:         *scope,
		RateLimit:     *rateLimit,
		AuditLogPath:  *auditLog,
		RespectRobots: *respectRobots,
	}
	complianceCtx, err := compliance.NewCompliance(complianceCfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Compliance init error: %v\n", err)
		os.Exit(1)
	}
	defer complianceCtx.Close()

	fmt.Printf("[*] Compliance: scope=%s, rate=%d/s, robots=%v\n",
		*scope, *rateLimit, *respectRobots)
	if *auditLog != "" {
		fmt.Printf("[*] Audit log: %s\n", *auditLog)
	}

	// Auto-crawl mode
	if *crawl && len(urls) > 0 {
		fmt.Printf("[*] Auto-crawling from %s (max-pages=%d, max-depth=%d)\n", urls[0], *maxPages, *maxDepth)

		crawlConfig := spider.DefaultConfig()
		crawlConfig.MaxPages = *maxPages
		crawlConfig.MaxDepth = *maxDepth
		crawlConfig.Compliance = complianceCtx
		if auth != nil {
			crawlConfig.AuthCookies = auth.Cookies
			crawlConfig.Headers = auth.Headers
		}

		crawler := spider.NewCrawler(crawlConfig)
		crawlResult := crawler.Crawl(urls[0])

		spider.PrintSummary(crawlResult)

		// Replace URLs with crawled pages
		urls = spider.ExtractURLs(crawlResult)

		if len(urls) == 0 {
			fmt.Println("[!] No pages discovered during crawl")
			return
		}

		fmt.Printf("[*] Will scan %d discovered pages\n", len(urls))
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

	// Build safety mode
	safetyMode := &safety.SafetyMode{
		DryRun:  *dryRun,
		Safe:    *safePayloads,
		Confirm: *confirm,
	}

	// If stored mode without any safety flag, default to safe+confirm
	if *stored && !*dryRun && !*safePayloads && !*confirm {
		safetyMode.Safe = true
		safetyMode.Confirm = true
		fmt.Println("[*] Stored XSS: using safe payloads with confirmation (use -dry-run for safest mode)")
	}

	// Parse manual parameters
	var manualParams []string
	if *paramFlag != "" {
		for _, p := range strings.Split(*paramFlag, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				manualParams = append(manualParams, p)
			}
		}
	}

	// Single URL or batch
	if len(urls) == 1 {
		if *analyze {
			scanURLCombined(urls[0], auth, *waf, *spa, *waitTime, *output, *maxVerify, *skipFiltered, complianceCtx)
		} else {
			scanURL(urls[0], auth, *waf, *verify, *stored, *spa, *waitTime, *output, safetyMode, complianceCtx,
				*mineParams, *useWordlist, manualParams, *autoWAF)
		}
	} else if len(urls) > 1 {
		scanBatch(urls, auth, *waf, *verify, *stored, *spa, *waitTime, *output, *threads, safetyMode, complianceCtx,
			*mineParams, *useWordlist, manualParams, *autoWAF)
	}
}

func printUsage() {
	fmt.Println("DOMXSS - DOM XSS Detection Tool")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  domxss -u https://example.com                          # Static analysis")
	fmt.Println("  domxss -u URL -analyze                                  # Combined analysis (recommended)")
	fmt.Println("  domxss -u URL -verify                                   # Reflected DOM XSS")
	fmt.Println("  domxss -u URL -stored -dry-run                          # Stored XSS (safe, no submit)")
	fmt.Println("  domxss -u URL -stored -safe -confirm                    # Stored XSS (safe payloads)")
	fmt.Println("  domxss -u URL -stored                                   # Stored XSS (full test)")
	fmt.Println("  domxss -u URL -spa                                      # SPA rendering mode")
	fmt.Println("  domxss -u URL -crawl                                    # Auto-crawl and scan all pages")
	fmt.Println("  domxss -u URL -crawl -max-pages 100 -max-depth 5       # Deep crawl")
	fmt.Println("  domxss -u URL -verify -waf cloudflare                   # WAF bypass mode")
	fmt.Println("  domxss -l urls.txt -threads 10                          # Batch scan")
	fmt.Println("  domxss -u URL -cookie \"session=abc\" -H \"Authorization: Bearer xxx\"")
	fmt.Println("  domxss -f script.js                                     # Scan local file")
	fmt.Println("  cat urls.txt | domxss -verify                           # Stdin pipe (BETA)")
	fmt.Println()
	fmt.Println("Flags:")
	fmt.Println("  -u          Target URL")
	fmt.Println("  -l          URL list file (one URL per line)")
	fmt.Println("  -f          Local JS file")
	fmt.Println("  -o          Output JSON file")
	fmt.Println("  -verify     Reflected DOM XSS verification")
	fmt.Println("  -stored     Stored DOM XSS detection")
	fmt.Println("  -spa        SPA mode: render page with headless browser")
	fmt.Println("  -crawl      Auto-crawl site and scan all discovered pages")
	fmt.Println("  -max-pages  Max pages to crawl (default: 50)")
	fmt.Println("  -max-depth  Max crawl depth (default: 3)")
	fmt.Println("  -waf        WAF type: cloudflare, aws, modsec, generic")
	fmt.Println("  -auto-waf   Auto-detect WAF (default: true)")
	fmt.Println("  -threads    Concurrent threads for batch (default: 5)")
	fmt.Println("  -wait       Wait time for SPA rendering in seconds (default: 5)")
	fmt.Println("  -cookie     Cookie string for auth")
	fmt.Println("  -H          Custom header (repeatable)")
	fmt.Println()
	fmt.Println("Safety Flags (for stored XSS):")
	fmt.Println("  -dry-run    Only detect inputs, don't submit any data (safest)")
	fmt.Println("  -safe       Use only harmless canary payloads")
	fmt.Println("  -confirm    Ask for confirmation before each submission")
	fmt.Println()
	fmt.Println("Analysis Flags:")
	fmt.Println("  -analyze       Combined static+dynamic analysis (lower false positives)")
	fmt.Println("  -max-verify    Max findings to verify dynamically (default: 10)")
	fmt.Println("  -skip-filtered Skip findings with detected filtering")
	fmt.Println()
	fmt.Println("Parameter Mining Flags:")
	fmt.Println("  -param         Comma-separated parameter names to test (e.g. \"id,name,email\")")
	fmt.Println("  -mine          Auto-discover parameters from HTML/JS (default: true)")
	fmt.Println("  -wordlist      Add common parameter wordlist to discovered params")
	fmt.Println()
	fmt.Println("Compliance Flags:")
	fmt.Println("  -scope        Restrict scanning to this domain (e.g. target.com)")
	fmt.Println("  -rate         Max requests per second (default: 2)")
	fmt.Println("  -audit        Audit log file path (JSON lines)")
	fmt.Println("  -respect-robots  Respect robots.txt rules (default: true)")
	fmt.Println("  -yes          Skip legal confirmation (for CI/CD)")
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

func scanURL(targetURL string, auth *verifier.AuthConfig, wafType string, doVerify, doStored, doSPA bool, waitTime int, output string, safetyMode *safety.SafetyMode, cc *compliance.ComplianceContext,
	doMine, useWordlist bool, manualParams []string, autoWAF bool) {
	var allFindings []scanner.Finding
	var allVerifyResults []verifier.VerifyResult
	var pageHTML string // store HTML for parameter mining

	// Compliance check for target URL
	if err := cc.CheckURL(targetURL, "scan"); err != nil {
		fmt.Printf("[!] Compliance blocked: %v\n", err)
		return
	}

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

		// Scan external scripts (with compliance check)
		for _, sURL := range spaResult.ExternalScripts {
			if err := cc.CheckURL(sURL, "script"); err != nil {
				continue
			}
			js, err := fetcher.FetchScript(sURL)
			if err != nil {
				cc.LogError(sURL, "script", err.Error())
				continue
			}
			allFindings = append(allFindings, scanner.ScanJS(js)...)
		}

		// Scan dynamically loaded scripts (with compliance check)
		for _, sURL := range spaResult.DynamicScripts {
			if err := cc.CheckURL(sURL, "script"); err != nil {
				continue
			}
			js, err := fetcher.FetchScript(sURL)
			if err != nil {
				cc.LogError(sURL, "script", err.Error())
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
		pageHTML = html // save for parameter mining

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
			if err := cc.CheckURL(sURL, "script"); err != nil {
				continue
			}
			js, err := fetcher.FetchScript(sURL)
			if err != nil {
				cc.LogError(sURL, "script", err.Error())
				continue
			}
			allFindings = append(allFindings, scanner.ScanJS(js)...)
		}
	}

	report.PrintFindings(allFindings, targetURL)

	// WAF Auto-Detection
	if autoWAF && wafType == "" && doVerify {
		fmt.Println("\n[*] WAF detection...")
		cookies := []string{}
		customHeaders := map[string]string{}
		if auth != nil {
			cookies = auth.Cookies
			customHeaders = auth.Headers
		}
		wafResult := wafpkg.DetectWAF(targetURL, cookies, customHeaders)
		wafpkg.PrintWAFResult(wafResult)
		if wafResult.Detected {
			wafType = wafpkg.GetRecommendedWAF(wafResult.Name)
			if wafType != "" {
				fmt.Printf("[*] Using WAF bypass payloads for: %s\n", wafType)
			}
		}
	}

	// Parameter Discovery
	var discoveredParams []miner.DiscoveredParam
	if doMine && pageHTML != "" {
		fmt.Println("\n[*] Parameter discovery...")
		discoveredParams = miner.MineParamsFromHTML(pageHTML)
	}

	// Merge with manual params
	if len(manualParams) > 0 {
		discoveredParams = miner.MergeParams(discoveredParams, manualParams)
	}

	// Add wordlist if requested
	if useWordlist {
		discoveredParams = miner.AddWordlistParams(discoveredParams, miner.GetDefaultWordlist())
	}

	// Print discovered parameters
	if doVerify {
		paramNames := miner.ParamNames(discoveredParams)
		if len(paramNames) > 0 {
			fmt.Printf("\n[*] Discovered %d parameters:\n", len(discoveredParams))
			miner.PrintDiscoveredParams(discoveredParams)
		}
	}

	// Reflected DOM XSS
	if doVerify {
		fmt.Println("\n[*] Reflected DOM XSS verification...")
		paramNames := miner.ParamNames(discoveredParams)
		if len(paramNames) > 0 {
			fmt.Printf("[*] Testing %d parameters...\n", len(paramNames))
			results := verifier.VerifyURLWithParams(targetURL, auth, wafType, paramNames)
			allVerifyResults = append(allVerifyResults, results...)
			verifier.PrintResults(results)
		} else {
			// Fallback to default params
			results := verifier.VerifyURL(targetURL, auth, wafType)
			allVerifyResults = append(allVerifyResults, results...)
			verifier.PrintResults(results)
		}
	}

	// Stored DOM XSS
	if doStored {
		fmt.Println("\n[*] Stored DOM XSS detection...")
		results, _ := verifier.VerifyStoredXSS(targetURL, auth, wafType, safetyMode)
		allVerifyResults = append(allVerifyResults, results...)
		verifier.PrintResults(results)
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

func scanURLCombined(targetURL string, auth *verifier.AuthConfig, waf string, doSPA bool, waitTime int, output string, maxVerify int, skipFiltered bool, cc *compliance.ComplianceContext) {
	// Compliance check
	if err := cc.CheckURL(targetURL, "analyze"); err != nil {
		fmt.Printf("[!] Compliance blocked: %v\n", err)
		return
	}

	var allFindings []scanner.Finding

	// Phase 1: Static Analysis
	if doSPA {
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

		for _, s := range spaResult.InlineScripts {
			allFindings = append(allFindings, scanner.ScanJS(s)...)
		}
		for _, sURL := range spaResult.ExternalScripts {
			if err := cc.CheckURL(sURL, "script"); err != nil {
				continue
			}
			js, err := fetcher.FetchScript(sURL)
			if err != nil {
				continue
			}
			allFindings = append(allFindings, scanner.ScanJS(js)...)
		}
		for _, sURL := range spaResult.DynamicScripts {
			if err := cc.CheckURL(sURL, "script"); err != nil {
				continue
			}
			js, err := fetcher.FetchScript(sURL)
			if err != nil {
				continue
			}
			allFindings = append(allFindings, scanner.ScanJS(js)...)
		}
	} else {
		fmt.Printf("[*] Fetching %s ...\n", targetURL)
		html, err := fetcher.FetchPage(targetURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return
		}

		scripts := fetcher.ExtractInlineScripts(html)
		for _, s := range scripts {
			allFindings = append(allFindings, scanner.ScanJS(s)...)
		}

		scriptURLs := fetcher.ExtractScriptURLs(html, targetURL)
		for _, sURL := range scriptURLs {
			if err := cc.CheckURL(sURL, "script"); err != nil {
				continue
			}
			js, err := fetcher.FetchScript(sURL)
			if err != nil {
				continue
			}
			allFindings = append(allFindings, scanner.ScanJS(js)...)
		}
	}

	// Phase 2: Combined Analysis with Dynamic Verification
	config := &analyzer.AnalysisConfig{
		DoVerify:     true,
		WAF:          waf,
		MaxVerify:    maxVerify,
		SkipFiltered: skipFiltered,
	}

	results := analyzer.AnalyzeFindings(targetURL, allFindings, auth, config)
	analyzer.PrintAnalysisResults(results)

	// Save detailed report
	if output != "" {
		analyzer.PrintDetailedReport(results)
		fmt.Printf("\n[*] Results saved to %s\n", output)
	}
}

func scanBatch(urls []string, auth *verifier.AuthConfig, wafType string, doVerify, doStored, doSPA bool, waitTime int, output string, concurrency int, safetyMode *safety.SafetyMode, cc *compliance.ComplianceContext,
	doMine, useWordlist bool, manualParams []string, autoWAF bool) {
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

			// Compliance check for target URL
			if err := cc.CheckURL(u, "scan"); err != nil {
				fmt.Printf("  ⚠ Compliance blocked: %v\n", err)
				return
			}

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
					if err := cc.CheckURL(sURL, "script"); err != nil {
						continue
					}
					js, err := fetcher.FetchScript(sURL)
					if err != nil {
						cc.LogError(sURL, "script", err.Error())
						continue
					}
					findings = append(findings, scanner.ScanJS(js)...)
				}
				for _, sURL := range spaResult.DynamicScripts {
					if err := cc.CheckURL(sURL, "script"); err != nil {
						continue
					}
					js, err := fetcher.FetchScript(sURL)
					if err != nil {
						cc.LogError(sURL, "script", err.Error())
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
					if err := cc.CheckURL(sURL, "script"); err != nil {
						continue
					}
					js, err := fetcher.FetchScript(sURL)
					if err != nil {
						cc.LogError(sURL, "script", err.Error())
						continue
					}
					findings = append(findings, scanner.ScanJS(js)...)
				}
			}

			if len(findings) > 0 {
				fmt.Printf("  [!] %d static findings\n", len(findings))
			}

			// WAF Auto-Detection
			effectiveWAF := wafType
			if autoWAF && wafType == "" {
				cookies := []string{}
				customHeaders := map[string]string{}
				if auth != nil {
					cookies = auth.Cookies
					customHeaders = auth.Headers
				}
				wafResult := wafpkg.DetectWAF(u, cookies, customHeaders)
				if wafResult.Detected {
					effectiveWAF = wafpkg.GetRecommendedWAF(wafResult.Name)
					if effectiveWAF != "" {
						fmt.Printf("  [*] WAF detected: %s\n", wafResult.Name)
					}
				}
			}

			// Dynamic verification
			if doVerify {

				// Parameter discovery for this URL
				var urlParams []string
				if doMine && !doSPA {
					html, err := fetcher.FetchPage(u)
					if err == nil {
						discovered := miner.MineParamsFromHTML(html)
						if len(manualParams) > 0 {
							discovered = miner.MergeParams(discovered, manualParams)
						}
						if useWordlist {
							discovered = miner.AddWordlistParams(discovered, miner.GetDefaultWordlist())
						}
						urlParams = miner.ParamNames(discovered)
					}
				}

				var results []verifier.VerifyResult
				if len(urlParams) > 0 {
					fmt.Printf("  [*] Testing %d parameters\n", len(urlParams))
					results = verifier.VerifyURLWithParams(u, auth, effectiveWAF, urlParams)
				} else {
					results = verifier.VerifyURL(u, auth, effectiveWAF)
				}
				verifyResults = append(verifyResults, results...)
				for _, r := range results {
					if r.Triggered {
						fmt.Printf("  [!] Confirmed: %s (%s)\n", r.Source, r.Detail)
					}
				}
			}

			// Stored XSS
			if doStored {
				results, _ := verifier.VerifyStoredXSS(u, auth, effectiveWAF, safetyMode)
				verifyResults = append(verifyResults, results...)
				for _, r := range results {
					if r.Triggered {
						fmt.Printf("  [!] Stored XSS: %s\n", r.Detail)
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
