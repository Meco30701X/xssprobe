package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Meco30701X/domxss/fetcher"
	"github.com/Meco30701X/domxss/report"
	"github.com/Meco30701X/domxss/scanner"
)

func main() {
	url := flag.String("u", "", "Target URL to scan")
	file := flag.String("f", "", "Local JS file to scan")
	output := flag.String("o", "", "Output results to JSON file")
	flag.Parse()

	if *url == "" && *file == "" {
		fmt.Println("DOMXSS - DOM XSS Detection Tool")
		fmt.Println("Usage:")
		fmt.Println("  domxss -u https://example.com    # Scan a URL")
		fmt.Println("  domxss -f script.js              # Scan a local file")
		fmt.Println("  domxss -u URL -o result.json     # Save results to JSON")
		os.Exit(1)
	}

	var allFindings []scanner.Finding
	var targetName string

	if *file != "" {
		// Scan local file
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
		// Normalize URL
		if !strings.HasPrefix(*url, "http") {
			*url = "https://" + *url
		}

		fmt.Printf("[*] Fetching %s ...\n", *url)
		html, err := fetcher.FetchPage(*url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

		// Scan inline scripts
		scripts := fetcher.ExtractInlineScripts(html)
		fmt.Printf("[*] Found %d inline scripts\n", len(scripts))
		for _, s := range scripts {
			findings := scanner.ScanJS(s)
			allFindings = append(allFindings, findings...)
		}

		// Scan external scripts
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

	// Output results
	report.PrintFindings(allFindings, targetName)

	if *output != "" {
		if err := report.OutputJSON(allFindings, *output); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON: %v\n", err)
		} else {
			fmt.Printf("\n[*] Results saved to %s\n", *output)
		}
	}

	if len(allFindings) > 0 {
		os.Exit(2) // Exit code 2 means vulnerabilities found
	}
}
