package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Meco30701X/domxss/fetcher"
	"github.com/Meco30701X/domxss/report"
	"github.com/Meco30701X/domxss/scanner"
	"github.com/Meco30701X/domxss/verifier"
)

func main() {
	url := flag.String("u", "", "Target URL to scan")
	file := flag.String("f", "", "Local JS file to scan")
	output := flag.String("o", "", "Output results to JSON file")
	verify := flag.Bool("verify", false, "Dynamic verification with headless browser")
	flag.Parse()

	if *url == "" && *file == "" {
		fmt.Println("DOMXSS - DOM XSS Detection Tool")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  domxss -u https://example.com          # Static analysis")
		fmt.Println("  domxss -u https://example.com -verify   # Static + dynamic verification")
		fmt.Println("  domxss -f script.js                     # Scan a local file")
		fmt.Println("  domxss -u URL -o result.json            # Save results to JSON")
		fmt.Println()
		fmt.Println("Flags:")
		fmt.Println("  -u        Target URL")
		fmt.Println("  -f        Local JS file")
		fmt.Println("  -o        Output JSON file")
		fmt.Println("  -verify   Enable dynamic verification (headless browser)")
		os.Exit(1)
	}

	var allFindings []scanner.Finding
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

	// Dynamic verification
	if *verify && *url != "" {
		fmt.Println("\n[*] Running dynamic verification with headless browser...")
		fmt.Println("[*] Testing payloads against target...")

		results := verifier.VerifyURL(*url)
		verifier.PrintResults(results)

		if *output != "" {
			// Append verification results to JSON output
			report.OutputVerifiedJSON(allFindings, results, *output)
		}
	} else if *output != "" {
		if err := report.OutputJSON(allFindings, *output); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON: %v\n", err)
		} else {
			fmt.Printf("\n[*] Results saved to %s\n", *output)
		}
	}

	if len(allFindings) > 0 {
		os.Exit(2)
	}
}
