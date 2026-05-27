package crawler

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/chromedp"
)

// InputPoint represents a form input or textarea found on the page
type InputPoint struct {
	Selector string
	Type     string // "input", "textarea", "contenteditable"
	Name     string
	Tag      string
}

// CrawlResult holds what we found on the page
type CrawlResult struct {
	URL        string
	Inputs     []InputPoint
	Forms      []FormInfo
}

// FormInfo represents a form on the page
type FormInfo struct {
	Action   string
	Method   string
	Selector string
	Inputs   []InputPoint
}

// DetectInputs finds all input points on a page (forms, textareas, contenteditable elements)
func DetectInputs(targetURL string) (*CrawlResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	taskCtx, taskCancel := chromedp.NewContext(allocCtx)
	defer taskCancel()

	result := &CrawlResult{URL: targetURL}

	// JS to find all input elements
	var inputHTML string
	jsFindInputs := `
		(function() {
			var results = [];
			// Find <input> elements
			document.querySelectorAll('input[type="text"], input[type="search"], input[type="email"], input[type="url"], input:not([type])').forEach(function(el) {
				var rect = el.getBoundingClientRect();
				if (rect.width > 0 && rect.height > 0) {
					results.push({
						tag: 'input',
						type: el.type || 'text',
						name: el.name || '',
						id: el.id || '',
						placeholder: el.placeholder || '',
						selector: el.id ? '#'+el.id : (el.name ? 'input[name="'+el.name+'"]' : 'input'),
						rect: {x: rect.x, y: rect.y, w: rect.width, h: rect.height}
					});
				}
			});
			// Find <textarea> elements
			document.querySelectorAll('textarea').forEach(function(el) {
				var rect = el.getBoundingClientRect();
				if (rect.width > 0 && rect.height > 0) {
					results.push({
						tag: 'textarea',
						type: 'textarea',
						name: el.name || '',
						id: el.id || '',
						placeholder: el.placeholder || '',
						selector: el.id ? '#'+el.id : (el.name ? 'textarea[name="'+el.name+'"]' : 'textarea'),
						rect: {x: rect.x, y: rect.y, w: rect.width, h: rect.height}
					});
				}
			});
			// Find contenteditable elements
			document.querySelectorAll('[contenteditable="true"]').forEach(function(el) {
				var rect = el.getBoundingClientRect();
				if (rect.width > 0 && rect.height > 0) {
					results.push({
						tag: el.tagName.toLowerCase(),
						type: 'contenteditable',
						name: el.id || el.className || '',
						id: el.id || '',
						selector: el.id ? '#'+el.id : '[contenteditable="true"]',
						rect: {x: rect.x, y: rect.y, w: rect.width, h: rect.height}
					});
				}
			});
			// Find forms
			var forms = [];
			document.querySelectorAll('form').forEach(function(form) {
				var formInputs = [];
				form.querySelectorAll('input, textarea').forEach(function(el) {
					var rect = el.getBoundingClientRect();
					if (rect.width > 0 && rect.height > 0) {
						formInputs.push({
							tag: el.tagName.toLowerCase(),
							type: el.type || 'text',
							name: el.name || '',
							id: el.id || '',
							selector: el.id ? '#'+el.id : (el.name ? el.tagName.toLowerCase()+'[name="'+el.name+'"]' : el.tagName.toLowerCase())
						});
					}
				});
				if (formInputs.length > 0) {
					forms.push({
						action: form.action || '',
						method: form.method || 'GET',
						id: form.id || '',
						selector: form.id ? '#'+form.id : 'form',
						inputs: formInputs
					});
				}
			});
			return JSON.stringify({inputs: results, forms: forms});
		})()
	`

	err := chromedp.Run(taskCtx,
		chromedp.Navigate(targetURL),
		chromedp.Sleep(2*time.Second),
		chromedp.Evaluate(jsFindInputs, &inputHTML),
	)

	if err != nil {
		return nil, fmt.Errorf("failed to crawl %s: %w", targetURL, err)
	}

	// Parse the JSON result
	parseCrawlResult(inputHTML, result)

	// Also try to detect comment-like inputs by analyzing labels/placeholders
	for i, input := range result.Inputs {
		if isCommentInput(input) {
			result.Inputs[i].Type = "comment"
		}
	}

	return result, nil
}

func parseCrawlResult(jsonStr string, result *CrawlResult) {
	// Simple JSON parsing for input points
	// We do manual parsing to avoid importing encoding/json for this internal function
	if !strings.Contains(jsonStr, "inputs") {
		return
	}

	// Extract input entries
	for _, part := range extractJSONObjects(jsonStr, "tag") {
		input := InputPoint{}
		input.Tag = extractJSONString(part, "tag")
		input.Type = extractJSONString(part, "type")
		input.Name = extractJSONString(part, "name")
		input.Selector = extractJSONString(part, "selector")
		if input.Selector != "" {
			result.Inputs = append(result.Inputs, input)
		}
	}

	// Extract form entries
	for _, part := range extractJSONObjects(jsonStr, "action") {
		form := FormInfo{}
		form.Action = extractJSONString(part, "action")
		form.Method = extractJSONString(part, "method")
		form.Selector = extractJSONString(part, "selector")
		if form.Selector != "" {
			result.Forms = append(result.Forms, form)
		}
	}
}

// isCommentInput checks if an input looks like a comment/reply field
func isCommentInput(input InputPoint) bool {
	indicators := []string{
		"comment", "reply", "review", "feedback", "message",
		"留言", "评论", "回复", "反馈",
	}

	check := strings.ToLower(input.Name + " " + input.Selector)
	for _, indicator := range indicators {
		if strings.Contains(check, indicator) {
			return true
		}
	}

	// textarea is more likely to be a comment field
	if input.Tag == "textarea" {
		return true
	}

	return false
}

// Helper functions for simple JSON extraction (avoid full JSON parsing)
func extractJSONObjects(jsonStr, key string) []string {
	var results []string
	searchKey := `"` + key + `"`
	start := 0

	for {
		idx := strings.Index(jsonStr[start:], searchKey)
		if idx == -1 {
			break
		}
		idx += start

		// Find the start of this object (walk backwards to find '{')
		objStart := strings.LastIndex(jsonStr[:idx], "{")
		if objStart == -1 {
			start = idx + len(searchKey)
			continue
		}

		// Find matching '}'
		depth := 0
		objEnd := -1
		for i := objStart; i < len(jsonStr); i++ {
			if jsonStr[i] == '{' {
				depth++
			} else if jsonStr[i] == '}' {
				depth--
				if depth == 0 {
					objEnd = i + 1
					break
				}
			}
		}

		if objEnd > objStart {
			results = append(results, jsonStr[objStart:objEnd])
		}
		start = idx + len(searchKey)
	}
	return results
}

func extractJSONString(jsonObj, key string) string {
	searchKey := `"` + key + `"`
	idx := strings.Index(jsonObj, searchKey)
	if idx == -1 {
		return ""
	}

	// Find the colon after the key
	colonIdx := strings.Index(jsonObj[idx+len(searchKey):], ":")
	if colonIdx == -1 {
		return ""
	}
	colonIdx += idx + len(searchKey)

	// Find the value (string between quotes)
	quoteStart := strings.Index(jsonObj[colonIdx:], `"`)
	if quoteStart == -1 {
		return ""
	}
	quoteStart += colonIdx + 1

	quoteEnd := strings.Index(jsonObj[quoteStart:], `"`)
	if quoteEnd == -1 {
		return ""
	}
	quoteEnd += quoteStart

	return jsonObj[quoteStart:quoteEnd]
}

// GetPageContent returns the visible text content of a page for context
func GetPageContent(targetURL string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
	)

	allocCtx, allocCancel := chromedp.NewExecAllocator(ctx, opts...)
	defer allocCancel()

	taskCtx, taskCancel := chromedp.NewContext(allocCtx)
	defer taskCancel()

	var content string
	err := chromedp.Run(taskCtx,
		chromedp.Navigate(targetURL),
		chromedp.Sleep(2*time.Second),
		chromedp.ActionFunc(func(ctx context.Context) error {
			node, err := dom.GetDocument().Do(ctx)
			if err != nil {
				return err
			}
			content, err = dom.GetOuterHTML().WithNodeID(node.NodeID).Do(ctx)
			return err
		}),
	)

	return content, err
}

// PrintInputs prints detected input points
func PrintInputs(result *CrawlResult) {
	fmt.Printf("\n[*] Input points detected on %s:\n", result.URL)
	if len(result.Inputs) == 0 {
		fmt.Println("  [!] No input fields detected")
		return
	}

	for i, input := range result.Inputs {
		mark := " "
		if input.Type == "comment" {
			mark = "*"
		}
		fmt.Printf("  %s #%d [%s] %s (%s)\n", mark, i+1, input.Tag, input.Selector, input.Type)
	}

	if len(result.Forms) > 0 {
		fmt.Printf("\n[*] Forms detected:\n")
		for i, form := range result.Forms {
			fmt.Printf("  #%d %s method=%s action=%s\n", i+1, form.Selector, form.Method, form.Action)
		}
	}

	fmt.Println("\n  * = likely comment/review input")
}
