package context

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Meco30701X/xssprobe/compliance"
)

// InjectionContext represents where the payload is reflected
type InjectionContext string

const (
	CtxHTML       InjectionContext = "html"       // HTML body
	CtxAttribute  InjectionContext = "attribute"   // HTML attribute value
	CtxJSString   InjectionContext = "js-string"   // Inside JavaScript string
	CtxJSCode     InjectionContext = "js-code"     // Inside JavaScript code (not in string)
	CtxURL        InjectionContext = "url"         // Inside URL/href
	CtxCSS        InjectionContext = "css"         // Inside CSS
	CtxComment    InjectionContext = "comment"     // Inside HTML comment
	CtxUnknown    InjectionContext = "unknown"     // Cannot determine
	CtxNone       InjectionContext = "none"        // Not reflected at all
)

// ContextResult holds the detection result
type ContextResult struct {
	Context    InjectionContext
	Reflected  bool
	Encoded    bool
	EncodingType string // html-entity, url, js-escape, none
	Detail     string
}

// DetectContext sends a canary probe and analyzes the reflection context
// limiter can be nil; if provided, rate limit is applied before the request
func DetectContext(targetURL string, paramName string, cookies []string, headers map[string]string, limiter *compliance.RateLimiter) *ContextResult {
	// Unique canary for detection
	canary := "xXxCTXxXx7xXx"

	// Build test URL
	testURL := buildTestURL(targetURL, paramName, canary)

	// Apply rate limit if provided
	if limiter != nil {
		limiter.Wait()
	}

	// Send request
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return &ContextResult{Context: CtxUnknown, Detail: "request error: " + err.Error()}
	}

	// Add cookies
	for _, cookie := range cookies {
		parts := strings.SplitN(cookie, "=", 2)
		if len(parts) == 2 {
			req.AddCookie(&http.Cookie{Name: parts[0], Value: parts[1]})
		}
	}

	// Add headers
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := client.Do(req)
	if err != nil {
		return &ContextResult{Context: CtxUnknown, Detail: "request error: " + err.Error()}
	}
	defer resp.Body.Close()

	// Read response body (limit to 1MB)
	buf := make([]byte, 1024*1024)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	// Check if canary is reflected
	if !strings.Contains(body, canary) {
		// Check URL-encoded version
		encodedCanary := url.QueryEscape(canary)
		if strings.Contains(body, encodedCanary) {
			return &ContextResult{
				Context:      CtxUnknown,
				Reflected:    true,
				Encoded:      true,
				EncodingType: "url",
				Detail:       "reflected but URL-encoded",
			}
		}

		// Check HTML-entity encoded
		htmlCanary := strings.ReplaceAll(canary, "<", "&lt;")
		htmlCanary = strings.ReplaceAll(htmlCanary, ">", "&gt;")
		htmlCanary = strings.ReplaceAll(htmlCanary, "\"", "&quot;")
		if strings.Contains(body, htmlCanary) {
			return &ContextResult{
				Context:      CtxUnknown,
				Reflected:    true,
				Encoded:      true,
				EncodingType: "html-entity",
				Detail:       "reflected but HTML-entity encoded",
			}
		}

		return &ContextResult{Context: CtxNone, Reflected: false, Detail: "not reflected"}
	}

	// Canary found - analyze context
	return analyzeContext(body, canary)
}

// buildTestURL creates a URL with the canary in the specified parameter
func buildTestURL(baseURL, paramName, canary string) string {
	parsed, err := url.Parse(baseURL)
	if err != nil {
		if strings.Contains(baseURL, "?") {
			return baseURL + "&" + paramName + "=" + canary
		}
		return baseURL + "?" + paramName + "=" + canary
	}

	q := parsed.Query()
	q.Set(paramName, canary)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

// analyzeContext determines the injection context from the response body
func analyzeContext(body, canary string) *ContextResult {
	// Find the canary in the body and analyze surrounding characters
	idx := strings.Index(body, canary)
	if idx == -1 {
		return &ContextResult{Context: CtxNone, Reflected: false}
	}

	// Get surrounding context (100 chars before and after)
	start := idx - 100
	if start < 0 {
		start = 0
	}
	end := idx + len(canary) + 100
	if end > len(body) {
		end = len(body)
	}
	surrounding := body[start:end]

	// Check if inside HTML comment
	if isInHTMLComment(body, idx) {
		return &ContextResult{
			Context:   CtxComment,
			Reflected: true,
			Detail:    "inside HTML comment",
		}
	}

	// Check if inside <script> tag
	if isInScriptTag(body, idx) {
		// Check if inside a string literal
		if isInJSString(body, idx, canary) {
			return &ContextResult{
				Context:   CtxJSString,
				Reflected: true,
				Detail:    "inside JavaScript string",
			}
		}
		return &ContextResult{
			Context:   CtxJSCode,
			Reflected: true,
			Detail:    "inside JavaScript code",
		}
	}

	// Check if inside HTML attribute
	attrContext := isInAttribute(body, idx, canary)
	if attrContext != nil {
		return attrContext
	}

	// Check if inside URL/href
	if isInURLContext(surrounding) {
		return &ContextResult{
			Context:   CtxURL,
			Reflected: true,
			Detail:    "inside URL context",
		}
	}

	// Check if inside CSS
	if isInCSSContext(body, idx) {
		return &ContextResult{
			Context:   CtxCSS,
			Reflected: true,
			Detail:    "inside CSS context",
		}
	}

	// Default: HTML body
	return &ContextResult{
		Context:   CtxHTML,
		Reflected: true,
		Detail:    "in HTML body",
	}
}

// isInHTMLComment checks if the canary is inside an HTML comment
func isInHTMLComment(body string, canaryIdx int) bool {
	// Look for <!-- before canary
	before := body[:canaryIdx]
	lastCommentStart := strings.LastIndex(before, "<!--")
	if lastCommentStart == -1 {
		return false
	}
	// Check if comment is closed
	commentContent := body[lastCommentStart:canaryIdx]
	return !strings.Contains(commentContent, "-->")
}

// isInScriptTag checks if the canary is inside a <script> tag
func isInScriptTag(body string, canaryIdx int) bool {
	before := body[:canaryIdx]

	// Find last <script> or </script>
	lastScriptOpen := strings.LastIndex(before, "<script")
	lastScriptClose := strings.LastIndex(before, "</script>")

	return lastScriptOpen > lastScriptClose
}

// isInJSString checks if the canary is inside a JavaScript string literal
func isInJSString(body string, canaryIdx int, canary string) bool {
	before := body[:canaryIdx]

	// Find the line containing the canary
	lineStart := strings.LastIndex(before, "\n")
	if lineStart == -1 {
		lineStart = 0
	}
	line := before[lineStart:]

	// Check for string quotes before canary
	inSingleQuote := false
	inDoubleQuote := false
	escaped := false

	for _, ch := range line {
		if escaped {
			escaped = false
			continue
		}
		if ch == '\\' {
			escaped = true
			continue
		}
		if ch == '\'' && !inDoubleQuote {
			inSingleQuote = !inSingleQuote
		}
		if ch == '"' && !inSingleQuote {
			inDoubleQuote = !inDoubleQuote
		}
	}

	return inSingleQuote || inDoubleQuote
}

// isInAttribute checks if the canary is inside an HTML attribute
func isInAttribute(body string, canaryIdx int, canary string) *ContextResult {
	before := body[:canaryIdx]

	// Find the last < tag before canary
	lastTag := strings.LastIndex(before, "<")
	if lastTag == -1 {
		return nil
	}

	// Check if we're inside a tag (between < and >)
	afterTag := before[lastTag:]
	if strings.Contains(afterTag, ">") {
		return nil // We're outside the tag
	}

	// We're inside a tag - check if in attribute value
	// Look for = " or = ' before canary
	attrPatterns := []struct {
		pattern string
		quote   byte
	}{
		{`=`, '"'},
		{`=`, '\''},
	}

	for _, ap := range attrPatterns {
		eqIdx := strings.LastIndex(afterTag, ap.pattern)
		if eqIdx != -1 {
			afterEq := afterTag[eqIdx+1:]
			// Skip whitespace
			afterEq = strings.TrimLeft(afterEq, " \t\n")
			if len(afterEq) > 0 && afterEq[0] == ap.quote {
				// Found attribute value start
				return &ContextResult{
					Context:   CtxAttribute,
					Reflected: true,
					Detail:    fmt.Sprintf("inside HTML attribute (quoted with %c)", ap.quote),
				}
			}
		}
	}

	// Inside tag but not in attribute value
	return &ContextResult{
		Context:   CtxAttribute,
		Reflected: true,
		Detail:    "inside HTML tag (unquoted attribute)",
	}
}

// isInURLContext checks if the surrounding looks like a URL context
func isInURLContext(surrounding string) bool {
	urlIndicators := []string{
		"href=", "src=", "action=", "data=",
		"window.location", "document.location",
		"location.href", "location.assign", "location.replace",
	}

	lower := strings.ToLower(surrounding)
	for _, indicator := range urlIndicators {
		if strings.Contains(lower, indicator) {
			return true
		}
	}
	return false
}

// isInCSSContext checks if the canary is inside CSS
func isInCSSContext(body string, canaryIdx int) bool {
	before := body[:canaryIdx]

	// Check for <style> tag
	lastStyleOpen := strings.LastIndex(before, "<style")
	lastStyleClose := strings.LastIndex(before, "</style>")

	if lastStyleOpen > lastStyleClose {
		return true
	}

	// Check for style= attribute
	lastStyleAttr := strings.LastIndex(before, "style=")
	if lastStyleAttr != -1 {
		afterStyle := before[lastStyleAttr:]
		if !strings.Contains(afterStyle, ">") {
			return true
		}
	}

	return false
}

// GetRecommendedPayloads returns payload types suitable for the detected context
func GetRecommendedPayloads(ctx InjectionContext) []string {
	switch ctx {
	case CtxHTML:
		return []string{"html", "script", "img", "svg", "event"}
	case CtxAttribute:
		return []string{"attr", "event", "img", "svg"}
	case CtxJSString:
		return []string{"js", "jsvar"}
	case CtxJSCode:
		return []string{"html", "script", "img"} // Break out with </script> or similar
	case CtxURL:
		return []string{"url", "javascript"}
	case CtxCSS:
		return []string{"css", "html"} // CSS injection can lead to XSS
	case CtxComment:
		return []string{"html", "comment"} // Close comment and inject
	default:
		return []string{"html", "attr", "js"} // Try all
	}
}

// PrintContextResult prints the context detection result
func PrintContextResult(result *ContextResult, paramName string) {
	if result.Reflected {
		emoji := "📍"
		if result.Encoded {
			emoji = "🔒"
		}

		fmt.Printf("  %s Parameter '%s': %s", emoji, paramName, result.Context)
		if result.Encoded {
			fmt.Printf(" (encoded: %s)", result.EncodingType)
		}
		fmt.Printf(" - %s\n", result.Detail)
	} else {
		fmt.Printf("  ❌ Parameter '%s': not reflected\n", paramName)
	}
}
