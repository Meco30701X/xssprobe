package report

import (
	"fmt"
	"html"
	"os"
	"strings"
	"time"

	"github.com/Meco30701X/xssprobe/scanner"
	"github.com/Meco30701X/xssprobe/verifier"
)

// HTMLReportData holds all data for HTML report generation
type HTMLReportData struct {
	TargetURL     string
	ScanTime      string
	Findings      []scanner.Finding
	VerifyResults []verifier.VerifyResult
	Summary       HTMLSummary
}

// HTMLSummary holds summary statistics
type HTMLSummary struct {
	Total     int
	Confirmed int
	Possible  int
	Filtered  int
	High      int
	Medium    int
	Low       int
}

// OutputHTML generates an HTML report
func OutputHTML(findings []scanner.Finding, results []verifier.VerifyResult, targetURL, filename string) error {
	data := HTMLReportData{
		TargetURL:     targetURL,
		ScanTime:      time.Now().Format("2006-01-02 15:04:05"),
		Findings:      findings,
		VerifyResults: results,
	}

	// Calculate summary
	data.Summary = calculateSummary(findings, results)

	// Generate HTML
	htmlContent := generateHTML(data)

	// Write to file
	return os.WriteFile(filename, []byte(htmlContent), 0644)
}

func calculateSummary(findings []scanner.Finding, results []verifier.VerifyResult) HTMLSummary {
	s := HTMLSummary{Total: len(findings)}

	// Count by severity
	for _, f := range findings {
		switch f.Severity {
		case "high":
			s.High++
		case "medium":
			s.Medium++
		case "low":
			s.Low++
		}
		if f.Filtered {
			s.Filtered++
		}
	}

	// Count confirmed from verify results
	confirmedLines := make(map[int]bool)
	for _, r := range results {
		if r.Triggered {
			// Try to match with findings
			for _, f := range findings {
				// Simple matching - in real implementation, you'd want better matching
				if strings.Contains(r.Source, f.Source) || strings.Contains(f.Source, r.Source) {
					confirmedLines[f.Line] = true
				}
			}
		}
	}

	s.Confirmed = len(confirmedLines)
	s.Possible = s.Total - s.Confirmed - s.Filtered

	return s
}

func generateHTML(data HTMLReportData) string {
	var sb strings.Builder

	sb.WriteString(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>XSSProbe Scan Report</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; color: #333; line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 20px; }
.header { background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 20px; }
.header h1 { font-size: 28px; margin-bottom: 10px; }
.header .meta { opacity: 0.9; font-size: 14px; }
.summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }
.summary-card { background: white; padding: 20px; border-radius: 8px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
.summary-card .number { font-size: 36px; font-weight: bold; }
.summary-card .label { color: #666; font-size: 14px; }
.summary-card.confirmed { border-left: 4px solid #e74c3c; }
.summary-card.confirmed .number { color: #e74c3c; }
.summary-card.possible { border-left: 4px solid #f39c12; }
.summary-card.possible .number { color: #f39c12; }
.summary-card.filtered { border-left: 4px solid #95a5a6; }
.summary-card.filtered .number { color: #95a5a6; }
.finding { background: white; border-radius: 8px; margin-bottom: 15px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden; }
.finding-header { padding: 15px 20px; border-bottom: 1px solid #eee; display: flex; justify-content: space-between; align-items: center; }
.finding-header h3 { font-size: 16px; }
.severity { padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: bold; text-transform: uppercase; }
.severity.high { background: #fde8e8; color: #e74c3c; }
.severity.medium { background: #fef3e2; color: #f39c12; }
.severity.low { background: #e8f8f5; color: #27ae60; }
.finding-body { padding: 20px; }
.finding-section { margin-bottom: 15px; }
.finding-section:last-child { margin-bottom: 0; }
.finding-section .label { font-weight: 600; color: #666; margin-bottom: 5px; font-size: 13px; }
.finding-section .value { font-family: 'Monaco', 'Menlo', monospace; background: #f8f9fa; padding: 10px; border-radius: 4px; font-size: 13px; overflow-x: auto; }
.code-block { background: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 6px; font-family: 'Monaco', 'Menlo', monospace; font-size: 13px; overflow-x: auto; }
.code-block .line-number { color: #858585; margin-right: 15px; }
.injection-url { background: #e3f2fd; padding: 12px; border-radius: 6px; word-break: break-all; }
.injection-url a { color: #1976d2; text-decoration: none; }
.injection-url a:hover { text-decoration: underline; }
.payload { background: #fff3e0; padding: 12px; border-radius: 6px; font-family: 'Monaco', 'Menlo', monospace; font-size: 13px; }
.status { display: inline-flex; align-items: center; gap: 8px; padding: 8px 16px; border-radius: 20px; font-size: 14px; }
.status.confirmed { background: #fde8e8; color: #e74c3c; }
.status.possible { background: #fef3e2; color: #f39c12; }
.status.filtered { background: #e8e8e8; color: #666; }
.filter-warning { background: #fff3cd; border: 1px solid #ffc107; padding: 12px; border-radius: 6px; margin-top: 10px; }
.verify-results { margin-top: 15px; }
.verify-result { padding: 10px; margin-bottom: 8px; border-radius: 4px; font-size: 13px; }
.verify-result.triggered { background: #fde8e8; border-left: 3px solid #e74c3c; }
.verify-result.not-triggered { background: #f8f9fa; border-left: 3px solid #95a5a6; }
.footer { text-align: center; padding: 20px; color: #666; font-size: 13px; margin-top: 30px; }
</style>
</head>
<body>
<div class="container">
`)

	// Header
	sb.WriteString(fmt.Sprintf(`
<div class="header">
<h1>🔍 XSSProbe Scan Report</h1>
<div class="meta">
<div>目标: %s</div>
<div>扫描时间: %s</div>
<div>生成时间: %s</div>
</div>
</div>
`, html.EscapeString(data.TargetURL), data.ScanTime, time.Now().Format("2006-01-02 15:04:05")))

	// Summary cards
	sb.WriteString(`
<div class="summary">
<div class="summary-card">
<div class="number">` + fmt.Sprintf("%d", data.Summary.Total) + `</div>
<div class="label">总发现</div>
</div>
<div class="summary-card confirmed">
<div class="number">` + fmt.Sprintf("%d", data.Summary.Confirmed) + `</div>
<div class="label">已确认</div>
</div>
<div class="summary-card possible">
<div class="number">` + fmt.Sprintf("%d", data.Summary.Possible) + `</div>
<div class="label">待验证</div>
</div>
<div class="summary-card filtered">
<div class="number">` + fmt.Sprintf("%d", data.Summary.Filtered) + `</div>
<div class="label">已过滤</div>
</div>
</div>
`)

	// Findings
	for i, f := range data.Findings {
		sb.WriteString(fmt.Sprintf(`
<div class="finding">
<div class="finding-header">
<h3>#%d - Line %d</h3>
<span class="severity %s">%s</span>
</div>
<div class="finding-body">
<div class="finding-section">
<div class="label">漏洞链</div>
<div class="value">%s → %s</div>
</div>
<div class="finding-section">
<div class="label">代码片段</div>
<div class="code-block"><span class="line-number">Line %d:</span>%s</div>
</div>
`, i+1, f.Line, f.Severity, strings.ToUpper(f.Severity),
			html.EscapeString(f.Source), html.EscapeString(f.Sink),
			f.Line, html.EscapeString(f.Code)))

		// Filter warning
		if f.Filtered {
			sb.WriteString(fmt.Sprintf(`
<div class="filter-warning">
⚠️ <strong>检测到过滤:</strong> %s<br>
<span style="color: #856404;">此漏洞可能被过滤机制阻断，需要手动验证</span>
</div>
`, html.EscapeString(f.FilterType)))
		}

		// Injection details
		payload, isFiltered, needsManual := suggestPayload(f.Sink, f.FilterType)
		paramName := extractParamName(f.Source)

		if paramName != "" {
			injectionURL := buildInjectionURL(data.TargetURL, paramName, payload)
			if injectionURL != "" {
				sb.WriteString(fmt.Sprintf(`
<div class="finding-section">
<div class="label">🔗 注入 URL</div>
<div class="injection-url"><a href="%s" target="_blank">%s</a></div>
</div>
`, html.EscapeString(injectionURL), html.EscapeString(injectionURL)))
			}
		}

		sb.WriteString(fmt.Sprintf(`
<div class="finding-section">
<div class="label">💡 建议 Payload</div>
<div class="payload">%s</div>
</div>
`, html.EscapeString(payload)))

		if isFiltered {
			if needsManual {
				sb.WriteString(`<div class="status filtered">⚠️ 需要手动验证</div>`)
			} else {
				sb.WriteString(`<div class="status filtered">⚠️ 使用绕过 Payload</div>`)
			}
		}

		// Verify results for this finding
		var relatedResults []verifier.VerifyResult
		for _, r := range data.VerifyResults {
			if strings.Contains(r.Source, f.Source) || strings.Contains(f.Source, r.Source) {
				relatedResults = append(relatedResults, r)
			}
		}

		if len(relatedResults) > 0 {
			sb.WriteString(`
<div class="verify-results">
<div class="label">验证结果</div>
`)
			confirmed := false
			for _, r := range relatedResults {
				if r.Triggered {
					confirmed = true
					sb.WriteString(fmt.Sprintf(`
<div class="verify-result triggered">
✅ <strong>已确认:</strong> %s<br>
<span style="color: #666;">Payload: %s</span>
</div>
`, html.EscapeString(r.Detail), html.EscapeString(r.Payload)))
				}
			}

			if !confirmed {
				sb.WriteString(`<div class="verify-result not-triggered">❌ 未确认可利用</div>`)
			}
			sb.WriteString(`</div>`)
		}

		sb.WriteString(`</div></div>`)
	}

	// Footer
	sb.WriteString(`
<div class="footer">
<p>XSSProbe - XSS Vulnerability Detection Tool</p>
<p>本报告仅供安全测试参考，请结合实际情况判断</p>
</div>
</div>
</body>
</html>
`)

	return sb.String()
}
