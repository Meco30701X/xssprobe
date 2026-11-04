package scanner

import "testing"

func TestFilterThirdPartyFindings(t *testing.T) {
	findings := []Finding{
		{Source: "unknown", Sink: "innerHTML", Confidence: "low"},
		{Source: "location.hash", Sink: "innerHTML", Confidence: "high"},
		{Source: "location.search", Sink: "document.write", Confidence: "medium"},
	}

	kept, suppressed := FilterThirdPartyFindings(findings, false)
	if suppressed != 1 || len(kept) != 2 {
		t.Fatalf("third-party filtering kept %d and suppressed %d, want 2 and 1", len(kept), suppressed)
	}
	if kept[0].Confidence != "high" || kept[1].Confidence != "medium" {
		t.Fatalf("source-to-sink findings should be retained: %#v", kept)
	}

	kept, suppressed = FilterThirdPartyFindings(findings, true)
	if suppressed != 0 || len(kept) != len(findings) {
		t.Fatalf("first-party findings changed: kept %d, suppressed %d", len(kept), suppressed)
	}
}

// This fixed, labeled corpus is a regression benchmark for the scanner's
// current binary claim: whether it can identify a direct, unsanitized
// attacker-controlled value reaching an executable HTML/code sink. Cases
// marked holdout are reserved for measuring generalization while tuning.
// It is intentionally small and must not be presented as real-world accuracy.
func TestAccuracyCorpus(t *testing.T) {
	type sample struct {
		name, code, split string
		vulnerable        bool
	}
	cases := []sample{
		{"hash_innerhtml_direct", `el.innerHTML = location.hash`, "dev", true},
		{"search_eval_direct", `eval(location.search)`, "dev", true},
		{"href_document_write", `document.write(location.href)`, "dev", true},
		{"pathname_insert_html", `node.insertAdjacentHTML('beforeend', location.pathname)`, "dev", true},
		{"referrer_outerhtml", `node.outerHTML = document.referrer`, "dev", true},
		{"window_name_timeout", `setTimeout(window.name)`, "dev", true},
		{"hash_to_variable", "const input = location.hash;\nel.innerHTML = input", "dev", true},
		{"search_cross_line", "let q = location.search;\neval(q)", "dev", true},
		{"hash_concat", "const value = location.hash;\nconst html = '<b>' + value;\nel.innerHTML = html", "dev", true},
		{"hash_template", "const value = location.hash;\nconst html = `<b>${value}`;\nel.innerHTML = html", "dev", true},
		{"storage_to_eval", "const saved = localStorage.getItem('x');\neval(saved)", "dev", true},
		{"message_to_html", "window.addEventListener('message', e => {\n el.innerHTML = e.data\n})", "dev", true},
		{"response_to_html", "xhr.onload = () => {\n el.innerHTML = xhr.responseText\n}", "dev", true},
		{"input_value_html", `input.value = location.hash;\nel.innerHTML = input.value`, "dev", true},
		{"decode_uri_html", `el.innerHTML = decodeURIComponent(location.search)`, "dev", true},
		{"data_attr_html", `el.innerHTML = node.dataset.content`, "dev", true},
		{"hash_jquery_html", `$('#out').html(location.hash)`, "dev", true},
		{"hash_script_src", `script.src = location.hash`, "dev", true},
		{"hash_setattribute_event", `el.setAttribute('onclick', location.hash)`, "dev", true},
		{"hash_function_constructor", `const run = new Function(location.hash)`, "dev", true},
		{"hash_dompurify", `el.innerHTML = DOMPurify.sanitize(location.hash)`, "dev", false},
		{"hash_textcontent", `el.textContent = location.hash`, "dev", false},
		{"hash_innertext", `el.innerText = location.hash`, "dev", false},
		{"constant_html", `el.innerHTML = '<b>hello</b>'`, "dev", false},
		{"safe_getter", `const el = document.getElementById('x')`, "dev", false},
		{"storage_write", `localStorage.setItem('x', value)`, "dev", false},
		{"tainted_unused", "const value = location.hash;\nconsole.log(value)", "dev", false},
		{"source_only", `const url = location.search`, "dev", false},
		{"sink_unknown", `el.innerHTML = trustedTemplate`, "dev", false},
		{"source_in_comment", "// location.hash reaches innerHTML\nel.innerHTML = trusted", "dev", false},
		{"source_in_string", "const help = \"location.hash\";\nel.innerHTML = trusted", "dev", false},
		{"source_in_sink_comment", `el.innerHTML = trusted; // location.hash`, "dev", false},
		{"identifier_substring", "const hash = location.hash;\nconst hashValue = 'safe';\nel.innerHTML = hashValue", "dev", false},
		{"safe_reassignment", "let value = location.hash;\nvalue = 'safe';\nel.innerHTML = value", "dev", false},
		{"unrelated_source_and_sink", "const url = location.hash;\nel.innerHTML = '<b>constant</b>'", "dev", false},
		{"safe_attribute", `el.setAttribute('title', location.hash)`, "dev", false},
		{"safe_text_node", `el.appendChild(document.createTextNode(location.hash))`, "dev", false},
		{"sanitized_cross_line", "const clean = DOMPurify.sanitize(location.hash);\nel.innerHTML = clean", "dev", false},
		{"encoded_cross_line", "const encoded = encodeURIComponent(location.hash);\nel.innerHTML = encoded", "dev", false},
		{"other_source_unrelated", "const value = document.referrer;\neval('1 + 1')", "dev", false},
		{"holdout_search_innerhtml", `el.innerHTML = new URLSearchParams(location.search).get('q')`, "holdout", true},
		{"holdout_hash_eval_assignment", "let code;\ncode = location.hash;\neval(code)", "holdout", true},
		{"holdout_optional_chain", `el.innerHTML = window.location?.hash`, "holdout", true},
		{"holdout_document_url_html", `el.innerHTML = document.URL`, "holdout", true},
		{"holdout_input_crossline", "const userValue = input.value;\nrender.innerHTML = userValue", "holdout", true},
		{"holdout_safe_encode_uri", `el.innerHTML = encodeURIComponent(location.hash)`, "holdout", false},
		{"holdout_safe_whitelist", "const value = location.hash;\nconst safe = value.replace(/[^a-z0-9]/gi, '');\nel.innerHTML = safe", "holdout", false},
		{"holdout_shadowed_parameter", "const value = location.hash;\nfunction render(value) { el.innerHTML = value }\nrender('constant')", "holdout", false},
		{"holdout_template_constant", "const html = `<b>literal</b>`;\nel.innerHTML = html", "holdout", false},
		{"holdout_comment_only", `/* location.search */\neval('1 + 1')`, "holdout", false},
	}

	var total, correct, tp, tn, fp, fn int
	var holdTotal, holdCorrect, holdTP, holdTN, holdFP, holdFN int
	for _, c := range cases {
		findings := ScanJS(c.code)
		predicted := false
		for _, f := range findings {
			if f.Source != "" && f.Source != "unknown" && f.Confidence == "high" && f.Severity == "high" {
				predicted = true
				break
			}
		}
		if predicted == c.vulnerable {
			correct++
		}
		total++
		if c.vulnerable && predicted {
			tp++
		} else if !c.vulnerable && !predicted {
			tn++
		} else if predicted {
			fp++
		} else {
			fn++
		}
		if c.split == "holdout" {
			holdTotal++
			if predicted == c.vulnerable {
				holdCorrect++
			}
			if c.vulnerable && predicted {
				holdTP++
			} else if !c.vulnerable && !predicted {
				holdTN++
			} else if predicted {
				holdFP++
			} else {
				holdFN++
			}
		}
		if c.split == "holdout" && predicted != c.vulnerable {
			t.Errorf("holdout %s: predicted vulnerable=%v, want %v; findings=%+v", c.name, predicted, c.vulnerable, findings)
		}
		if predicted != c.vulnerable {
			t.Logf("mismatch split=%s case=%s predicted=%v want=%v findings=%+v", c.split, c.name, predicted, c.vulnerable, findings)
		}
	}
	precision := percent(tp, tp+fp)
	recall := percent(tp, tp+fn)
	t.Logf("all: n=%d accuracy=%.1f%% precision=%.1f%% recall=%.1f%% TP=%d TN=%d FP=%d FN=%d", total, percent(correct, total), precision, recall, tp, tn, fp, fn)
	t.Logf("holdout: n=%d accuracy=%.1f%% precision=%.1f%% recall=%.1f%% TP=%d TN=%d FP=%d FN=%d", holdTotal, percent(holdCorrect, holdTotal), percent(holdTP, holdTP+holdFP), percent(holdTP, holdTP+holdFN), holdTP, holdTN, holdFP, holdFN)
	if percent(holdCorrect, holdTotal) < 85 {
		t.Fatalf("held-out accuracy %.1f%% is below the 85%% target", percent(holdCorrect, holdTotal))
	}
}

func percent(n, d int) float64 {
	if d == 0 {
		return 100
	}
	return 100 * float64(n) / float64(d)
}
