package miner

import (
	"testing"
)

func TestMineParamsFromHTML_FormInputs(t *testing.T) {
	html := `
		<form action="/search">
			<input type="text" name="q" placeholder="Search">
			<input type="hidden" name="token" value="abc123">
			<select name="category">
				<option value="1">Cat 1</option>
			</select>
			<textarea name="comment"></textarea>
		</form>
	`

	params := MineParamsFromHTML(html)
	names := ParamNames(params)

	// Should find 4 form inputs
	if len(names) != 4 {
		t.Errorf("expected 4 params, got %d: %v", len(names), names)
	}

	expected := map[string]bool{"q": true, "token": true, "category": true, "comment": true}
	for _, name := range names {
		if !expected[name] {
			t.Errorf("unexpected param: %s", name)
		}
	}
}

func TestMineParamsFromHTML_URLParams(t *testing.T) {
	html := `
		<a href="/page?id=123&ref=home">Link</a>
		<a href="/user?uid=456">User</a>
	`

	params := MineParamsFromHTML(html)
	names := ParamNames(params)

	if len(names) != 3 {
		t.Errorf("expected 3 params, got %d: %v", len(names), names)
	}

	expected := map[string]bool{"id": true, "ref": true, "uid": true}
	for _, name := range names {
		if !expected[name] {
			t.Errorf("unexpected param: %s", name)
		}
	}
}

func TestMineParamsFromHTML_JSParams(t *testing.T) {
	html := `
		<script>
		var params = new URLSearchParams(location.search);
		var page = params.get('page');
		var sort = params.get('sort');
		</script>
	`

	params := MineParamsFromHTML(html)
	names := ParamNames(params)

	if len(names) != 2 {
		t.Errorf("expected 2 params, got %d: %v", len(names), names)
	}

	expected := map[string]bool{"page": true, "sort": true}
	for _, name := range names {
		if !expected[name] {
			t.Errorf("unexpected param: %s", name)
		}
	}
}

func TestMineParamsFromHTML_Empty(t *testing.T) {
	html := `<html><body>No params here</body></html>`

	params := MineParamsFromHTML(html)

	if len(params) != 0 {
		t.Errorf("expected 0 params, got %d", len(params))
	}
}

func TestMineParamsFromHTML_Deduplication(t *testing.T) {
	html := `
		<input name="q">
		<a href="/search?q=test">Link</a>
	`

	params := MineParamsFromHTML(html)
	names := ParamNames(params)

	// 'q' appears twice but should be deduplicated
	if len(names) != 1 {
		t.Errorf("expected 1 param (deduplicated), got %d: %v", len(names), names)
	}
}

func TestMergeParams(t *testing.T) {
	discovered := []DiscoveredParam{
		{Name: "q", Source: SourceForm},
		{Name: "id", Source: SourceURL},
	}
	manual := []string{"token", "q"} // 'q' is duplicate

	merged := MergeParams(discovered, manual)

	if len(merged) != 3 {
		t.Errorf("expected 3 params, got %d", len(merged))
	}
}

func TestAddWordlistParams(t *testing.T) {
	discovered := []DiscoveredParam{
		{Name: "q", Source: SourceForm},
	}
	wordlist := []string{"id", "page", "q"} // 'q' is duplicate

	result := AddWordlistParams(discovered, wordlist)

	if len(result) != 3 {
		t.Errorf("expected 3 params, got %d", len(result))
	}
}

func TestGetDefaultWordlist(t *testing.T) {
	wordlist := GetDefaultWordlist()

	if len(wordlist) == 0 {
		t.Error("wordlist should not be empty")
	}

	// Check some common params exist
	commonParams := []string{"q", "id", "page", "search", "name"}
	for _, p := range commonParams {
		found := false
		for _, w := range wordlist {
			if w == p {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("wordlist missing common param: %s", p)
		}
	}
}

func TestExtractURLParams(t *testing.T) {
	tests := []struct {
		input    string
		expected int
	}{
		{"https://example.com?q=test&id=123", 2},
		{"https://example.com?q=test", 1},
		{"https://example.com", 0},
		{"https://example.com?q=test#fragment", 1},
	}

	for _, tt := range tests {
		params := extractURLParams(tt.input)
		if len(params) != tt.expected {
			t.Errorf("extractURLParams(%s) = %d, want %d", tt.input, len(params), tt.expected)
		}
	}
}
