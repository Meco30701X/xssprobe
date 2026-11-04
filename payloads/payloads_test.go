package payloads

import (
	"os"
	"testing"
)

func TestGetBasePayloads(t *testing.T) {
	payloads := GetBasePayloads()

	if len(payloads) == 0 {
		t.Error("expected non-empty base payloads")
	}

	// Check that different contexts are represented
	contexts := make(map[Context]bool)
	for _, p := range payloads {
		contexts[p.Context] = true
	}

	expectedContexts := []Context{ContextHTML, ContextAttr, ContextJS, ContextURL, ContextTemplate}
	for _, ctx := range expectedContexts {
		if !contexts[ctx] {
			t.Errorf("missing context in base payloads: %s", ctx)
		}
	}
}

func TestGetPayloadsByContext(t *testing.T) {
	tests := []struct {
		context  Context
		minCount int
	}{
		{ContextHTML, 5},
		{ContextAttr, 3},
		{ContextJS, 3},
		{ContextURL, 2},
	}

	for _, tt := range tests {
		payloads := GetPayloadsByContext(tt.context)
		if len(payloads) < tt.minCount {
			t.Errorf("GetPayloadsByContext(%s) returned %d, want at least %d",
				tt.context, len(payloads), tt.minCount)
		}
	}
}

func TestGetPayloadsByWAF(t *testing.T) {
	tests := []struct {
		waf      string
		minCount int
	}{
		{"cloudflare", 3},
		{"aws", 3},
		{"modsec", 3},
		{"generic", 3},
	}

	for _, tt := range tests {
		payloads := GetPayloadsByWAF(tt.waf)
		if len(payloads) < tt.minCount {
			t.Errorf("GetPayloadsByWAF(%s) returned %d, want at least %d",
				tt.waf, len(payloads), tt.minCount)
		}
	}
}

func TestGetCanaryPayloads(t *testing.T) {
	canary := "TEST_CANARY_123"
	payloads := GetCanaryPayloads(canary)

	if len(payloads) == 0 {
		t.Error("expected non-empty canary payloads")
	}

	// Check that canary is included in payloads
	found := false
	for _, p := range payloads {
		if p.Value == canary || contains(p.Value, canary) {
			found = true
			break
		}
	}
	if !found {
		t.Error("canary not found in payloads")
	}
}

func TestLoadPayloadsFromFile(t *testing.T) {
	// Create temp file
	content := `# Comment line
<script>alert(1)</script>
<img src=x onerror=alert(1)>

# Another comment
<svg onload=alert(1)>`

	tmpFile, err := os.CreateTemp("", "payloads_*.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	tmpFile.WriteString(content)
	tmpFile.Close()

	payloads, err := LoadPayloadsFromFile(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	if len(payloads) != 3 {
		t.Errorf("expected 3 payloads, got %d", len(payloads))
	}

	// Check payload values
	expected := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
	}
	for i, p := range payloads {
		if p.Value != expected[i] {
			t.Errorf("payload[%d] = %s, want %s", i, p.Value, expected[i])
		}
	}
}

func TestLoadPayloadsFromStrings(t *testing.T) {
	values := []string{
		"<script>alert(1)</script>",
		"<img src=x onerror=alert(1)>",
		"",    // Should be skipped
		"   ", // Should be skipped
	}

	payloads := LoadPayloadsFromStrings(values)

	if len(payloads) != 2 {
		t.Errorf("expected 2 payloads, got %d", len(payloads))
	}
}

func TestMergePayloads(t *testing.T) {
	builtIn := []Payload{
		{Value: "builtin1"},
		{Value: "builtin2"},
	}
	custom := []Payload{
		{Value: "custom1"},
		{Value: "custom2"},
	}

	// Custom first
	merged := MergePayloads(builtIn, custom, true)
	if len(merged) != 4 {
		t.Errorf("expected 4 payloads, got %d", len(merged))
	}
	if merged[0].Value != "custom1" {
		t.Errorf("expected custom first, got %s", merged[0].Value)
	}

	// Built-in first
	merged = MergePayloads(builtIn, custom, false)
	if merged[0].Value != "builtin1" {
		t.Errorf("expected built-in first, got %s", merged[0].Value)
	}
}

func TestGetPayloadValues(t *testing.T) {
	payloads := []Payload{
		{Value: "test1"},
		{Value: "test2"},
		{Value: "test3"},
	}

	values := GetPayloadValues(payloads)

	if len(values) != 3 {
		t.Errorf("expected 3 values, got %d", len(values))
	}

	for i, v := range values {
		if v != payloads[i].Value {
			t.Errorf("value[%d] = %s, want %s", i, v, payloads[i].Value)
		}
	}
}

func TestCount(t *testing.T) {
	count := Count()
	if count == 0 {
		t.Error("expected non-zero payload count")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
