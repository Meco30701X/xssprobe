package report

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/Meco30701X/xssprobe/analyzer"
	"github.com/Meco30701X/xssprobe/verifier"
)

func TestWritePrivateFile(t *testing.T) {
	path := t.TempDir() + "/report.json"
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := writePrivateFile(path, []byte("new")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Fatalf("report contents = %q, want %q", data, "new")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0600 {
			t.Errorf("report permissions = %04o, want 0600", got)
		}
	}
}

func TestOutputAnalysisJSONPersistsCombinedResults(t *testing.T) {
	path := t.TempDir() + "/analysis.json"
	err := OutputAnalysisJSON(
		[]analyzer.AnalysisResult{{Confidence: "confirmed"}},
		[]verifier.VerifyResult{{Source: "path-segment", Triggered: true}},
		path,
	)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"analysis_results", "direct_dynamic_verification", "path-segment", "confirmed"} {
		if !strings.Contains(string(data), expected) {
			t.Errorf("analysis JSON missing %q: %s", expected, data)
		}
	}
}
