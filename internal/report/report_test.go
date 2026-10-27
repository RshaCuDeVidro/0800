package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RshaCuDeVidro/0800/internal/scan"
)

func sampleSnapshot() *scan.Snapshot {
	st := scan.NewStore([]string{"192.0.2.10", "192.0.2.11"}, nil)
	st.PortOpen("192.0.2.10", 445)
	st.PortOpen("192.0.2.10", 88)
	st.SetSMB("192.0.2.10", &scan.SMBView{
		Dialect: "3.0.2", Signing: "disabled", Auth: "null",
		Host: "DC01", Domain: "corp.local",
		Shares: []scan.ShareView{{Name: "SYSVOL", Type: "disk"}},
	})
	st.AddFinding("192.0.2.10", scan.Finding{
		Port: 445, Proto: "smb", Kind: "smb-null", Label: "null session",
		Severity: scan.SevCritical, Detail: "anonymous session",
		Evidence: []string{"SESSION_SETUP null -> SUCCESS"},
	})
	st.Finish("192.0.2.10", 120*time.Millisecond)
	st.Finish("192.0.2.11", 90*time.Millisecond)
	st.Refresh()
	return st.Snapshot()
}

func TestBuild(t *testing.T) {
	doc := Build(sampleSnapshot(), "test")
	if doc.Tool != "0800" || doc.Version != "test" {
		t.Errorf("header = %+v", doc)
	}
	if doc.Stats.Targets != 2 || doc.Stats.OpenPorts != 2 {
		t.Errorf("stats = %+v", doc.Stats)
	}
	if len(doc.Hosts) != 1 {
		t.Fatalf("hosts = %d", len(doc.Hosts))
	}
	if doc.Stats.Exposed != 1 {
		t.Errorf("exposed = %d", doc.Stats.Exposed)
	}
}

func TestWriteJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.json")
	if err := WriteJSON(path, Build(sampleSnapshot(), "test")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	text := string(data)
	for _, want := range []string{`"severity": "critical"`, `"null session"`, `"192.0.2.10"`, `"evidence"`} {
		if !strings.Contains(text, want) {
			t.Errorf("json missing %s", want)
		}
	}
	if strings.Contains(text, `"192.0.2.11"`) {
		t.Error("silent hosts should be omitted")
	}
}

func TestPlainLine(t *testing.T) {
	snap := sampleSnapshot()
	var host *scan.HostView
	for _, h := range snap.Hosts {
		if h.IP == "192.0.2.10" {
			host = h
		}
	}
	if host == nil {
		t.Fatal("host missing")
	}
	line := PlainLine(host)
	for _, want := range []string{"192.0.2.10", "DC01", "auth=null", "signing=disabled", "shares=1", "null session"} {
		if !strings.Contains(line, want) {
			t.Errorf("line missing %q: %s", want, line)
		}
	}
}

func TestSummary(t *testing.T) {
	s := Summary(sampleSnapshot())
	if !strings.Contains(s, "2 targets") || !strings.Contains(s, "1 findings") {
		t.Errorf("summary = %q", s)
	}
}

func TestWriteHTML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTML(path, Build(sampleSnapshot(), "test")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"<!doctype html>",
		"192.0.2.10",
		"null session",
		"sev-critical",
		"written permission to test",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("html missing %q", want)
		}
	}
	// A silent host must not appear, and the page must stay valid HTML even
	// with a hostname/banner that happens to contain markup.
	if strings.Contains(text, "192.0.2.11") {
		t.Error("silent host should be omitted")
	}
}

func TestWriteHTMLEscapesUntrustedFields(t *testing.T) {
	st := scan.NewStore([]string{"192.0.2.20"}, nil)
	st.SetSMB("192.0.2.20", &scan.SMBView{
		Auth: "null", Host: `<script>alert(1)</script>`,
		Shares: []scan.ShareView{{Name: `"><img src=x>`, Type: "disk"}},
	})
	st.AddFinding("192.0.2.20", scan.Finding{
		Port: 445, Proto: "smb", Kind: "smb-null", Label: "null session",
		Severity: scan.SevCritical, Detail: "anonymous session",
	})
	st.Refresh()

	path := filepath.Join(t.TempDir(), "escape.html")
	if err := WriteHTML(path, Build(st.Snapshot(), "test")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "<script>") {
		t.Error("untrusted host field was not HTML-escaped")
	}
}

func TestWriteMarkdown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.md")
	if err := WriteMarkdown(path, Build(sampleSnapshot(), "test")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{
		"# 0800 — null authentication report",
		"## 192.0.2.10",
		"null session",
		"SESSION_SETUP null -> SUCCESS",
		"written permission to test",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}
