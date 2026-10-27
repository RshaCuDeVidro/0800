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

func TestPartialDocumentAndLoadResume(t *testing.T) {
	st := scan.NewStore([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, nil)
	st.PortOpen("10.0.0.1", 21)
	st.SetFTP("10.0.0.1", &scan.FTPView{Port: 21, Banner: "hi", AnonOK: true, Code: 230})
	st.AddFinding("10.0.0.1", scan.Finding{Port: 21, Proto: "ftp", Kind: "ftp-anon", Label: "anonymous login", Severity: scan.SevHigh})
	st.Finish("10.0.0.1", time.Millisecond)
	// 10.0.0.3 is mid-probe: it has a partial finding but is not finished.
	st.PortOpen("10.0.0.3", 445)
	st.AddFinding("10.0.0.3", scan.Finding{Port: 445, Proto: "smb", Kind: "smb-null", Label: "null session", Severity: scan.SevCritical})
	st.Refresh()

	doc := Build(st.Snapshot(), "t")
	if !doc.Partial || len(doc.Pending) != 2 {
		t.Fatalf("partial=%v pending=%v, want the two unfinished hosts", doc.Partial, doc.Pending)
	}
	path := filepath.Join(t.TempDir(), "p.json")
	if err := WriteJSON(path, doc); err != nil {
		t.Fatal(err)
	}

	rs, err := LoadResume(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Targets) != 2 {
		t.Errorf("targets = %v", rs.Targets)
	}
	if len(rs.Done) != 1 || rs.Done[0].IP != "10.0.0.1" {
		t.Fatalf("done = %+v: the mid-probe host must be re-scanned, not restored", rs.Done)
	}
	if rs.Done[0].FTP == nil || !rs.Done[0].FTP.AnonOK || rs.Done[0].Findings[0].Severity != scan.SevHigh {
		t.Errorf("the restored host lost data in the JSON round trip: %+v", rs.Done[0])
	}
}

func TestLoadResumeRejectsCompleteAndForeignFiles(t *testing.T) {
	dir := t.TempDir()
	full := filepath.Join(dir, "full.json")
	if err := WriteJSON(full, Build(sampleSnapshot(), "t")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadResume(full); err == nil || !strings.Contains(err.Error(), "nothing to resume") {
		t.Errorf("a complete report: %v", err)
	}

	foreign := filepath.Join(dir, "other.json")
	if err := os.WriteFile(foreign, []byte(`{"tool":"nmap"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDocument(foreign); err == nil {
		t.Error("a report from another tool must be refused")
	}
	garbage := filepath.Join(dir, "garbage.json")
	_ = os.WriteFile(garbage, []byte("not json"), 0o644)
	if _, err := LoadDocument(garbage); err == nil {
		t.Error("garbage must be refused")
	}
}

func finding(ip string, port int, proto, kind string, sev scan.Severity) scan.Finding {
	return scan.Finding{Port: port, Proto: proto, Kind: kind, Label: kind, Severity: sev}
}

func docWith(findings map[string][]scan.Finding) Document {
	var doc Document
	doc.Tool = "0800"
	for ip, fs := range findings {
		doc.Hosts = append(doc.Hosts, &scan.HostView{IP: ip, Findings: fs})
	}
	return doc
}

func TestDiff(t *testing.T) {
	old := docWith(map[string][]scan.Finding{
		"10.0.0.1": {finding("10.0.0.1", 445, "smb", "smb-null", scan.SevCritical), finding("10.0.0.1", 445, "smb", "smb1", scan.SevLow)},
		"10.0.0.2": {finding("10.0.0.2", 2049, "nfs", "nfs-read", scan.SevHigh)},
	})
	cur := docWith(map[string][]scan.Finding{
		"10.0.0.1": {finding("10.0.0.1", 445, "smb", "smb-null", scan.SevCritical)},
		"10.0.0.3": {finding("10.0.0.3", 21, "ftp", "ftp-anon", scan.SevHigh), finding("10.0.0.3", 6379, "redis", "redis-open", scan.SevCritical)},
	})

	d := Diff(old, cur)
	if len(d.New) != 2 || d.New[0].Kind != "redis-open" {
		t.Errorf("new = %+v, want 2 findings, most severe (redis) first", d.New)
	}
	if len(d.Resolved) != 2 || d.Resolved[0].Kind != "nfs-read" {
		t.Errorf("resolved = %+v", d.Resolved)
	}
	if d.Same != 1 {
		t.Errorf("same = %d, want 1", d.Same)
	}
	if len(d.NewHosts) != 1 || d.NewHosts[0] != "10.0.0.3" || len(d.GoneHosts) != 1 || d.GoneHosts[0] != "10.0.0.2" {
		t.Errorf("new hosts %v gone hosts %v", d.NewHosts, d.GoneHosts)
	}
	if !d.NewExposure() {
		t.Error("a new critical finding is a new exposure")
	}

	out := FormatDiff(d, "old.json", "new.json")
	for _, want := range []string{"2 new", "2 resolved", "1 unchanged", "10.0.0.3", "redis-open", "no longer exposed: 10.0.0.2"} {
		if !strings.Contains(out, want) {
			t.Errorf("diff output misses %q:\n%s", want, out)
		}
	}
}

func TestDiffLowSeverityIsNotAnExposure(t *testing.T) {
	old := docWith(nil)
	cur := docWith(map[string][]scan.Finding{"10.0.0.1": {finding("10.0.0.1", 445, "smb", "smb1", scan.SevLow)}})
	d := Diff(old, cur)
	if len(d.New) != 1 || d.NewExposure() {
		t.Errorf("a new low finding must show up but not trip the alert: %+v", d)
	}
	if out := FormatDiff(Diff(old, old), "a", "b"); !strings.Contains(out, "no change in exposure") {
		t.Errorf("identical reports: %s", out)
	}
}
