package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/RshaCuDeVidro/0800/internal/report"
	"github.com/RshaCuDeVidro/0800/internal/scan"
)

func TestParseRemap(t *testing.T) {
	svc, ports, err := parseRemap("smb=1445, ldap=1389,ftp=2121")
	if err != nil {
		t.Fatal(err)
	}
	if svc[1445] != "smb" || svc[1389] != "ldap" || svc[2121] != "ftp" {
		t.Errorf("services = %v", svc)
	}
	if !reflect.DeepEqual(ports, []int{1445, 1389, 2121}) {
		t.Errorf("ports = %v", ports)
	}
	if svc, ports, err := parseRemap("  "); err != nil || svc != nil || ports != nil {
		t.Errorf("empty spec: %v %v %v", svc, ports, err)
	}
	for _, bad := range []string{"smb", "smb=abc", "smb=0", "smb=70000", "gopher=70", "=445"} {
		if _, _, err := parseRemap(bad); err == nil {
			t.Errorf("parseRemap(%q) should fail", bad)
		}
	}
}

func partialSnapshot() *scan.Snapshot {
	st := scan.NewStore([]string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}, nil)
	st.PortOpen("10.0.0.1", 445)
	st.SetSMB("10.0.0.1", &scan.SMBView{Auth: "null", Dialect: "3.0.2", Signing: "disabled"})
	st.AddFinding("10.0.0.1", scan.Finding{Port: 445, Proto: "smb", Kind: "smb-null", Label: "null session", Severity: scan.SevCritical})
	st.Finish("10.0.0.1", time.Millisecond)
	st.Finish("10.0.0.2", time.Millisecond) // silent, finished
	// 10.0.0.3 is still pending.
	st.Refresh()
	return st.Snapshot()
}

func writeDoc(t *testing.T, name string, snap *scan.Snapshot) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := report.WriteJSON(path, report.Build(snap, "test")); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResumeTargetsMergesAndSorts(t *testing.T) {
	path := writeDoc(t, "partial.json", partialSnapshot())
	rs, err := report.LoadResume(path)
	if err != nil {
		t.Fatal(err)
	}
	ips, skip := resumeTargets(&rs)
	if !reflect.DeepEqual(ips, []string{"10.0.0.1", "10.0.0.3"}) {
		t.Errorf("targets = %v, want the finished host plus the pending one, sorted", ips)
	}
	if !skip["10.0.0.1"] || skip["10.0.0.3"] {
		t.Errorf("skip = %v: only the finished host may be skipped", skip)
	}
}

func TestResumeTargetsSortsNumerically(t *testing.T) {
	rs := &report.Resume{Targets: []string{"10.0.0.10", "10.0.0.9", "9.0.0.1"}}
	ips, _ := resumeTargets(rs)
	if !reflect.DeepEqual(ips, []string{"9.0.0.1", "10.0.0.9", "10.0.0.10"}) {
		t.Errorf("ips = %v (lexical order would put 10.0.0.10 first)", ips)
	}
}

func TestRunDiffExitSemantics(t *testing.T) {
	oldSnap := partialSnapshot()

	st := scan.NewStore([]string{"10.0.0.1", "10.0.0.2"}, nil)
	st.PortOpen("10.0.0.1", 445)
	st.AddFinding("10.0.0.1", scan.Finding{Port: 445, Proto: "smb", Kind: "smb-null", Label: "null session", Severity: scan.SevCritical})
	st.PortOpen("10.0.0.2", 21)
	st.AddFinding("10.0.0.2", scan.Finding{Port: 21, Proto: "ftp", Kind: "ftp-anon", Label: "anonymous login", Severity: scan.SevHigh})
	st.Finish("10.0.0.1", 0)
	st.Finish("10.0.0.2", 0)
	st.Refresh()

	a := writeDoc(t, "old.json", oldSnap)
	b := writeDoc(t, "new.json", st.Snapshot())

	if err := runDiff([]string{a, b}); !errors.Is(err, errNewExposure) {
		t.Errorf("a new high finding must give errNewExposure, got %v", err)
	}
	if err := runDiff([]string{b, b}); err != nil {
		t.Errorf("identical reports: %v", err)
	}
	// Going backwards only resolves things: no alert.
	if err := runDiff([]string{b, a}); err != nil {
		t.Errorf("resolved-only diff must not alert: %v", err)
	}
	if err := runDiff([]string{a}); err == nil {
		t.Error("--diff needs two files")
	}
	if err := runDiff([]string{a, filepath.Join(t.TempDir(), "missing.json")}); err == nil {
		t.Error("a missing report must be an error")
	}
}

func TestWriteReportsSkipsEmptyPaths(t *testing.T) {
	dir := t.TempDir()
	snap := partialSnapshot()
	js, html := filepath.Join(dir, "r.json"), filepath.Join(dir, "r.html")

	if err := writeReportsAnnounce(snap, "t", js, "", html, false); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{js, html} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("%s not written: %v", p, err)
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Errorf("only the requested formats may be written, got %d files", len(entries))
	}
	if err := writeReportsAnnounce(snap, "t", filepath.Join(dir, "no", "such", "dir", "r.json"), "", "", false); err == nil {
		t.Error("an unwritable path must surface as an error")
	}
}

func TestCheckpointerWritesAndStops(t *testing.T) {
	eng := scan.New(scan.Config{Targets: []string{"127.0.0.1"}, Ports: []int{1}})
	path := filepath.Join(t.TempDir(), "cp.json")

	ctx, cancel := context.WithCancel(context.Background())
	stop := startCheckpointer(ctx, eng, "t", 10*time.Millisecond, path, "", "")

	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the checkpointer never wrote a partial report")
		}
		time.Sleep(5 * time.Millisecond)
	}
	doc, err := report.LoadDocument(path)
	if err != nil {
		t.Fatal(err)
	}
	if !doc.Partial || len(doc.Pending) != 1 {
		t.Errorf("a checkpoint of an unfinished scan must be partial with its pending targets: %+v", doc)
	}

	// Cancel first, then stop: this is the order main uses, and stop must not
	// hang waiting for a goroutine that was never told to exit.
	cancel()
	finished := make(chan struct{})
	go func() { stop(); close(finished) }()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("stop() deadlocked")
	}
}

func TestCheckpointerDisabled(t *testing.T) {
	eng := scan.New(scan.Config{Targets: []string{"127.0.0.1"}, Ports: []int{1}})
	for name, stop := range map[string]func(){
		"interval 0": startCheckpointer(context.Background(), eng, "t", 0, "x.json", "", ""),
		"no paths":   startCheckpointer(context.Background(), eng, "t", time.Second, "", "", ""),
	} {
		done := make(chan struct{})
		go func() { stop(); close(done) }()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Errorf("%s: the no-op stop must return immediately", name)
		}
	}
}
