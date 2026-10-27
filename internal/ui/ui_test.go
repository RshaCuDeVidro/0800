package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/rsha/0800/internal/scan"
)

func writeFile(p string) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte("x"), 0o644)
}

func press(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	case "up":
		return tea.KeyMsg{Type: tea.KeyUp}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

func TestViewRendersDashboard(t *testing.T) {
	m := NewDemo(120, 40, "main")
	v := m.View()
	for _, want := range []string{"0800", "targets", "192.0.2.10", "null auth", "q quit"} {
		if !strings.Contains(v, want) {
			t.Errorf("view missing %q", want)
		}
	}
	if got := len(strings.Split(v, "\n")); got != 40 {
		t.Errorf("height = %d, want 40", got)
	}
}

func TestViewTooSmall(t *testing.T) {
	m := NewDemo(40, 10, "main")
	if !strings.Contains(m.View(), "terminal too small") {
		t.Fatal("expected the size guard")
	}
}

func TestCursorMoves(t *testing.T) {
	m := NewDemo(120, 40, "main")
	if m.cursor != 0 {
		t.Fatalf("cursor = %d", m.cursor)
	}
	m.Update(press("j"))
	if m.cursor != 1 {
		t.Fatalf("cursor after j = %d", m.cursor)
	}
	m.Update(press("down"))
	if m.cursor != 2 {
		t.Fatalf("cursor after down = %d", m.cursor)
	}
	m.Update(press("k"))
	if m.cursor != 1 {
		t.Fatalf("cursor after k = %d", m.cursor)
	}
	for i := 0; i < 50; i++ {
		m.Update(press("j"))
	}
	if m.cursor >= len(m.hosts) {
		t.Fatalf("cursor escaped the list: %d", m.cursor)
	}
}

func TestFilter(t *testing.T) {
	m := NewDemo(120, 40, "main")
	m.Update(press("/"))
	if !m.filtering {
		t.Fatal("expected filter mode")
	}
	for _, r := range "redis" {
		m.Update(press(string(r)))
	}
	m.Update(press("enter"))
	if m.filtering {
		t.Fatal("filter mode should close on enter")
	}
	if len(m.hosts) != 1 {
		t.Fatalf("hosts = %d, want 1", len(m.hosts))
	}
	if m.hosts[0].IP != "203.0.113.9" {
		t.Errorf("host = %s", m.hosts[0].IP)
	}

	// Escape clears the filter.
	m.Update(press("/"))
	m.Update(press("esc"))
	if m.filter != "" {
		t.Errorf("filter = %q", m.filter)
	}
	if len(m.hosts) < 5 {
		t.Errorf("hosts after clear = %d", len(m.hosts))
	}
}

func TestDetailsAndHelp(t *testing.T) {
	m := NewDemo(120, 40, "main")
	m.Update(press("tab"))
	if !m.showDetails {
		t.Fatal("details should be visible")
	}
	if !strings.Contains(m.View(), "findings") {
		t.Error("details pane missing findings")
	}
	m.Update(press("tab"))
	if m.showDetails {
		t.Fatal("details should be hidden")
	}

	m.Update(press("?"))
	if !m.showHelp {
		t.Fatal("help should be visible")
	}
	if !strings.Contains(m.View(), "navigation") {
		t.Error("help pane missing content")
	}
	m.Update(press("esc"))
	if m.showHelp {
		t.Fatal("help should close")
	}
}

func TestQuit(t *testing.T) {
	m := NewDemo(120, 40, "main")
	_, cmd := m.Update(press("q"))
	if cmd == nil {
		t.Fatal("quit returned no command")
	}
	if _, ok := cmd().(tea.QuitMsg); !ok {
		t.Fatal("expected tea.QuitMsg")
	}
}

func TestBrowserNavigation(t *testing.T) {
	m := NewDemo(120, 40, "browser")
	if m.browser.mode != modeDir {
		t.Fatalf("mode = %v", m.browser.mode)
	}
	start := m.browser.cursor
	m.Update(press("j"))
	if m.browser.cursor != start+1 {
		t.Errorf("cursor = %d, want %d", m.browser.cursor, start+1)
	}
	m.Update(press("k"))
	if m.browser.cursor != start {
		t.Errorf("cursor = %d, want %d", m.browser.cursor, start)
	}
}

func TestBrowserBackFromRoot(t *testing.T) {
	m := NewDemo(120, 40, "browser")
	b := &m.browser
	b.path = ""
	b.mode = modeDir
	b.fs = demoFS{}
	b.entries = []remoteEntry{{Name: "a.txt"}}

	_, handled := b.back()
	if !handled {
		t.Fatal("back should be handled")
	}
	if b.mode != modeShares {
		t.Errorf("mode = %v, want shares", b.mode)
	}
}

func TestWithParent(t *testing.T) {
	if got := withParent("", []remoteEntry{{Name: "a"}}); len(got) != 1 {
		t.Fatalf("root should not get ..: %v", got)
	}
	got := withParent("docs", []remoteEntry{{Name: "a"}})
	if len(got) != 2 || !got[0].up || got[0].Name != ".." {
		t.Fatalf("missing ..: %+v", got)
	}
}

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"../../etc/passwd": "_.._etc_passwd",
		"a/b":              "a_b",
		`a\b`:              "a_b",
		"":                 "_",
		"..":               "_",
		"report.pdf":       "report.pdf",
	}
	for in, want := range cases {
		if got := sanitizeName(in); got != want {
			t.Errorf("sanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHumanSize(t *testing.T) {
	cases := map[int64]string{
		0:       "0 B",
		1023:    "1023 B",
		1024:    "1.0 KiB",
		1 << 20: "1.0 MiB",
		1536:    "1.5 KiB",
	}
	for in, want := range cases {
		if got := humanSize(in); got != want {
			t.Errorf("humanSize(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestDetailsRenderEmptyHost(t *testing.T) {
	h := &scan.HostView{IP: "192.0.2.1", State: scan.StateDone}
	if len(detailsLines(h, 60)) == 0 {
		t.Fatal("no lines")
	}
	if out := renderDetails(h, 70, 20, 0, false); !strings.Contains(out, "192.0.2.1") {
		t.Error("missing ip in panel")
	}
}

func TestDestPathUsesLootDir(t *testing.T) {
	m := NewDemo(120, 40, "browser")
	m.cfg.LootDir = t.TempDir()
	m.browser.hostIP = "192.0.2.24"
	m.browser.share = "public"
	m.browser.path = "financeiro/2026"

	got := m.destPath("senhas.txt")
	if !strings.Contains(got, "192.0.2.24") || !strings.Contains(got, "public") {
		t.Errorf("path = %s", got)
	}
	if !strings.HasSuffix(got, "senhas.txt") {
		t.Errorf("path = %s", got)
	}
	// A second download must not overwrite the first.
	if err := writeFile(got); err != nil {
		t.Fatal(err)
	}
	again := m.destPath("senhas.txt")
	if again == got {
		t.Error("expected a collision suffix")
	}
}

func TestViewFitsEverySize(t *testing.T) {
	sizes := [][2]int{{62, 17}, {70, 20}, {78, 24}, {80, 24}, {100, 30}, {120, 40}, {200, 60}}
	for _, s := range sizes {
		for _, variant := range []string{"main", "browser", "details", "help"} {
			m := NewDemo(s[0], s[1], variant)
			out := m.View()
			if out == "" {
				t.Fatalf("%s %dx%d: empty view", variant, s[0], s[1])
			}
			lines := strings.Split(out, "\n")
			if len(lines) > s[1] {
				t.Errorf("%s %dx%d: %d lines", variant, s[0], s[1], len(lines))
			}
			for i, ln := range lines {
				if w := lipgloss.Width(ln); w > s[0] {
					t.Errorf("%s %dx%d: line %d is %d wide", variant, s[0], s[1], i, w)
				}
			}
		}
	}
}
