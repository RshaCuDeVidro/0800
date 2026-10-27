package ui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RshaCuDeVidro/0800/internal/scan"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "0800-ui-test")
	if err == nil {
		prefsDirOverride = dir
		defer os.RemoveAll(dir)
	}
	os.Exit(m.Run())
}

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

// TestFTPHostOpensInfoPanel covers the gap where an FTP-only host (no SMB,
// NFS or DB) used to fall through to an empty panel on enter: FTP never
// opens a data channel, so there is nothing to browse, but the login result
// must still be shown instead of a blank screen.
func TestFTPHostOpensInfoPanel(t *testing.T) {
	m := NewDemo(120, 40, "main")
	m.filter = "" // make sure the FTP demo host is in the visible list
	m.allHosts = true
	m.refresh()

	idx := indexOf(m.hosts, "198.51.100.77")
	if m.hosts[idx].IP != "198.51.100.77" {
		t.Fatalf("FTP demo host not found in host list")
	}
	m.cursor = idx

	m.Update(press("enter"))
	if m.browser.mode != modeInfo {
		t.Fatalf("mode = %v, want modeInfo", m.browser.mode)
	}
	if m.browser.proto != "ftp" {
		t.Errorf("proto = %q, want ftp", m.browser.proto)
	}
	view := m.View()
	if !strings.Contains(view, "anonymous login accepted") {
		t.Errorf("view missing the FTP login result: %s", view)
	}
}

// TestFTPCountedInOverviews guards the dashboard/summary protocol breakdown,
// which lists protocols by a hardcoded set of keys: adding a protocol to the
// scanner is easy to forget to also add there.
func TestFTPCountedInOverviews(t *testing.T) {
	m := NewDemo(120, 40, "main")
	if n := m.snap.ByProto["ftp"]; n != 1 {
		t.Fatalf("ByProto[ftp] = %d, want 1", n)
	}

	m.Update(press("s"))
	if !strings.Contains(m.View(), "ftp") {
		t.Error("summary view should break down the ftp protocol count")
	}
	m.Update(press("s"))

	dash := renderDashboard(m.snap, 100, 30, false, false)
	if !strings.Contains(dash, "ftp") {
		t.Error("dashboard view should break down the ftp protocol count")
	}
}

// TestFTPDetailsLine guards the "tab" details pane, which lists protocols
// section by section: FTP must get the same treatment as SMB/LDAP/NFS.
func TestFTPDetailsLine(t *testing.T) {
	host := &scan.HostView{
		IP:  "198.51.100.77",
		FTP: &scan.FTPView{Port: 21, Banner: "ProFTPD ready", AnonOK: true, Code: 230, Message: "ok"},
	}
	lines := detailsLines(host, 80)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "ProFTPD ready") {
		t.Errorf("details missing the ftp banner: %s", joined)
	}
	if !strings.Contains(joined, "anonymous login accepted") {
		t.Errorf("details missing the anonymous-login call-out: %s", joined)
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

// TestDetailsFromBrowserReturnsToBrowser guards a real regression: opening
// the details overlay (tab) while browsing a directory, then closing it
// (esc/h), used to drop focus to the host list, where the next "enter"
// called openHost() and silently reset the whole browser session — closing
// the remote connection and discarding the directory the user had navigated
// into. Closing the overlay must instead return to that same session.
func TestDetailsFromBrowserReturnsToBrowser(t *testing.T) {
	m := NewDemo(120, 40, "browser")
	if m.browser.mode != modeDir {
		t.Fatalf("precondition: mode = %v, want modeDir", m.browser.mode)
	}
	wantPath := m.browser.path
	wantEntries := len(m.browser.entries)
	m.focus = 1

	m.Update(press("tab"))
	if !m.showDetails || m.focus != 1 {
		t.Fatalf("after tab: showDetails=%v focus=%d, want true/1", m.showDetails, m.focus)
	}

	m.Update(press("esc"))
	if m.showDetails {
		t.Fatal("esc should close the details overlay")
	}
	if m.focus != 1 {
		t.Errorf("focus = %d, want 1 (back to the browser, not the host list)", m.focus)
	}
	if m.browser.mode != modeDir || m.browser.path != wantPath || len(m.browser.entries) != wantEntries {
		t.Errorf("browser session was reset: mode=%v path=%q entries=%d",
			m.browser.mode, m.browser.path, len(m.browser.entries))
	}
}

// TestDetailsFromEmptyBrowserReturnsToHostList is the other half of the fix
// above: a host with nothing to browse has no browser session to return to,
// so closing its details overlay still goes back to the host list.
func TestDetailsFromEmptyBrowserReturnsToHostList(t *testing.T) {
	m := NewDemo(120, 40, "main")
	// 192.0.2.90 is the demo host with a closed SMB port and nothing
	// browsable (modeEmpty once opened).
	m.cursor = indexOf(m.hosts, "192.0.2.90")
	m.Update(press("enter"))
	if m.browser.mode != modeEmpty {
		t.Fatalf("precondition: mode = %v, want modeEmpty", m.browser.mode)
	}
	if !m.showDetails {
		t.Fatal("opening a host with nothing to browse should show its details")
	}

	m.Update(press("esc"))
	if m.focus != 0 {
		t.Errorf("focus = %d, want 0 (nothing to go back to)", m.focus)
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

// TestDestPathCollisionOnExtensionlessFileKeepsIPIntact reproduces a real
// bug: the collision suffix used to be computed by splitting the *whole*
// path on its last ".", not just the filename. A host IP like 192.0.2.24 has
// dots too, so downloading a second, extensionless file (no dot of its own)
// put the "(1)" suffix in the middle of the IP address instead of after the
// filename.
func TestDestPathCollisionOnExtensionlessFileKeepsIPIntact(t *testing.T) {
	m := NewDemo(120, 40, "browser")
	m.cfg.LootDir = t.TempDir()
	m.browser.hostIP = "192.0.2.24"
	m.browser.share = "public"
	m.browser.path = ""

	first := m.destPath("README") // no extension: the bug needs this
	if err := writeFile(first); err != nil {
		t.Fatal(err)
	}

	second := m.destPath("README")
	if second == first {
		t.Fatal("expected a collision suffix")
	}
	if !strings.Contains(second, "192.0.2.24") {
		t.Errorf("host IP was mangled by the collision suffix: %s", second)
	}
	if !strings.HasSuffix(filepath.Base(second), ")") {
		t.Errorf("collision suffix should be on the filename, got %s", second)
	}
	if filepath.Dir(second) != filepath.Dir(first) {
		t.Errorf("collision changed the directory: %s vs %s", filepath.Dir(second), filepath.Dir(first))
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

func BenchmarkRefreshBigList(b *testing.B) {
	hosts := make([]string, 0, 65000)
	for i := 0; i < 65000; i++ {
		hosts = append(hosts, fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256))
	}
	st := scan.NewStore(hosts, nil)
	for _, ip := range hosts {
		st.PortOpen(ip, 445)
	}
	st.Refresh()
	m := New(Config{Store: st, Width: 120, Height: 40})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.refresh()
	}
}

func TestPrettyFS(t *testing.T) {
	cases := map[string]string{
		"smb: STATUS_INVALID_PARAMETER": "this share cannot be listed as a file tree (invalid parameter)",
		"STATUS_ACCESS_DENIED":          "access denied by the server",
		"read tcp: i/o timeout":         "server stopped answering",
	}
	for in, want := range cases {
		if got := prettyFS(in); got != want {
			t.Errorf("prettyFS(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPipeShareOpens(t *testing.T) {
	b := &browser{
		mode:   modeShares,
		hostIP: "192.0.2.1",
		auth:   "null",
		shares: []shareItem{{Name: "IPC$", Type: "pipe"}},
	}
	if cmd := b.open(); cmd == nil {
		t.Fatal("IPC$ must be openable (it lists named pipes)")
	}
	if !b.loading {
		t.Error("expected the share to start loading")
	}
}
