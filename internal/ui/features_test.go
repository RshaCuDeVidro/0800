package ui

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/RshaCuDeVidro/0800/internal/report"
	"github.com/RshaCuDeVidro/0800/internal/scan"
)

// memFS is an in-memory remoteFS: tree maps a directory to its entries, data
// maps a file path to its content. A directory missing from tree is denied.
type memFS struct {
	tree  map[string][]remoteEntry
	data  map[string]string
	opens atomic.Int32
}

func (f *memFS) List(_ context.Context, path string) ([]remoteEntry, error) {
	es, ok := f.tree[path]
	if !ok {
		return nil, errors.New("smb: STATUS_ACCESS_DENIED")
	}
	return append([]remoteEntry(nil), es...), nil
}

func (f *memFS) Open(_ context.Context, path string) (io.ReadCloser, int64, error) {
	f.opens.Add(1)
	d, ok := f.data[path]
	if !ok {
		return nil, 0, errors.New("smb: STATUS_OBJECT_NAME_NOT_FOUND")
	}
	return io.NopCloser(strings.NewReader(d)), int64(len(d)), nil
}

func (f *memFS) Close() error { return nil }

// sampleTree: root has a file, a sub-directory and an unreadable directory.
//
//	/a.txt
//	/docs/b.txt, /docs/deep/c.txt
//	/locked/        (listing denied)
func sampleTree() *memFS {
	return &memFS{
		tree: map[string][]remoteEntry{
			"":          {{Name: "a.txt", Size: 5}, {Name: "docs", Dir: true}, {Name: "locked", Dir: true}},
			"docs":      {{Name: "b.txt", Size: 5}, {Name: "deep", Dir: true}},
			"docs/deep": {{Name: "c.txt", Size: 5}},
		},
		data: map[string]string{
			"a.txt":           "alpha",
			"docs/b.txt":      "bravo",
			"docs/deep/c.txt": "charl",
		},
	}
}

// browserModel is a demo model parked in a directory backed by fs.
func browserModel(t *testing.T, fs remoteFS, entries []remoteEntry) *Model {
	t.Helper()
	m := NewDemo(120, 40, "browser")
	m.cfg.LootDir = t.TempDir()
	b := &m.browser
	b.fs = fs
	b.path = ""
	b.all = entries
	b.rebuild()
	b.cursor = 0
	m.focus = 1
	return m
}

func run(t *testing.T, m *Model, cmd tea.Cmd) {
	t.Helper()
	if cmd == nil {
		return
	}
	switch msg := cmd().(type) {
	case nil:
	case tea.BatchMsg:
		for _, c := range msg {
			run(t, m, c)
		}
	default:
		m.Update(msg)
	}
}

// --- preview ----------------------------------------------------------------

func TestLooksBinary(t *testing.T) {
	cases := map[string]struct {
		in   []byte
		want bool
	}{
		"ascii":       {[]byte("hello\nworld\n"), false},
		"utf8":        {[]byte("olá, ação\n"), false},
		"empty":       {nil, false},
		"nul byte":    {[]byte("MZ\x00\x01"), true},
		"invalid":     {[]byte{0xff, 0xfe, 0xfd, 0xfc}, true},
		"cut rune":    {append([]byte("texto "), 0xc3), false}, // multi-byte rune split by the limit
		"mostly ctrl": {[]byte("\x01\x02\x03\x04\x05\x06\x07\x08ab"), true},
	}
	for name, c := range cases {
		if got := looksBinary(c.in); got != c.want {
			t.Errorf("%s: looksBinary = %v, want %v", name, got, c.want)
		}
	}
}

// A hostile file must not be able to drive the terminal through the preview.
func TestPreviewNeutralisesEscapeSequences(t *testing.T) {
	data := []byte("normal\n\x1b]0;pwned\x07\x1b[2Jboom\ttab\n")
	p := newPreview(previewMsg{name: "evil.txt", size: int64(len(data)), data: data})
	if p.binary {
		t.Fatal("this file is text")
	}
	joined := strings.Join(p.lines, "\n")
	for _, bad := range []string{"\x1b", "\x07"} {
		if strings.Contains(joined, bad) {
			t.Errorf("preview kept control byte %q: %q", bad, joined)
		}
	}
	if !strings.Contains(joined, "boom") || !strings.Contains(joined, "tab") {
		t.Errorf("visible text lost: %q", joined)
	}
}

func TestHexDump(t *testing.T) {
	lines := hexDump([]byte("0123456789ABCDEFxyz\x00"))
	if len(lines) != 2 {
		t.Fatalf("lines = %d, want 2: %q", len(lines), lines)
	}
	if !strings.HasPrefix(lines[0], "00000000  30 31 32 33") || !strings.HasSuffix(lines[0], "|0123456789ABCDEF|") {
		t.Errorf("first row = %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "00000010  78 79 7a 00") || !strings.HasSuffix(lines[1], "|xyz.|") {
		t.Errorf("second row = %q", lines[1])
	}
}

func TestPreviewTruncatedAndErrors(t *testing.T) {
	p := newPreview(previewMsg{name: "big.log", size: 1 << 20, data: []byte("line\n")})
	if !p.trunc {
		t.Error("a file larger than what was read must be marked truncated")
	}
	if e := newPreview(previewMsg{name: "x", err: errors.New("smb: STATUS_ACCESS_DENIED")}); e.err == "" {
		t.Error("an error must reach the overlay")
	}
}

func TestPreviewFlow(t *testing.T) {
	fs := sampleTree()
	m := browserModel(t, fs, fs.tree[""])
	m.browser.cursor = 0 // a.txt

	_, cmd := m.Update(press("p"))
	if m.preview == nil || !m.preview.loading {
		t.Fatal("p should open a loading preview")
	}
	run(t, m, cmd)
	if m.preview == nil || m.preview.loading || m.preview.err != "" {
		t.Fatalf("preview did not load: %+v", m.preview)
	}
	if v := m.View(); !strings.Contains(v, "alpha") || !strings.Contains(v, "preview") {
		t.Errorf("view does not show the file:\n%s", v)
	}

	m.Update(press("esc"))
	if m.preview != nil {
		t.Error("esc should close the preview")
	}
}

func TestPreviewIgnoresDirectories(t *testing.T) {
	fs := sampleTree()
	m := browserModel(t, fs, fs.tree[""])
	m.browser.cursor = 1 // docs/
	if _, cmd := m.Update(press("p")); cmd != nil || m.preview != nil {
		t.Error("previewing a directory must do nothing")
	}
}

// --- recursive download ------------------------------------------------------

func TestDownloadTree(t *testing.T) {
	fs := sampleTree()
	dest := t.TempDir()
	st := &downloadState{}

	res := downloadTree(context.Background(), fs, "", dest, st)

	if res.files != 3 {
		t.Errorf("files = %d, want 3", res.files)
	}
	if res.skipped != 1 || !strings.Contains(res.note, "access denied") {
		t.Errorf("the unreadable directory should be skipped and explained: %+v", res)
	}
	for rel, want := range map[string]string{
		"a.txt": "alpha", "docs/b.txt": "bravo", "docs/deep/c.txt": "charl",
	} {
		got, err := os.ReadFile(filepath.Join(dest, filepath.FromSlash(rel)))
		if err != nil || string(got) != want {
			t.Errorf("%s = %q (%v), want %q", rel, got, err, want)
		}
	}
	if st.files.Load() != 3 {
		t.Errorf("progress files = %d", st.files.Load())
	}
}

func TestDownloadTreeNeverOverwrites(t *testing.T) {
	fs := sampleTree()
	dest := t.TempDir()
	if err := os.WriteFile(filepath.Join(dest, "a.txt"), []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	downloadTree(context.Background(), fs, "", dest, &downloadState{})

	if got, _ := os.ReadFile(filepath.Join(dest, "a.txt")); string(got) != "mine" {
		t.Errorf("existing file was overwritten: %q", got)
	}
	if got, err := os.ReadFile(filepath.Join(dest, "a (1).txt")); err != nil || string(got) != "alpha" {
		t.Errorf("collision copy = %q (%v)", got, err)
	}
}

func TestDownloadTreeCancel(t *testing.T) {
	fs := sampleTree()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := downloadTree(ctx, fs, "", t.TempDir(), &downloadState{})
	if res.files != 0 || res.note != "cancelled" {
		t.Errorf("a cancelled download must stop at once: %+v", res)
	}
}

func TestDownloadTreeDepthLimit(t *testing.T) {
	fs := &memFS{tree: map[string][]remoteEntry{}, data: map[string]string{}}
	path := ""
	for i := 0; i <= treeMaxDepth+3; i++ {
		fs.tree[path] = []remoteEntry{{Name: "d", Dir: true}}
		path = joinRemote(path, "d")
	}
	res := downloadTree(context.Background(), fs, "", t.TempDir(), &downloadState{})
	if res.skipped == 0 || !strings.Contains(res.note, "levels") {
		t.Errorf("a runaway directory chain must hit the depth limit: %+v", res)
	}
}

func TestDownloadDirFromModel(t *testing.T) {
	fs := sampleTree()
	m := browserModel(t, fs, fs.tree[""])
	m.browser.hostIP, m.browser.share = "192.0.2.24", "public"
	m.browser.cursor = 1 // docs/ (index 0 is a.txt: no ".." at the root)

	_, cmd := m.Update(press("D"))
	if m.dl == nil || !m.dl.tree {
		t.Fatal("D should start a recursive download")
	}
	// The status line shows the transfer and how to stop it.
	if s := m.statusLine(); !strings.Contains(s, "docs/") || !strings.Contains(s, "cancel") {
		t.Errorf("status line = %q", s)
	}
	run(t, m, cmd)
	if m.dl != nil {
		t.Fatal("download should be finished")
	}
	want := filepath.Join(m.cfg.LootDir, "192.0.2.24", "public", "docs", "deep", "c.txt")
	if got, err := os.ReadFile(want); err != nil || string(got) != "charl" {
		t.Errorf("%s = %q (%v)", want, got, err)
	}
}

func TestSecondDownloadIsRefused(t *testing.T) {
	fs := sampleTree()
	m := browserModel(t, fs, fs.tree[""])
	m.dl = &downloadState{name: "busy"}
	if _, cmd := m.Update(press("D")); cmd != nil {
		t.Error("a second recursive download must not start while one runs")
	}
	if _, cmd := m.Update(press("g")); cmd != nil {
		t.Error("a second file download must not start while one runs")
	}
}

// Opening another host (or leaving the share) closes the remote session; doing
// that under a running transfer used to kill it with a "closed connection".
func TestNavigationBlockedWhileDownloading(t *testing.T) {
	m := NewDemo(120, 40, "main")
	m.dl = &downloadState{name: "busy"}
	m.focus = 0
	if cmd := m.openHost(); cmd != nil || m.browser.mode != modeEmpty {
		t.Errorf("openHost must refuse while a download runs (mode=%v)", m.browser.mode)
	}
	if !strings.Contains(m.toastText, "download") {
		t.Errorf("the refusal should be explained: %q", m.toastText)
	}
}

func TestCancelKeyStopsDownload(t *testing.T) {
	m := NewDemo(120, 40, "main")
	ctx, cancel := context.WithCancel(context.Background())
	m.dl = &downloadState{name: "x", cancel: cancel}
	m.Update(press("c"))
	if ctx.Err() == nil {
		t.Error("c should cancel the running download")
	}
}

// sanitizeName("") is "_": an empty path used to put share-root downloads in
// <ip>/<share>/_/<file>.
func TestLootPartsSkipsEmptySegments(t *testing.T) {
	m := NewDemo(120, 40, "browser")
	m.cfg.LootDir = "loot"
	m.browser.hostIP, m.browser.share = "192.0.2.24", "public"
	if got := filepath.Join(m.lootParts("")...); got != filepath.Join("loot", "192.0.2.24", "public") {
		t.Errorf("share-root parts = %q", got)
	}
	if got := filepath.Join(m.lootParts("a//b")...); got != filepath.Join("loot", "192.0.2.24", "public", "a", "b") {
		t.Errorf("nested parts = %q", got)
	}
	m.cfg.Flat = true
	if got := filepath.Join(m.lootParts("a/b")...); got != "loot" {
		t.Errorf("flat parts = %q", got)
	}
}

// --- directory filter --------------------------------------------------------

func TestBrowserFilter(t *testing.T) {
	m := NewDemo(120, 40, "browser")
	b := &m.browser
	b.path = "financeiro/2026"
	b.all = []remoteEntry{{Name: "contratos", Dir: true}, {Name: "senhas.txt"}, {Name: "notas.xml"}}
	b.rebuild()
	if len(b.entries) != 4 { // three entries + ".."
		t.Fatalf("entries = %d, want 4", len(b.entries))
	}

	b.setFilter("SENHAS")
	if len(b.entries) != 2 || b.entries[1].Name != "senhas.txt" {
		t.Errorf("filtered entries = %+v (want the parent row and senhas.txt, case-insensitive)", b.entries)
	}
	if !b.entries[0].up {
		t.Error("the .. entry must survive a filter")
	}

	// Navigating clears it: a filter belongs to one directory.
	b.applyListed(listedMsg{path: "financeiro", entries: []remoteEntry{{Name: "x"}}})
	if b.filter != "" || len(b.entries) != 2 {
		t.Errorf("filter survived navigation: %q %+v", b.filter, b.entries)
	}
}

func TestSlashFiltersTheTreeWhenItHasFocus(t *testing.T) {
	fs := sampleTree()
	m := browserModel(t, fs, fs.tree[""])
	m.focus = 1

	m.Update(press("/"))
	if !m.filtering || !m.filterRemote {
		t.Fatalf("/ with the tree focused should filter the tree (filtering=%v remote=%v)", m.filtering, m.filterRemote)
	}
	for _, r := range "doc" {
		m.Update(press(string(r)))
	}
	if len(m.browser.entries) != 1 || m.browser.entries[0].Name != "docs" {
		t.Errorf("tree entries = %+v", m.browser.entries)
	}
	if m.filter != "" {
		t.Errorf("the host filter must be untouched, got %q", m.filter)
	}
	m.Update(press("esc"))
	if m.browser.filter != "" || len(m.browser.entries) != 3 {
		t.Errorf("esc should clear the tree filter: %q %d", m.browser.filter, len(m.browser.entries))
	}
}

func TestSlashFiltersHostsWhenListHasFocus(t *testing.T) {
	m := NewDemo(120, 40, "main")
	m.focus = 0
	m.Update(press("/"))
	if !m.filtering || m.filterRemote {
		t.Fatal("/ on the host list must filter hosts")
	}
}

// --- severity floor, marks, copy --------------------------------------------

func TestSeverityFloorCycle(t *testing.T) {
	m := NewDemo(120, 40, "main")
	all := len(m.hosts)

	seen := []scan.Severity{}
	for i := 0; i < 3; i++ {
		m.Update(press("v"))
		seen = append(seen, m.minSev)
		for _, h := range m.hosts {
			if h.Sev < m.minSev {
				t.Errorf("floor %v let %s (%v) through", m.minSev, h.IP, h.Sev)
			}
		}
	}
	if seen[0] != scan.SevMedium || seen[1] != scan.SevHigh || seen[2] != scan.SevCritical {
		t.Errorf("cycle = %v", seen)
	}
	if len(m.hosts) >= all {
		t.Errorf("critical-only should hide hosts: %d >= %d", len(m.hosts), all)
	}
	if !strings.Contains(m.listTitle(), "crit") {
		t.Errorf("title = %q", m.listTitle())
	}

	m.Update(press("v")) // wraps back to everything
	if m.minSev != scan.SevInfo || len(m.hosts) != all {
		t.Errorf("wrap: floor=%v hosts=%d want %d", m.minSev, len(m.hosts), all)
	}
}

func TestMarkAndExportMarked(t *testing.T) {
	t.Chdir(t.TempDir())
	m := NewDemo(120, 40, "main")
	m.focus = 0

	if _, cmd := m.Update(press("E")); cmd != nil {
		t.Error("exporting with nothing marked must not write anything")
	}

	m.cursor = indexOf(m.hosts, "192.0.2.10")
	m.Update(press("m"))
	if !m.marks["192.0.2.10"] || !strings.Contains(m.listTitle(), "★1") {
		t.Fatalf("marks = %v title = %q", m.marks, m.listTitle())
	}
	if row := m.hostRow(m.hosts[m.cursor], false, 60); !strings.Contains(row, "★") {
		t.Errorf("marked host row has no star: %q", row)
	}

	_, cmd := m.Update(press("E"))
	run(t, m, cmd)
	for _, f := range []string{"0800-marked.json", "0800-marked.md", "0800-marked.html"} {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if !strings.Contains(string(data), "192.0.2.10") {
			t.Errorf("%s misses the marked host", f)
		}
		if strings.Contains(string(data), "198.51.100.42") {
			t.Errorf("%s contains an unmarked host", f)
		}
	}

	m.Update(press("m")) // toggles off
	if m.marks["192.0.2.10"] {
		t.Error("m again should unmark")
	}
}

func TestBuildFilteredStats(t *testing.T) {
	m := NewDemo(120, 40, "main")
	doc := report.BuildFiltered(m.snap, "t", func(h *scan.HostView) bool {
		return h.IP == "192.0.2.10" || h.IP == "192.0.2.90"
	})
	if doc.Stats.Targets != 2 || len(doc.Hosts) != 2 {
		t.Errorf("subset = %+v hosts=%d", doc.Stats, len(doc.Hosts))
	}
	if doc.Stats.Exposed != 1 {
		t.Errorf("exposed = %d, want 1 (only the DC has medium+ findings)", doc.Stats.Exposed)
	}
}

func TestCopyHostAndPath(t *testing.T) {
	var got []string
	old := clipboardWrite
	clipboardWrite = func(s string) error { got = append(got, s); return nil }
	defer func() { clipboardWrite = old }()

	m := NewDemo(120, 40, "main")
	m.focus = 0
	m.cursor = indexOf(m.hosts, "192.0.2.24")
	_, cmd := m.Update(press("y"))
	run(t, m, cmd)

	fs := sampleTree()
	m2 := browserModel(t, fs, fs.tree[""])
	m2.browser.hostIP, m2.browser.share, m2.browser.proto = "192.0.2.24", "public", "smb"
	m2.browser.cursor = 0
	_, cmd = m2.Update(press("y"))
	run(t, m2, cmd)

	if len(got) != 2 || got[0] != "192.0.2.24" || got[1] != `\\192.0.2.24\public\a.txt` {
		t.Errorf("clipboard = %q", got)
	}
}

// --- mouse -------------------------------------------------------------------

func wheel(dir tea.MouseButton, x, y int) tea.MouseMsg {
	return tea.MouseMsg{X: x, Y: y, Button: dir, Action: tea.MouseActionPress}
}

func TestMouseWheelAndClick(t *testing.T) {
	m := NewDemo(120, 40, "main")
	m.focus = 0
	m.cursor = 0

	m.Update(wheel(tea.MouseButtonWheelDown, 5, 10))
	if m.cursor != 3 {
		t.Errorf("wheel down moved the cursor to %d, want 3", m.cursor)
	}
	m.Update(wheel(tea.MouseButtonWheelUp, 5, 10))
	if m.cursor != 0 {
		t.Errorf("wheel up moved the cursor to %d, want 0", m.cursor)
	}

	// Click the third row.
	m.Update(tea.MouseMsg{X: 5, Y: hostListTop + 2, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
	if m.cursor != 2 || m.focus != 0 {
		t.Errorf("click selected %d (focus %d), want 2/0", m.cursor, m.focus)
	}

	// Releases and clicks outside the list are ignored.
	m.Update(tea.MouseMsg{X: 5, Y: hostListTop + 5, Button: tea.MouseButtonLeft, Action: tea.MouseActionRelease})
	m.Update(tea.MouseMsg{X: 5, Y: 0, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
	if m.cursor != 2 {
		t.Errorf("cursor = %d after ignored events", m.cursor)
	}
}

func TestMouseSecondClickOpensHost(t *testing.T) {
	m := NewDemo(120, 40, "main")
	m.focus = 0
	row := 1
	click := tea.MouseMsg{X: 5, Y: hostListTop + row, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress}
	m.Update(click)
	if m.focus != 0 {
		t.Fatal("the first click only selects")
	}
	m.Update(click)
	if m.focus != 1 {
		t.Errorf("the second click on the selected host should open it (focus=%d)", m.focus)
	}
}

func TestMouseWheelScrollsTreeAndPreview(t *testing.T) {
	m := NewDemo(120, 40, "browser")
	m.focus = 1
	start := m.browser.cursor
	m.Update(wheel(tea.MouseButtonWheelDown, 100, 12))
	if m.browser.cursor <= start {
		t.Errorf("wheel in the right pane should move the tree cursor (%d -> %d)", start, m.browser.cursor)
	}

	long := strings.Repeat("line\n", 200)
	m.preview = newPreview(previewMsg{name: "f", size: int64(len(long)), data: []byte(long)})
	m.Update(wheel(tea.MouseButtonWheelDown, 100, 12))
	if m.preview.off == 0 {
		t.Error("wheel over a preview should scroll it")
	}
}

// --- header sparkline ---------------------------------------------------------

func TestSparkline(t *testing.T) {
	if got := sparkline([]float64{0, 1, 2, 4, 8}, 10); len([]rune(got)) != 5 || got[:3] != "▁" {
		t.Errorf("sparkline = %q", got)
	}
	got := []rune(sparkline([]float64{0, 8}, 10))
	if got[0] != '▁' || got[1] != '█' {
		t.Errorf("min/max glyphs = %q", string(got))
	}
	if got := []rune(sparkline([]float64{1, 2, 3, 4, 5, 6}, 3)); len(got) != 3 {
		t.Errorf("must keep only the newest width values: %q", string(got))
	}
	if sparkline(nil, 5) != "" || sparkline([]float64{1}, 0) != "" {
		t.Error("empty input / zero width must render nothing")
	}
	if got := sparkline([]float64{0, 0, 0}, 5); strings.ContainsAny(got, "▂▃▄▅▆▇█") {
		t.Errorf("an idle scan must render a flat line, got %q", got)
	}
}

// Everything above must keep fitting the terminal at every size.
func TestNewViewsFitEverySize(t *testing.T) {
	fs := sampleTree()
	long := strings.Repeat("a line of text that is quite long and keeps going and going\n", 80)
	for _, s := range [][2]int{{62, 17}, {78, 24}, {100, 30}, {120, 40}, {200, 60}} {
		m := browserModel(t, fs, fs.tree[""])
		m.Update(tea.WindowSizeMsg{Width: s[0], Height: s[1]})
		m.preview = newPreview(previewMsg{name: "f.txt", size: int64(len(long)), data: []byte(long)})
		m.marks = map[string]bool{"192.0.2.10": true}
		m.minSev = scan.SevHigh
		m.rateHist = []float64{1, 3, 2, 5, 4, 9}
		m.dl = &downloadState{name: "docs/", tree: true}
		v := m.View()
		lines := strings.Split(v, "\n")
		if len(lines) != s[1] {
			t.Errorf("%dx%d: height = %d", s[0], s[1], len(lines))
		}
		for i, l := range lines {
			if w := lipgloss.Width(l); w > s[0] {
				t.Errorf("%dx%d: line %d is %d cells wide", s[0], s[1], i, w)
				break
			}
		}
	}
}

// A scan stopped early used to render as "100% done · scan complete".
func TestStoppedScanIsNotShownAsComplete(t *testing.T) {
	st := scan.NewStore([]string{"192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4"}, nil)
	st.PortOpen("192.0.2.1", 445)
	st.Finish("192.0.2.1", time.Millisecond)
	st.Complete() // the engine returned, but three hosts were never scanned
	st.Refresh()

	m := New(Config{Store: st, Width: 120, Height: 40})
	v := m.View()
	if !strings.Contains(v, "stopped") || !strings.Contains(v, "1/4") {
		t.Errorf("a stopped scan must say so, with how far it got:\n%s", v)
	}
	if strings.Contains(v, "scan complete") || strings.Contains(v, "100%") {
		t.Errorf("a stopped scan must not look complete:\n%s", v)
	}
}
