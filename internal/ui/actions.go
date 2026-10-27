package ui

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/RshaCuDeVidro/0800/internal/report"
	"github.com/RshaCuDeVidro/0800/internal/scan"
)

// --- filters ----------------------------------------------------------------

// applyFilter updates whichever list the "/" prompt was opened for.
func (m *Model) applyFilter(v string) {
	if m.filterRemote {
		m.browser.setFilter(v)
		return
	}
	m.filter = v
	m.refresh()
}

// nextMinSev cycles the severity floor: everything → medium+ → high+ → critical.
func nextMinSev(s scan.Severity) scan.Severity {
	switch s {
	case scan.SevInfo, scan.SevLow:
		return scan.SevMedium
	case scan.SevMedium:
		return scan.SevHigh
	case scan.SevHigh:
		return scan.SevCritical
	}
	return scan.SevInfo
}

func minSevLabel(s scan.Severity) string {
	switch s {
	case scan.SevMedium:
		return "medium and above"
	case scan.SevHigh:
		return "high and above"
	case scan.SevCritical:
		return "critical only"
	}
	return "every host"
}

// minSevTag is the short form shown in the list title.
func minSevTag(s scan.Severity) string {
	switch s {
	case scan.SevMedium:
		return "≥med"
	case scan.SevHigh:
		return "≥high"
	case scan.SevCritical:
		return "crit"
	}
	return ""
}

// --- clipboard --------------------------------------------------------------

// clipboardWrite copies text with an OSC 52 sequence, which works over SSH and
// inside tmux with no helper binary. Tests replace it.
var clipboardWrite = func(text string) error {
	_, err := os.Stdout.WriteString("\x1b]52;c;" + base64.StdEncoding.EncodeToString([]byte(text)) + "\a")
	return err
}

// copyCurrent copies what the cursor is on: a host IP, or the remote path.
func (m *Model) copyCurrent() tea.Cmd {
	text := ""
	switch {
	case m.focus == 1 && m.w >= 78 && m.browser.mode == modeDir:
		text = m.browser.absolute()
		if e, ok := m.browser.current(); ok && !e.up {
			text = m.browser.entryPath(e.Name)
		}
	case m.focus == 1 && m.w >= 78 && m.browser.mode == modeShares && m.browser.cursor < len(m.browser.shares):
		text = m.browser.shareRoot(m.browser.shares[m.browser.cursor].Name)
	default:
		if h := m.selected(); h != nil {
			text = h.IP
		}
	}
	if text == "" {
		return nil
	}
	return func() tea.Msg { return copiedMsg{text: text, err: clipboardWrite(text)} }
}

// --- marks and partial export ----------------------------------------------

// exportMarked writes json, markdown and html for the starred hosts only.
func (m *Model) exportMarked() tea.Cmd {
	if len(m.marks) == 0 {
		m.toast("nothing marked: press m on a host first", scan.SevInfo)
		return nil
	}
	snap, ver := m.snap, m.cfg.Version
	marks := make(map[string]bool, len(m.marks))
	for ip := range m.marks {
		marks[ip] = true
	}
	return func() tea.Msg {
		if snap == nil {
			return exportedMsg{err: fmt.Errorf("nothing scanned yet")}
		}
		doc := report.BuildFiltered(snap, ver, func(h *scan.HostView) bool { return marks[h.IP] })
		out := exportedMsg{json: "0800-marked.json", md: "0800-marked.md", html: "0800-marked.html"}
		if err := report.WriteJSON(out.json, doc); err != nil {
			return exportedMsg{err: err}
		}
		if err := report.WriteMarkdown(out.md, doc); err != nil {
			return exportedMsg{err: err}
		}
		if err := report.WriteHTML(out.html, doc); err != nil {
			return exportedMsg{err: err}
		}
		return out
	}
}

// --- preview ----------------------------------------------------------------

func (m *Model) previewRows() int { return max(1, m.h-8) }

// openPreview shows the head of the selected file without downloading it.
func (m *Model) openPreview() tea.Cmd {
	e, ok := m.browser.current()
	if m.browser.mode != modeDir || !ok || e.Dir || e.up || e.Pipe {
		return nil
	}
	m.preview = &previewState{name: e.Name, loading: true}
	return m.browser.previewCmd(e)
}

func (m *Model) keyPreview(msg tea.KeyMsg) tea.Cmd {
	st := m.preview
	switch {
	case matches(msg, keys.Down):
		st.off++
	case matches(msg, keys.Up):
		st.off--
	case matches(msg, keys.HalfDown):
		st.off += 10
	case matches(msg, keys.HalfUp):
		st.off -= 10
	case matches(msg, keys.Top):
		st.off = 0
	case matches(msg, keys.Bottom):
		st.off = 1 << 20
	case msg.String() == "g":
		m.preview = nil
		return m.download()
	default:
		switch msg.String() {
		case "esc", "h", "left", "p", " ", "enter":
			m.preview = nil
		}
	}
	if m.preview != nil {
		m.preview.clamp(m.previewRows())
	}
	return nil
}

// --- downloads --------------------------------------------------------------

// downloadBusy refuses to tear the remote session down while a transfer is
// using it, instead of killing the transfer with a "closed connection" error.
func (m *Model) downloadBusy() bool {
	if m.dl == nil {
		return false
	}
	m.toast("a download is running: wait for it, or press c to cancel", scan.SevLow)
	return true
}

// lootParts is the local directory (as path parts) a remote directory maps to.
// Empty segments are skipped: sanitizeName("") is "_", which used to turn every
// download from a share root into <ip>/<share>/_/<file>.
func (m *Model) lootParts(rel string) []string {
	parts := []string{m.cfg.LootDir}
	if m.cfg.Flat {
		return parts
	}
	parts = append(parts, sanitizeName(m.browser.hostIP))
	if m.browser.share != "" {
		parts = append(parts, sanitizeName(m.browser.share))
	}
	for _, seg := range strings.Split(rel, "/") {
		if seg == "" {
			continue
		}
		parts = append(parts, sanitizeName(seg))
	}
	return parts
}

// downloadDir copies the selected directory (or the current one when the
// cursor is on a file or "..") recursively, within the treeMax* limits.
func (m *Model) downloadDir() tea.Cmd {
	b := &m.browser
	if b.mode != modeDir || b.fs == nil {
		return nil
	}
	if m.dl != nil {
		m.toast("a download is already running (c cancels it)", scan.SevLow)
		return nil
	}

	remote := b.path
	name := b.path
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if name == "" {
		name = b.share
	}
	if e, ok := b.current(); ok && e.Dir && !e.up {
		remote, name = joinRemote(b.path, e.Name), e.Name
	}

	var local string
	if m.cfg.Flat {
		local = filepath.Join(m.cfg.LootDir, sanitizeName(name))
	} else {
		local = filepath.Join(m.lootParts(remote)...)
	}

	ctx, cancel := context.WithCancel(context.Background())
	st := &downloadState{name: sanitizeName(name) + "/", tree: true, cancel: cancel}
	m.dl = st
	fs := b.fs
	return func() tea.Msg {
		defer cancel()
		res := downloadTree(ctx, fs, remote, local, st)
		return downloadedMsg{
			name: name, dest: local, size: res.bytes,
			tree: true, files: res.files, skipped: res.skipped, note: res.note,
		}
	}
}

// --- mouse ------------------------------------------------------------------

// hostListTop is the screen row of the first host: two header lines, the
// panel's top border and its title row.
const hostListTop = 4

// leftWidth is the width of the host panel (the whole screen when narrow).
func (m *Model) leftWidth() int {
	if m.w < 78 {
		return m.w
	}
	leftW := m.w * 38 / 100
	if leftW < 34 {
		leftW = 34
	}
	if leftW > 56 {
		leftW = 56
	}
	return leftW
}

func (m *Model) handleMouse(msg tea.MouseMsg) tea.Cmd {
	if m.showHelp || m.filtering || m.w < 62 || m.h < 17 {
		return nil
	}
	inLeft := msg.X < m.leftWidth()
	if msg.Action != tea.MouseActionPress {
		return nil
	}
	switch msg.Button {
	case tea.MouseButtonWheelUp:
		m.wheel(-3, inLeft)
	case tea.MouseButtonWheelDown:
		m.wheel(3, inLeft)
	case tea.MouseButtonLeft:
		return m.click(msg.X, msg.Y, inLeft)
	}
	return nil
}

func (m *Model) wheel(delta int, inLeft bool) {
	switch {
	case m.showSummary:
		m.summaryOff += delta
	case inLeft || m.w < 78:
		m.moveCursor(delta)
	case m.preview != nil:
		m.preview.off += delta
		m.preview.clamp(m.previewRows())
	case m.showDetails:
		m.detailsOff += delta
	default:
		m.browser.move(delta, m.remoteRows())
	}
}

func (m *Model) click(x, y int, inLeft bool) tea.Cmd {
	if m.showSummary {
		return nil
	}
	row := y - hostListTop
	if inLeft || m.w < 78 {
		idx := m.offset + row
		if row < 0 || row >= m.hostRows() || idx >= len(m.hosts) {
			return nil
		}
		again := idx == m.cursor && m.focus == 0
		m.cursor = idx
		m.focus = 0
		if again {
			return m.openHost() // a second click on the selected host opens it
		}
		return nil
	}

	// Right-hand pane.
	if m.browser.mode == modeEmpty && !m.showDetails {
		return nil
	}
	m.focus = 1
	if m.showDetails || m.preview != nil {
		return nil
	}
	b := &m.browser
	idx := b.offset + row
	if row < 0 || row >= m.remoteRows() || idx >= b.rows() {
		return nil
	}
	if idx == b.cursor {
		return b.open()
	}
	b.cursor = idx
	return nil
}

// --- sparkline ---------------------------------------------------------------

var sparkBlocks = []rune("▁▂▃▄▅▆▇█")

// sparkline renders the last width values as a one-line bar chart.
func sparkline(vals []float64, width int) string {
	if width <= 0 || len(vals) == 0 {
		return ""
	}
	if len(vals) > width {
		vals = vals[len(vals)-width:]
	}
	peak := 0.0
	for _, v := range vals {
		if v > peak {
			peak = v
		}
	}
	var b strings.Builder
	for _, v := range vals {
		idx := 0
		if peak > 0 && v > 0 {
			idx = int(v/peak*float64(len(sparkBlocks)-1) + 0.5)
		}
		b.WriteRune(sparkBlocks[idx])
	}
	return b.String()
}
