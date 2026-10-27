package ui

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/rsha/0800/internal/scan"
	"github.com/rsha/0800/internal/smb"
)

// Config wires the model to the running scan.
type Config struct {
	Store      *scan.Store
	LootDir    string
	Flat       bool
	Version    string
	SMB        smb.Config
	NFSTimeout time.Duration
	Width      int
	Height     int
}

// Model is the Bubble Tea application state.
type Model struct {
	cfg Config

	w, h int

	snap     *scan.Snapshot
	hosts    []*scan.HostView
	cursor   int
	offset   int
	allHosts bool
	filter   string

	focus       int // 0 = hosts, 1 = remote
	showDetails bool
	detailsOff  int
	browser     browser

	filtering bool
	input     textinput.Model

	spinner  spinner.Model
	scanning bool
	started  time.Time

	showHelp bool

	toastText string
	toastSev  scan.Severity
	toastTill time.Time

	dl *downloadState
}

type tickMsg time.Time

type downloadedMsg struct {
	name string
	dest string
	size int64
	err  error
}

// New builds the TUI model.
func New(cfg Config) *Model {
	if cfg.LootDir == "" {
		cfg.LootDir = "0800-loot"
	}
	if cfg.NFSTimeout <= 0 {
		cfg.NFSTimeout = 8 * time.Second
	}
	sp := spinner.New(
		spinner.WithSpinner(spinner.Dot),
		spinner.WithStyle(lipgloss.NewStyle().Foreground(colAccent)),
	)
	ti := textinput.New()
	ti.Prompt = "/"
	ti.Placeholder = "ip, name or tag"
	ti.PromptStyle = lipgloss.NewStyle().Foreground(colAccent)
	ti.TextStyle = lipgloss.NewStyle().Foreground(colText)
	ti.Cursor.Style = lipgloss.NewStyle().Foreground(colAccent)

	m := &Model{
		cfg:     cfg,
		w:       cfg.Width,
		h:       cfg.Height,
		input:   ti,
		spinner: sp,
		started: time.Now(),
	}
	m.browser = browser{smbCfg: cfg.SMB, nfsTimeout: cfg.NFSTimeout}
	if cfg.Store != nil {
		m.snap = cfg.Store.Snapshot()
		m.started = m.snap.Started
		m.refresh()
	}
	return m
}

// Init implements tea.Model.
func (m *Model) Init() tea.Cmd {
	return tea.Batch(tea.SetWindowTitle("0800 · null auth recon"), m.spinner.Tick, tick())
}

func tick() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// Update implements tea.Model.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		return m, nil

	case tickMsg:
		m.refresh()
		return m, tick()

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case tea.KeyMsg:
		return m.handleKey(msg)

	case connectedMsg:
		m.browser.applyConnected(msg)
		if msg.err != nil {
			m.toast("connect failed: "+msg.err.Error(), scan.SevHigh)
		} else {
			m.toast("mounted "+msg.share, scan.SevLow)
			m.focus = 1
			m.showDetails = false
		}
		return m, nil

	case listedMsg:
		m.browser.applyListed(msg)
		if msg.err != nil {
			m.toast(msg.err.Error(), scan.SevHigh)
		}
		return m, nil

	case downloadedMsg:
		if msg.err != nil {
			m.toast("download failed: "+msg.err.Error(), scan.SevHigh)
		} else {
			m.toast(fmt.Sprintf("saved %s (%s)", msg.dest, humanSize(msg.size)), scan.SevInfo)
		}
		m.dl = nil
		return m, nil
	}
	return m, nil
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()

	if m.showHelp {
		switch key {
		case "esc", "?", "q", "enter":
			m.showHelp = false
		}
		return m, nil
	}

	if m.filtering {
		switch key {
		case "esc":
			m.filtering = false
			m.input.Blur()
			m.filter = ""
			m.input.SetValue("")
			m.refresh()
			return m, nil
		case "enter":
			m.filtering = false
			m.input.Blur()
			m.filter = strings.TrimSpace(m.input.Value())
			m.refresh()
			return m, nil
		}
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		m.filter = strings.TrimSpace(m.input.Value())
		m.refresh()
		return m, cmd
	}

	switch key {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "?":
		m.showHelp = true
		return m, nil
	case "tab":
		m.showDetails = !m.showDetails
		if m.showDetails {
			m.focus = 1
			m.detailsOff = 0
		}
		return m, nil
	case "a":
		m.allHosts = !m.allHosts
		m.refresh()
		return m, nil
	case "/":
		m.filtering = true
		m.input.Focus()
		m.input.SetValue(m.filter)
		return m, textinput.Blink
	}

	if m.w < 78 {
		m.focus = 0
	}

	if m.focus == 1 {
		return m, m.keyRemote(msg)
	}
	return m, m.keyHosts(msg)
}

func (m *Model) keyHosts(msg tea.KeyMsg) tea.Cmd {
	switch {
	case matches(msg, keys.Down):
		m.moveCursor(1)
	case matches(msg, keys.Up):
		m.moveCursor(-1)
	case matches(msg, keys.HalfDown):
		m.moveCursor(10)
	case matches(msg, keys.HalfUp):
		m.moveCursor(-10)
	case matches(msg, keys.Top):
		m.moveCursor(-len(m.hosts))
	case matches(msg, keys.Bottom):
		m.moveCursor(len(m.hosts))
	case matches(msg, keys.Details):
		m.showDetails = !m.showDetails
	case msg.String() == "right" || msg.String() == "l":
		return m.openHost()
	case matches(msg, keys.Open):
		return m.openHost()
	}
	return nil
}

func (m *Model) keyRemote(msg tea.KeyMsg) tea.Cmd {
	if m.showDetails {
		switch {
		case matches(msg, keys.Down):
			m.detailsOff++
		case matches(msg, keys.Up):
			m.detailsOff--
		case matches(msg, keys.HalfDown):
			m.detailsOff += 10
		case matches(msg, keys.HalfUp):
			m.detailsOff -= 10
		case matches(msg, keys.Top):
			m.detailsOff = 0
		case matches(msg, keys.Bottom):
			m.detailsOff = 1 << 20
		case matches(msg, keys.Back), msg.String() == "left":
			m.showDetails = false
			m.focus = 0
		}
		return nil
	}

	switch {
	case matches(msg, keys.Down):
		m.browser.move(1, m.remoteRows())
	case matches(msg, keys.Up):
		m.browser.move(-1, m.remoteRows())
	case matches(msg, keys.HalfDown):
		m.browser.move(10, m.remoteRows())
	case matches(msg, keys.HalfUp):
		m.browser.move(-10, m.remoteRows())
	case matches(msg, keys.Top):
		m.browser.move(-len(m.browser.entries)-len(m.browser.shares), m.remoteRows())
	case matches(msg, keys.Bottom):
		m.browser.move(len(m.browser.entries)+len(m.browser.shares), m.remoteRows())
	case matches(msg, keys.Open):
		return m.browser.open()
	case msg.String() == "g":
		return m.download()
	case msg.String() == "r":
		if m.browser.mode == modeDir {
			return m.browser.listCmd(m.browser.path)
		}
	case msg.String() == "h" || msg.String() == "esc" || msg.String() == "left":
		if cmd, handled := m.browser.back(); handled {
			if m.browser.mode == modeEmpty {
				m.focus = 0
			}
			return cmd
		}
		m.focus = 0
	}
	return nil
}

func (m *Model) openHost() tea.Cmd {
	h := m.selected()
	if h == nil {
		return nil
	}
	cmd := m.browser.openHost(h)
	m.showDetails = m.browser.mode == modeEmpty
	m.focus = 1
	m.detailsOff = 0
	return cmd
}

// refresh reloads the snapshot and rebuilds the visible list.
func (m *Model) refresh() {
	if m.cfg.Store == nil {
		return
	}
	snap := m.cfg.Store.Snapshot()
	m.snap = snap
	m.scanning = !snap.Finished

	prevIP := ""
	if h := m.selected(); h != nil {
		prevIP = h.IP
	}

	filter := strings.ToLower(m.filter)
	m.hosts = m.hosts[:0]
	for _, h := range snap.Hosts {
		if !m.allHosts && len(h.Ports) == 0 && len(h.Findings) == 0 && h.Err == "" {
			continue
		}
		if filter != "" && !hostMatches(h, filter) {
			continue
		}
		m.hosts = append(m.hosts, h)
	}
	sort.SliceStable(m.hosts, func(i, j int) bool { return lessIPv4(m.hosts[i].IP, m.hosts[j].IP) })

	if prevIP != "" {
		for i, h := range m.hosts {
			if h.IP == prevIP {
				m.cursor = i
				break
			}
		}
	}
	m.clampCursor()
}

func hostMatches(h *scan.HostView, filter string) bool {
	if strings.Contains(strings.ToLower(h.IP), filter) {
		return true
	}
	if strings.Contains(strings.ToLower(h.Name), filter) {
		return true
	}
	for _, t := range h.Tags {
		if strings.Contains(strings.ToLower(t.Text), filter) {
			return true
		}
	}
	for _, f := range h.Findings {
		if strings.Contains(strings.ToLower(f.Label), filter) {
			return true
		}
	}
	return false
}

func (m *Model) selected() *scan.HostView {
	if m.cursor < 0 || m.cursor >= len(m.hosts) {
		return nil
	}
	return m.hosts[m.cursor]
}

func (m *Model) moveCursor(delta int) {
	if len(m.hosts) == 0 {
		return
	}
	m.cursor += delta
	m.clampCursor()
}

func (m *Model) clampCursor() {
	if len(m.hosts) == 0 {
		m.cursor, m.offset = 0, 0
		return
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
	if m.cursor >= len(m.hosts) {
		m.cursor = len(m.hosts) - 1
	}
	vis := m.hostRows()
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if vis > 0 && m.cursor >= m.offset+vis {
		m.offset = m.cursor - vis + 1
	}
}

func (m *Model) hostRows() int {
	if m.h < 16 {
		return 1
	}
	return max(1, m.h-4-3)
}

func (m *Model) remoteRows() int {
	if m.h < 16 {
		return 1
	}
	return max(1, m.h-4-3)
}

// View implements tea.Model.
func (m *Model) View() string {
	if m.w <= 0 || m.h <= 0 {
		return ""
	}
	if m.w < 62 || m.h < 17 {
		return m.tooSmall()
	}

	head := m.header()
	foot := m.footer()
	bodyH := m.h - lipgloss.Height(head) - lipgloss.Height(foot)

	var body string
	switch {
	case m.showHelp:
		body = m.helpView(bodyH)
	default:
		body = m.main(bodyH)
	}
	return lipgloss.JoinVertical(lipgloss.Left, head, body, foot)
}

func (m *Model) main(h int) string {
	if m.w < 78 {
		return m.hostPanel(m.w, h, true)
	}
	leftW := m.w * 38 / 100
	if leftW < 32 {
		leftW = 32
	}
	if leftW > 56 {
		leftW = 56
	}
	rightW := m.w - leftW - 1

	left := m.hostPanel(leftW, h, m.focus == 0)

	var right string
	if m.showDetails {
		if sel := m.selected(); sel != nil {
			right = renderDetails(sel, rightW, h, m.detailsOff, m.focus == 1)
		} else {
			right = panel("details", "", styleDim.Render("no selection"), rightW, h, false)
		}
	} else if m.browser.mode == modeEmpty {
		right = m.browser.render(rightW, h, false)
	} else {
		right = m.browser.render(rightW, h, m.focus == 1)
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right)
}

func (m *Model) hostPanel(w, h int, focused bool) string {
	innerW := w - 4
	inner := h - 3
	if inner < 1 {
		inner = 1
	}
	if len(m.hosts) == 0 {
		msg := "waiting for hosts…"
		if !m.scanning {
			msg = "no hosts matched"
		}
		if m.filter != "" {
			msg = "no match for " + m.filter
		}
		return panel(m.listTitle(), "", styleDim.Render(msg), w, h, focused)
	}

	if m.cursor >= len(m.hosts) {
		m.cursor = len(m.hosts) - 1
	}
	if m.cursor < m.offset {
		m.offset = m.cursor
	}
	if m.cursor >= m.offset+inner {
		m.offset = m.cursor - inner + 1
	}

	lines := make([]string, 0, inner)
	for i := m.offset; i < len(m.hosts) && len(lines) < inner; i++ {
		lines = append(lines, m.hostRow(m.hosts[i], i == m.cursor, innerW))
	}
	return panel(m.listTitle(), m.listRight(), strings.Join(lines, "\n"), w, h, focused)
}

func (m *Model) listTitle() string {
	if m.filter != "" {
		return "targets · /" + m.filter
	}
	return "targets"
}

func (m *Model) listRight() string {
	if m.scanning {
		return fmt.Sprintf("%d/%d", m.snap.Done, m.snap.Total)
	}
	return fmt.Sprintf("%d hosts", len(m.hosts))
}

func (m *Model) hostRow(h *scan.HostView, selected bool, width int) string {
	marker := "  "
	if selected {
		marker = styleAccent.Render("▌ ")
	}
	ip := h.IP
	if h.Name != "" && h.Name != h.IP && width > 52 {
		ip = h.IP + " " + h.Name
	}

	// Fit as many tags as possible, highest severity first, and summarise the
	// remainder instead of cutting a word in half.
	avail := width - 2 - lipgloss.Width(ip) - 1
	shown := make([]scan.Tag, 0, len(h.Tags))
	used := 0
	for _, t := range h.Tags {
		tw := len([]rune(t.Text))
		if used+tw+1 > avail {
			break
		}
		shown = append(shown, t)
		used += tw + 1
	}
	leftover := len(h.Tags) - len(shown)
	tagText := ""
	if leftover > 0 && avail > 3 {
		tagText = "+" + fmt.Sprint(leftover)
		if used+len(tagText) <= avail {
			used += len(tagText)
		}
	}

	plain := ip
	if len(shown) > 0 || tagText != "" {
		parts := make([]string, 0, len(shown)+1)
		for _, t := range shown {
			parts = append(parts, t.Text)
		}
		if tagText != "" {
			parts = append(parts, tagText)
		}
		plain = spread(ip, strings.Join(parts, " "), width-2)
	}

	if selected {
		return pad(marker+lipgloss.NewStyle().Bold(true).Background(colSel).Foreground(colText).Render(pad(plain, width-2)), width)
	}

	ipStyle := styleIP
	if h.State == scan.StatePending {
		ipStyle = styleIPPend
	}
	if len(shown) == 0 {
		return pad(marker+ipStyle.Render(truncate(plain, width-2)), width)
	}

	styleTags := make([]string, 0, len(shown)+1)
	for _, t := range shown {
		styleTags = append(styleTags, lipgloss.NewStyle().Foreground(sevColor(t.Sev)).Render(t.Text))
	}
	if tagText != "" {
		styleTags = append(styleTags, styleFaint.Render(tagText))
	}
	ipW := max(0, width-2-used-1)
	left := ipStyle.Render(pad(truncate(ip, ipW), ipW))
	line := spread(left, strings.Join(styleTags, " "), width-2)
	return pad(marker+line, width)
}

func (m *Model) header() string {
	left := styleTitle.Render("0800") + styleSubtitle.Render("  null-auth recon")
	if m.snap != nil && m.snap.Total > 0 {
		left = spread(left, styleFaint.Render(fmt.Sprintf("v%s", m.cfg.Version)), m.w)
	}

	pct := 0.0
	if m.snap != nil && m.snap.Total > 0 {
		pct = float64(m.snap.Done) / float64(m.snap.Total)
	}
	barW := min(28, max(10, m.w/5))
	status := "done"
	if m.scanning {
		status = m.spinner.View() + " scanning"
	}
	line2 := ""
	if m.snap != nil {
		line2 = fmt.Sprintf("%s  %3.0f%%  %s  ·  %d open  ·  %d findings",
			bar(pct, barW), pct*100, status, m.snap.Open, m.snap.Findings)
	}
	line2Style := styleDim
	if m.scanning {
		line2Style = styleText
	}
	return pad(left, m.w) + "\n" + pad(line2Style.Render(truncate(line2, m.w)), m.w)
}

func (m *Model) footer() string {
	if m.filtering {
		line := m.input.View()
		line = spread(line, styleDim.Render("enter apply · esc clear"), m.w)
		return pad(styleText.Render(truncate(line, m.w)), m.w) + "\n" + pad("", m.w)
	}

	type hint struct{ k, d string }
	hints := []hint{
		{"j/k", "move"}, {"↵", "open"}, {"h", "back"}, {"g", "get"},
		{"tab", "details"}, {"/", "filter"}, {"?", "help"}, {"q", "quit"},
	}
	var b strings.Builder
	used := 0
	for _, h := range hints {
		seg := styleKey.Render(h.k) + " " + styleKeyDesc.Render(h.d)
		sw := lipgloss.Width(seg)
		if used+sw+2 > m.w-12 && h.k != "q" {
			continue
		}
		if used > 0 {
			b.WriteString("  ")
			used += 2
		}
		b.WriteString(seg)
		used += sw
	}
	line1 := b.String()
	if m.snap != nil && m.snap.Finished {
		line1 = spread(line1, styleFaint.Render("scan complete"), m.w)
	}

	status := m.statusLine()
	return pad(truncate(line1, m.w), m.w) + "\n" + pad(truncate(status, m.w), m.w)
}

func (m *Model) statusLine() string {
	if !m.toastTill.IsZero() && time.Now().Before(m.toastTill) {
		return lipgloss.NewStyle().Foreground(sevColor(m.toastSev)).Render(" " + m.toastText)
	}
	if m.dl != nil {
		done := m.dl.done.Load()
		total := m.dl.total.Load()
		pct := 0.0
		if total > 0 {
			pct = float64(done) / float64(total)
		}
		return styleAccent.Render(" ↓ ") +
			styleText.Render(m.dl.name) + " " +
			styleDim.Render(fmt.Sprintf("%s / %s  %3.0f%%", humanSize(done), humanSize(total), pct*100))
	}
	h := m.selected()
	if h == nil {
		if m.snap != nil {
			return styleDim.Render(fmt.Sprintf(" %d targets · %d scanned · %d ports open · %d findings",
				m.snap.Total, m.snap.Done, m.snap.Open, m.snap.Findings))
		}
		return ""
	}
	left := styleAccent.Render(" "+h.IP) + " " + styleDim.Render(h.Detail)
	if m.browser.mode == modeDir && m.focus == 1 {
		left = styleAccent.Render(" " + m.browser.absolute())
	}
	return left
}

func (m *Model) toast(text string, sev scan.Severity) {
	m.toastText = text
	m.toastSev = sev
	m.toastTill = time.Now().Add(5 * time.Second)
}

func (m *Model) tooSmall() string {
	msg := "terminal too small\n\n" + styleDim.Render(fmt.Sprintf("%d×%d", m.w, m.h)) + "\n\n" +
		styleDim.Render("resize to at least 62×17") + "\n\n" + styleKey.Render("q") + " quit"
	return lipgloss.Place(max(1, m.w), max(1, m.h), lipgloss.Center, lipgloss.Center, msg)
}

func (m *Model) helpView(h int) string {
	rows := [][2]string{
		{"j / k", "move selection down / up"},
		{"↵ or l", "open share, directory or host"},
		{"h or esc", "go back one level"},
		{"g", "download the selected file"},
		{"tab", "toggle the details pane"},
		{"/ ", "filter hosts by ip, name or tag"},
		{"a", "show every target, including silent ones"},
		{"r", "reload the current directory"},
		{"?", "this help"},
		{"q", "quit"},
	}
	var lines []string
	lines = append(lines, "")
	lines = append(lines, styleAccent.Render("  navigation"))
	for _, r := range rows {
		lines = append(lines, "  "+styleKey.Render(pad(r[0], 10))+styleText.Render(r[1]))
	}
	lines = append(lines, "")
	lines = append(lines, styleAccent.Render("  about"))
	lines = append(lines, "  "+styleText.Render("0800 finds services that answer without credentials."))
	lines = append(lines, "  "+styleDim.Render("SMB null/guest · LDAP anonymous bind · NFS exports · open databases"))
	lines = append(lines, "")
	lines = append(lines, "  "+styleWarn.Render("Use only against systems you are authorised to test."))
	lines = append(lines, "  "+styleFaint.Render("downloads are written to: "+m.cfg.LootDir))
	return panel("help", "any key closes", strings.Join(lines, "\n"), m.w, h, true)
}

// --- downloads ------------------------------------------------------------

type downloadState struct {
	name  string
	total atomic.Int64
	done  atomic.Int64
}

type progressReader struct {
	r  io.Reader
	st *downloadState
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	if n > 0 {
		p.st.done.Add(int64(n))
	}
	return n, err
}

func (m *Model) download() tea.Cmd {
	e, ok := m.browser.current()
	if !ok || e.Dir {
		return nil
	}
	fs := m.browser.fs
	if fs == nil {
		return nil
	}
	remote := joinRemote(m.browser.path, e.Name)
	dest := m.destPath(e.Name)
	st := &downloadState{name: e.Name}
	if e.Size > 0 {
		st.total.Store(e.Size)
	}
	m.dl = st

	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
		defer cancel()

		rc, size, err := fs.Open(ctx, remote)
		if err != nil {
			return downloadedMsg{name: e.Name, err: err}
		}
		defer rc.Close()
		if size > 0 {
			st.total.Store(size)
		}

		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return downloadedMsg{name: e.Name, err: err}
		}
		tmp := dest + ".part"
		f, err := os.Create(tmp)
		if err != nil {
			return downloadedMsg{name: e.Name, err: err}
		}
		pr := &progressReader{r: rc, st: st}
		n, err := io.CopyBuffer(f, pr, make([]byte, 256*1024))
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			_ = os.Remove(tmp)
			return downloadedMsg{name: e.Name, err: err}
		}
		if err := os.Rename(tmp, dest); err != nil {
			return downloadedMsg{name: e.Name, err: err}
		}
		return downloadedMsg{name: e.Name, dest: dest, size: n}
	}
}

// destPath builds a collision free local path inside the loot directory.
func (m *Model) destPath(name string) string {
	parts := []string{m.cfg.LootDir}
	if !m.cfg.Flat {
		parts = append(parts, sanitizeName(m.browser.hostIP))
		if m.browser.share != "" {
			parts = append(parts, sanitizeName(m.browser.share))
		}
		for _, seg := range strings.Split(m.browser.path, "/") {
			if seg = sanitizeName(seg); seg != "" {
				parts = append(parts, seg)
			}
		}
	}
	parts = append(parts, sanitizeName(name))

	dest := filepath.Join(parts...)
	base, ext := dest, ""
	if i := strings.LastIndex(dest, "."); i > 0 {
		base, ext = dest[:i], dest[i:]
	}
	for i := 1; exists(dest); i++ {
		dest = fmt.Sprintf("%s (%d)%s", base, i, ext)
		if i > 500 {
			break
		}
	}
	return dest
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func sanitizeName(s string) string {
	s = strings.TrimSpace(s)
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, "\\", "_")
	s = strings.ReplaceAll(s, "\x00", "")
	s = strings.Trim(s, ".")
	if s == "" {
		return "_"
	}
	return s
}

func lessIPv4(a, b string) bool {
	ia, ib := net.ParseIP(a), net.ParseIP(b)
	if ia == nil || ib == nil {
		return a < b
	}
	va, vb := ia.To16(), ib.To16()
	for i := 0; i < len(va); i++ {
		if va[i] != vb[i] {
			return va[i] < vb[i]
		}
	}
	return false
}

func matches(msg tea.KeyMsg, b interface{ Keys() []string }) bool {
	k := msg.String()
	for _, c := range b.Keys() {
		if c == k {
			return true
		}
	}
	return false
}

func bar(p float64, w int) string {
	if p < 0 {
		p = 0
	}
	if p > 1 {
		p = 1
	}
	n := int(p * float64(w))
	return styleAccent.Render(strings.Repeat("█", n)) + styleFaint.Render(strings.Repeat("░", w-n))
}
