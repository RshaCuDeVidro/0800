package ui

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/RshaCuDeVidro/0800/internal/nfs"
	"github.com/RshaCuDeVidro/0800/internal/scan"
	"github.com/RshaCuDeVidro/0800/internal/smb"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

type browserMode int

const (
	modeEmpty browserMode = iota
	modeShares
	modeDir
	modeInfo
	modeDetails
)

// remoteEntry is a protocol independent directory element.
type remoteEntry struct {
	Name    string
	Dir     bool
	Pipe    bool
	Size    int64
	ModTime time.Time
	up      bool
}

// remoteFS is the only interface the file browser knows about. Adding a new
// protocol means implementing these two methods.
type remoteFS interface {
	List(ctx context.Context, path string) ([]remoteEntry, error)
	Open(ctx context.Context, path string) (io.ReadCloser, int64, error)
	Close() error
}

type shareItem struct {
	Name     string
	Type     string
	Comment  string
	Writable bool
}

type browser struct {
	smbCfg     smb.Config
	nfsTimeout time.Duration

	mode    browserMode
	hostIP  string
	hostTag string
	proto   string
	auth    string
	share   string
	path    string
	entries []remoteEntry
	shares  []shareItem

	// all* hold the unfiltered listings; entries/shares are what the filter
	// (key: /) lets through, and what every cursor index refers to.
	all       []remoteEntry
	allShares []shareItem
	filter    string

	cursor  int
	offset  int
	loading bool
	err     string

	fs remoteFS

	mountPort uint16
	nfsPort   uint16
	smbPort   int
	export    string
	info      []string
	scroll    int

	shareCache map[string][]shareItem
}

type connectedMsg struct {
	proto   string
	share   string
	fs      remoteFS
	entries []remoteEntry
	err     error
}

type listedMsg struct {
	proto   string
	share   string
	path    string
	entries []remoteEntry
	err     error
}

type sharesMsg struct {
	ip     string
	shares []shareItem
	err    error
}

func (b *browser) reset() {
	if b.fs != nil {
		go b.fs.Close()
	}
	cache := b.shareCache
	*b = browser{smbCfg: b.smbCfg, nfsTimeout: b.nfsTimeout, shareCache: cache}
}

// openHost picks the most useful panel for the selected host.
func (b *browser) openHost(h *scan.HostView) tea.Cmd {
	b.reset()
	b.hostIP = h.IP
	b.hostTag = h.Name
	if b.hostTag == "" {
		b.hostTag = h.IP
	}

	switch {
	case h.SMB != nil && h.SMB.Auth != "" && h.SMB.Signing != "required":
		b.mode = modeShares
		b.proto = "smb"
		b.auth = h.SMB.Auth
		b.smbPort = h.SMB.Port
		if cached, ok := b.shareCache[h.IP]; ok {
			b.shares = cached
		} else if len(h.SMB.Shares) > 0 {
			for _, s := range h.SMB.Shares {
				b.shares = append(b.shares, shareItem{
					Name: s.Name, Type: s.Type, Comment: s.Comment, Writable: s.Writable,
				})
			}
			sortShares(b.shares)
		} else {
			// The scan skipped enumeration to stay fast; load it on demand.
			b.loading = true
			return b.loadSharesCmd()
		}
	case h.NFS != nil && len(h.NFS.Exports) > 0:
		b.mode = modeShares
		b.proto = "nfs"
		b.mountPort = h.NFS.MountPort
		b.nfsPort = h.NFS.Port
		for _, e := range h.NFS.Exports {
			comment := "export"
			if len(e.Groups) > 0 {
				comment = strings.Join(e.Groups, ",")
			}
			if !e.Mounted {
				comment = "not mounted"
			}
			b.shares = append(b.shares, shareItem{Name: e.Path, Type: "export", Comment: comment, Writable: e.Mounted})
		}
	case len(h.DBs) > 0:
		b.mode = modeInfo
		b.proto = "db"
		for _, d := range h.DBs {
			b.info = append(b.info, fmt.Sprintf("%s:%d  %s", d.Proto, d.Port, d.Status))
			if d.Version != "" {
				b.info = append(b.info, "  version "+d.Version)
			}
			if d.User != "" {
				b.info = append(b.info, "  user "+d.User)
			}
			for _, l := range d.Detail {
				b.info = append(b.info, "  "+l)
			}
		}
	case h.FTP != nil:
		// FTP never opens a data channel, so there is nothing to browse:
		// show the login result instead of leaving the panel empty.
		b.mode = modeInfo
		b.proto = "ftp"
		b.info = append(b.info, fmt.Sprintf("ftp:%d  %s", h.FTP.Port, h.FTP.Banner))
		if h.FTP.AnonOK {
			b.info = append(b.info, "  anonymous login accepted")
		} else if h.FTP.Message != "" {
			b.info = append(b.info, fmt.Sprintf("  %d %s", h.FTP.Code, h.FTP.Message))
		}
	default:
		b.mode = modeEmpty
	}
	b.allShares = append([]shareItem(nil), b.shares...)
	b.cursor, b.offset = 0, 0
	return nil
}

// filterable reports whether the "/" filter applies to what is on screen.
func (b *browser) filterable() bool { return b.mode == modeDir || b.mode == modeShares }

// setFilter narrows the listing to names containing v (case-insensitive).
func (b *browser) setFilter(v string) {
	b.filter = v
	b.rebuild()
	b.cursor, b.offset = 0, 0
}

// rebuild recomputes entries and shares from the unfiltered listings.
func (b *browser) rebuild() {
	f := strings.ToLower(b.filter)
	kept := b.all
	if f != "" {
		kept = make([]remoteEntry, 0, len(b.all))
		for _, e := range b.all {
			if strings.Contains(strings.ToLower(e.Name), f) {
				kept = append(kept, e)
			}
		}
	}
	b.entries = withParent(b.path, kept)

	b.shares = b.allShares
	if f != "" {
		b.shares = make([]shareItem, 0, len(b.allShares))
		for _, s := range b.allShares {
			if strings.Contains(strings.ToLower(s.Name), f) ||
				strings.Contains(strings.ToLower(s.Comment), f) {
				b.shares = append(b.shares, s)
			}
		}
	}
	if n := b.rows(); b.cursor >= n {
		b.cursor = max(0, n-1)
	}
}

// shareRoot is the printable root of a share on this host.
func (b *browser) shareRoot(name string) string {
	if b.proto == "nfs" {
		return name
	}
	return `\\` + b.hostIP + `\` + name
}

// entryPath is the printable full path of an entry in the current directory.
func (b *browser) entryPath(name string) string {
	base := b.absolute()
	if b.proto == "nfs" {
		return strings.TrimSuffix(base, "/") + "/" + name
	}
	return strings.TrimSuffix(base, `\`) + `\` + name
}

func (b *browser) rows() int {
	switch b.mode {
	case modeShares:
		return len(b.shares)
	case modeDir:
		return len(b.entries)
	}
	return 0
}

// prettyFS turns common SMB statuses into something a human can act on.
func prettyFS(s string) string {
	switch {
	case strings.Contains(s, "STATUS_INVALID_PARAMETER"):
		return "this share cannot be listed as a file tree (invalid parameter)"
	case strings.Contains(s, "STATUS_ACCESS_DENIED"):
		return "access denied by the server"
	case strings.Contains(s, "STATUS_BAD_NETWORK_NAME"):
		return "share no longer available"
	case strings.Contains(s, "STATUS_OBJECT_NAME_NOT_FOUND"):
		return "directory not found"
	case strings.Contains(s, "i/o timeout"), strings.Contains(s, "deadline exceeded"):
		return "server stopped answering"
	}
	return s
}

func sortShares(list []shareItem) {
	sort.Slice(list, func(i, j int) bool {
		return strings.ToLower(list[i].Name) < strings.ToLower(list[j].Name)
	})
}

// loadSharesCmd enumerates shares on demand, including the common-name
// fallback that is too slow for the scan phase.
func (b *browser) loadSharesCmd() tea.Cmd {
	ip, auth, port := b.hostIP, b.auth, b.smbPort
	cfg := b.smbCfg
	cfg.Port = port
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		c, err := smb.Connect(ctx, ip, auth, cfg)
		if err != nil {
			return sharesMsg{ip: ip, err: err}
		}
		defer c.Close()
		shares, err := c.ListShares(ctx, smb.SharesFull)
		if err != nil {
			return sharesMsg{ip: ip, err: err}
		}
		out := make([]shareItem, 0, len(shares))
		for _, s := range shares {
			out = append(out, shareItem{Name: s.Name, Type: s.Type, Comment: s.Comment, Writable: s.Writable})
		}
		sortShares(out)
		return sharesMsg{ip: ip, shares: out}
	}
}

func (b *browser) applyShares(msg sharesMsg) {
	b.loading = false
	if msg.err != nil {
		b.err = msg.err.Error()
		return
	}
	b.allShares = msg.shares
	b.rebuild()
	if b.shareCache == nil {
		b.shareCache = map[string][]shareItem{}
	}
	b.shareCache[msg.ip] = msg.shares
	b.err = ""
}

func (b *browser) connectCmd(item shareItem) tea.Cmd {
	proto, ip, auth := b.proto, b.hostIP, b.auth
	cfg, timeout, mountPort := b.smbCfg, b.nfsTimeout, b.mountPort
	cfg.Port = b.smbPort
	nfsCfg := nfs.Config{Timeout: timeout, MountPort: mountPort, Port: b.nfsPort}
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
		defer cancel()

		switch proto {
		case "smb":
			c, err := smb.Connect(ctx, ip, auth, cfg)
			if err != nil {
				return connectedMsg{proto: proto, share: item.Name, err: err}
			}
			fs := &smbFS{c: c, share: item.Name}
			entries, err := fs.List(ctx, "")
			if err != nil {
				_ = fs.Close()
				return connectedMsg{proto: proto, share: item.Name, err: err}
			}
			return connectedMsg{proto: proto, share: item.Name, fs: fs, entries: entries}
		default:
			fs, err := nfs.MountFS(ctx, ip, nfsCfg, item.Name)
			if err != nil {
				return connectedMsg{proto: proto, share: item.Name, err: err}
			}
			wrapped := &nfsFS{fs: fs}
			entries, err := wrapped.List(ctx, "")
			if err != nil {
				_ = wrapped.Close()
				return connectedMsg{proto: proto, share: item.Name, err: err}
			}
			return connectedMsg{proto: proto, share: item.Name, fs: wrapped, entries: entries}
		}
	}
}

func (b *browser) listCmd(p string) tea.Cmd {
	fs := b.fs
	proto, share := b.proto, b.share
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if fs == nil {
			return listedMsg{proto: proto, share: share, path: p, err: fmt.Errorf("no session")}
		}
		entries, err := fs.List(ctx, p)
		return listedMsg{proto: proto, share: share, path: p, entries: entries, err: err}
	}
}

// open activates the current row.
func (b *browser) open() tea.Cmd {
	switch b.mode {
	case modeShares:
		if b.cursor < 0 || b.cursor >= len(b.shares) {
			return nil
		}
		item := b.shares[b.cursor]
		b.loading = true
		b.err = ""
		return b.connectCmd(item)
	case modeDir:
		if b.cursor < 0 || b.cursor >= len(b.entries) {
			return nil
		}
		e := b.entries[b.cursor]
		if !e.Dir {
			return nil
		}
		next := joinRemote(b.path, e.Name)
		if e.up {
			next = parentRemote(b.path)
		}
		b.loading = true
		b.err = ""
		return b.listCmd(next)
	}
	return nil
}

// back walks up one level and reports whether it consumed the key.
func (b *browser) back() (tea.Cmd, bool) {
	switch b.mode {
	case modeDir:
		if b.path != "" {
			p := parentRemote(b.path)
			b.loading = true
			b.err = ""
			return b.listCmd(p), true
		}
		b.closeFS()
		b.mode = modeShares
		b.cursor, b.offset = 0, 0
		return nil, true
	case modeShares, modeInfo:
		b.reset()
		return nil, true
	}
	return nil, false
}

func (b *browser) closeFS() {
	if b.fs != nil {
		go b.fs.Close()
		b.fs = nil
	}
}

func (b *browser) applyConnected(msg connectedMsg) {
	b.loading = false
	if msg.err != nil {
		b.err = msg.err.Error()
		return
	}
	b.fs = msg.fs
	b.share = msg.share
	b.path = ""
	b.filter = ""
	b.all = msg.entries
	b.rebuild()
	b.mode = modeDir
	b.cursor, b.offset = 0, 0
	b.err = ""
}

func (b *browser) applyListed(msg listedMsg) {
	b.loading = false
	if msg.err != nil {
		b.err = msg.err.Error()
		return
	}
	b.path = msg.path
	b.filter = "" // a filter belongs to one directory
	b.all = msg.entries
	b.rebuild()
	b.cursor, b.offset = 0, 0
	b.err = ""
}

func (b *browser) current() (remoteEntry, bool) {
	if b.mode != modeDir || b.cursor < 0 || b.cursor >= len(b.entries) {
		return remoteEntry{}, false
	}
	return b.entries[b.cursor], true
}

func (b *browser) move(delta, visible int) {
	n := b.rows()
	if n == 0 {
		b.cursor = 0
		return
	}
	b.cursor += delta
	if b.cursor < 0 {
		b.cursor = 0
	}
	if b.cursor >= n {
		b.cursor = n - 1
	}
	if visible > 0 {
		if b.cursor < b.offset {
			b.offset = b.cursor
		}
		if b.cursor >= b.offset+visible {
			b.offset = b.cursor - visible + 1
		}
	}
}

func (b *browser) absolute() string {
	switch b.proto {
	case "smb":
		base := `\\` + b.hostIP + `\` + b.share
		if b.path == "" {
			return base
		}
		return base + `\` + strings.ReplaceAll(b.path, "/", `\`)
	case "nfs":
		base := b.share
		if b.path == "" {
			return base
		}
		return strings.TrimSuffix(base, "/") + "/" + b.path
	}
	return ""
}

func (b *browser) render(w, h int, focused bool) string {
	title := "remote"
	right := ""
	switch b.mode {
	case modeEmpty:
		title = "remote"
	case modeShares:
		title = b.hostTag
		right = b.proto + " shares"
		if b.filter != "" {
			right = "/" + b.filter + " · " + right
		}
	case modeDir:
		title = b.absolute()
		right = b.proto
		if b.filter != "" {
			right = "/" + b.filter + " · " + right
		}
	case modeInfo:
		title = b.hostTag
		right = "services"
	}
	right = truncate(right, max(0, w/3))

	inner := h - 4
	if inner < 1 {
		inner = 1
	}
	var body string

	switch b.mode {
	case modeEmpty:
		body = b.renderEmpty(w-4, inner)
	case modeInfo:
		lines := make([]string, 0, len(b.info))
		for _, l := range b.info {
			lines = append(lines, truncate(styleText.Render(l), w-4))
		}
		body = strings.Join(lines, "\n")
	case modeShares, modeDir:
		body = b.renderList(inner, w-4)
	}

	return panel(title, right, body, w, h, focused)
}

func (b *browser) renderList(visible, width int) string {
	if b.loading {
		return styleDim.Render("  loading…")
	}
	n := b.rows()
	if n == 0 {
		if b.err != "" {
			return styleErr.Render("  " + truncate(b.err, width-4))
		}
		if b.filter != "" {
			return styleDim.Render("  nothing matches /" + b.filter)
		}
		if b.mode == modeShares {
			return styleDim.Render("  no shares")
		}
		return styleDim.Render("  empty directory")
	}

	var prefix string
	if b.err != "" {
		prefix = styleErr.Render("  "+truncate(prettyFS(b.err), width-4)) + "\n"
		visible = max(1, visible-1)
	}

	if b.cursor >= n {
		b.cursor = n - 1
	}
	if b.cursor < b.offset {
		b.offset = b.cursor
	}
	if visible > 0 && b.cursor >= b.offset+visible {
		b.offset = b.cursor - visible + 1
	}

	lines := make([]string, 0, visible)
	for i := b.offset; i < n && len(lines) < visible; i++ {
		selected := i == b.cursor
		lines = append(lines, b.rowLine(i, selected, width))
	}
	return prefix + strings.Join(lines, "\n")
}

func (b *browser) rowLine(i int, selected bool, width int) string {
	if b.mode == modeShares {
		it := b.shares[i]
		mark := "▸"
		name := it.Name
		if it.Writable {
			name += " *"
		}
		comment := it.Comment
		left := fmt.Sprintf("%s %s", mark, name)
		line := spread(styleText.Render(left), styleDim.Render(truncate(comment, width/2)), width)
		return b.highlight(line, selected, width)
	}

	e := b.entries[i]
	icon := "·"
	name := e.Name
	switch {
	case e.up:
		icon = "↑"
	case e.Pipe:
		icon = "│"
	case e.Dir:
		icon = "▸"
		name += "/"
	}
	left := fmt.Sprintf("%s %s", icon, name)
	size := ""
	switch {
	case e.Pipe:
		size = "pipe"
	case !e.Dir:
		size = humanSize(e.Size)
	}
	if e.ModTime.IsZero() || width < 46 {
		line := spread(left, styleDim.Render(size), width)
		if e.Dir {
			line = spread(styleBlue.Render(left), styleDim.Render(size), width)
		}
		return b.highlight(line, selected, width)
	}
	line := spread(left, styleDim.Render(size), width)
	if e.Pipe {
		line = spread(styleDim.Render(left), styleFaint.Render(size), width)
	} else if e.Dir {
		line = spread(styleBlue.Render(left), styleDim.Render(size), width)
	}
	return b.highlight(line, selected, width)
}

func (b *browser) highlight(line string, selected bool, width int) string {
	if !selected {
		return pad(line, width)
	}
	// Nested ANSI resets cancel a background applied around them, so the
	// selected row is flattened and re-styled as a single run.
	plain := ansi.Strip(line)
	return lipgloss.NewStyle().
		Background(colSel).
		Foreground(colText).
		Bold(true).
		Width(width).
		MaxWidth(width).
		Render(pad(plain, width))
}

func (b *browser) renderEmpty(width, height int) string {
	pad := 3
	if width > 60 {
		pad = 5
	}
	lines := []string{""}
	for i := 0; i < height/6; i++ {
		lines = append(lines, "")
	}
	lines = append(lines,
		strings.Repeat(" ", pad)+styleAccent.Bold(true).Render("0800"),
		strings.Repeat(" ", pad)+styleDim.Render("null-auth recon"),
		"",
		strings.Repeat(" ", pad)+styleText.Render("select a target and press enter"),
		strings.Repeat(" ", pad)+styleFaint.Render("SMB and NFS hosts open a remote file tree"),
		strings.Repeat(" ", pad)+styleFaint.Render("press s for the exposure summary"),
	)
	for len(lines) < height {
		lines = append(lines, "")
	}
	return strings.Join(lines[:height], "\n")
}

// smbFS adapts *smb.Client to remoteFS.
type smbFS struct {
	c     *smb.Client
	share string
}

func (s *smbFS) List(ctx context.Context, path string) ([]remoteEntry, error) {
	es, err := s.c.ReadDir(ctx, s.share, path)
	if err != nil {
		return nil, err
	}
	out := make([]remoteEntry, 0, len(es))
	for _, e := range es {
		out = append(out, remoteEntry{Name: e.Name, Dir: e.Dir, Pipe: e.Pipe, Size: e.Size, ModTime: e.ModTime})
	}
	return out, nil
}

func (s *smbFS) Open(ctx context.Context, path string) (io.ReadCloser, int64, error) {
	return s.c.Open(ctx, s.share, path)
}

func (s *smbFS) Close() error { return s.c.Close() }

// nfsFS adapts *nfs.FS to remoteFS.
type nfsFS struct{ fs *nfs.FS }

func (n *nfsFS) List(ctx context.Context, path string) ([]remoteEntry, error) {
	es, err := n.fs.List(ctx, path)
	if err != nil {
		return nil, err
	}
	out := make([]remoteEntry, 0, len(es))
	for _, e := range es {
		out = append(out, remoteEntry{Name: e.Name, Dir: e.Dir, Size: e.Size, ModTime: e.ModTime})
	}
	return out, nil
}

func (n *nfsFS) Open(ctx context.Context, path string) (io.ReadCloser, int64, error) {
	return n.fs.Open(ctx, path)
}

func (n *nfsFS) Close() error { return n.fs.Close() }

// withParent prepends the synthetic ".." entry for non-root directories.
func withParent(path string, entries []remoteEntry) []remoteEntry {
	if path == "" {
		return entries
	}
	out := make([]remoteEntry, 0, len(entries)+1)
	out = append(out, remoteEntry{Name: "..", Dir: true, up: true})
	return append(out, entries...)
}

func joinRemote(base, name string) string {
	if base == "" {
		return name
	}
	return base + "/" + name
}

func parentRemote(p string) string {
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return ""
	}
	return p[:i]
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}
