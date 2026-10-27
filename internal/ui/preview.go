package ui

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
)

// previewMax is how much of a file the preview pane ever fetches. One READ,
// read-only: looking at a file must stay cheap on the remote side.
const previewMax = 16 * 1024

// previewState is the file preview overlay (key: p).
type previewState struct {
	name    string
	size    int64
	lines   []string
	binary  bool
	trunc   bool
	off     int
	loading bool
	err     string
}

type previewMsg struct {
	name string
	size int64
	data []byte
	err  error
}

// peeker is implemented by filesystems that can read the head of a file in
// one round trip; others fall back to Open + a bounded read.
type peeker interface {
	Peek(ctx context.Context, path string, n int) ([]byte, int64, error)
}

func (s *smbFS) Peek(ctx context.Context, path string, n int) ([]byte, int64, error) {
	return s.c.Peek(ctx, s.share, path, n)
}

func (n *nfsFS) Peek(ctx context.Context, path string, count int) ([]byte, int64, error) {
	return n.fs.Peek(ctx, path, count)
}

// previewCmd fetches the head of the selected file.
func (b *browser) previewCmd(e remoteEntry) tea.Cmd {
	fs := b.fs
	remote := joinRemote(b.path, e.Name)
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if fs == nil {
			return previewMsg{name: e.Name, err: errors.New("no session")}
		}
		if p, ok := fs.(peeker); ok {
			data, size, err := p.Peek(ctx, remote, previewMax)
			return previewMsg{name: e.Name, size: size, data: data, err: err}
		}
		rc, size, err := fs.Open(ctx, remote)
		if err != nil {
			return previewMsg{name: e.Name, err: err}
		}
		defer rc.Close()
		data, err := io.ReadAll(io.LimitReader(rc, previewMax))
		if err != nil && len(data) == 0 {
			return previewMsg{name: e.Name, size: size, err: err}
		}
		return previewMsg{name: e.Name, size: size, data: data}
	}
}

// newPreview turns the fetched bytes into display lines.
func newPreview(msg previewMsg) *previewState {
	st := &previewState{name: msg.name, size: msg.size}
	if msg.err != nil {
		st.err = prettyFS(msg.err.Error())
		return st
	}
	st.trunc = msg.size > int64(len(msg.data))
	st.binary = looksBinary(msg.data)
	if st.binary {
		st.lines = hexDump(msg.data)
	} else {
		st.lines = textLines(msg.data)
	}
	return st
}

// looksBinary decides between a text view and a hex dump: a NUL byte, or
// bytes that are not valid UTF-8 / not printable, mean "not text".
func looksBinary(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return true
	}
	// A multi-byte rune cut in half by the preview limit is not evidence of
	// binary: drop it only when the tail really is an incomplete sequence
	// (a lead byte followed by too few continuation bytes).
	probe := data
	for i := len(data) - 1; i >= 0 && i >= len(data)-3; i-- {
		b := data[i]
		if b&0xC0 == 0x80 { // continuation byte: keep looking for its lead
			continue
		}
		if b >= 0xC0 && !utf8.FullRune(data[i:]) {
			probe = data[:i]
		}
		break
	}
	if !utf8.Valid(probe) {
		return true
	}
	ctrl := 0
	for _, r := range string(probe) {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			ctrl++
		}
	}
	return ctrl*10 > len(probe) // more than 10% control characters
}

// textLines splits text into numbered display lines. Tabs are expanded and
// control characters neutralised so a hostile file cannot inject terminal
// escape sequences into the TUI.
func textLines(data []byte) []string {
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	raw := strings.Split(text, "\n")
	if n := len(raw); n > 1 && raw[n-1] == "" {
		raw = raw[:n-1]
	}
	out := make([]string, 0, len(raw))
	for i, l := range raw {
		out = append(out, fmt.Sprintf("%4d │ %s", i+1, sanitizeLine(l)))
	}
	return out
}

// sanitizeLine replaces everything that could drive the terminal (ESC, CSI,
// C0/C1 controls) and expands tabs.
func sanitizeLine(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteString("    ")
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			b.WriteRune('·')
		case r == utf8.RuneError:
			b.WriteRune('�')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// hexDump renders 16 bytes per row: offset, hex, and the printable column.
func hexDump(data []byte) []string {
	out := make([]string, 0, len(data)/16+1)
	for off := 0; off < len(data); off += 16 {
		end := min(off+16, len(data))
		chunk := data[off:end]

		var hex strings.Builder
		for i := 0; i < 16; i++ {
			if i < len(chunk) {
				fmt.Fprintf(&hex, "%02x ", chunk[i])
			} else {
				hex.WriteString("   ")
			}
			if i == 7 {
				hex.WriteByte(' ')
			}
		}
		var asc strings.Builder
		for _, c := range chunk {
			if c >= 0x20 && c < 0x7f {
				asc.WriteByte(c)
			} else {
				asc.WriteByte('.')
			}
		}
		out = append(out, fmt.Sprintf("%08x  %s |%s|", off, hex.String(), asc.String()))
	}
	return out
}

// renderPreview draws the overlay in the right-hand pane.
func renderPreview(st *previewState, w, h int, focused bool) string {
	title := "preview · " + st.name
	inner := max(1, h-4)

	if st.loading {
		return panel(title, "", styleDim.Render("  reading…"), w, h, focused)
	}
	if st.err != "" {
		return panel(title, "esc closes", styleErr.Render("  "+st.err), w, h, focused)
	}

	st.clamp(inner)
	end := min(len(st.lines), st.off+inner)
	lines := make([]string, 0, inner)
	for _, l := range st.lines[st.off:end] {
		if st.binary {
			lines = append(lines, styleText.Render(l))
		} else {
			num, rest, _ := strings.Cut(l, "│")
			lines = append(lines, styleFaint.Render(num+"│")+styleText.Render(rest))
		}
	}
	if len(st.lines) == 0 {
		lines = append(lines, styleDim.Render("  empty file"))
	}

	kind := "text"
	if st.binary {
		kind = "hex"
	}
	right := fmt.Sprintf("%s · %s", kind, humanSize(st.size))
	if st.trunc {
		right = fmt.Sprintf("%s · first %s of %s", kind, humanSize(previewMax), humanSize(st.size))
	}
	if len(st.lines) > inner {
		right += fmt.Sprintf(" · %d-%d/%d", st.off+1, end, len(st.lines))
	}
	return panel(title, right, strings.Join(lines, "\n"), w, h, focused)
}

func (st *previewState) clamp(visible int) {
	if st.off > len(st.lines)-visible {
		st.off = len(st.lines) - visible
	}
	if st.off < 0 {
		st.off = 0
	}
}
