// Command screenshot renders the TUI to a self-contained SVG so the README can
// show real output without shipping binary images.
//
//	go run ./tools/screenshot -view main -o docs/screenshots/main.svg
//	go run ./tools/screenshot -view main -raw
package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/rsha/0800/internal/ui"
)

func main() {
	var (
		view   = flag.String("view", "main", "main | browser | details | help")
		out    = flag.String("o", "", "output svg path")
		raw    = flag.Bool("raw", false, "print the plain text view instead")
		width  = flag.Int("w", 128, "columns")
		height = flag.Int("h", 40, "rows")
		title  = flag.String("title", "0800 — null-auth recon", "window title")
	)
	flag.Parse()

	lipgloss.SetColorProfile(termenv.TrueColor)

	m := ui.NewDemo(*width, *height, *view)
	v := m.View()

	if *raw {
		fmt.Print(stripANSI(v))
		return
	}
	if *out == "" {
		fmt.Fprintln(os.Stderr, "missing -o")
		os.Exit(2)
	}
	svg := renderSVG(v, *width, *height, *title)
	if err := os.WriteFile(*out, []byte(svg), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "wrote %s (%d bytes, %d cols)\n", *out, len(svg), *width)
}

// --- ANSI model -----------------------------------------------------------

type color struct {
	set     bool
	r, g, b uint8
}

type style struct {
	fg, bg    color
	bold      bool
	dim       bool
	underline bool
}

type run struct {
	text  string
	style style
}

type line []run

func renderSVG(view string, cols, rows int, title string) string {
	lines := parseANSI(view)

	const (
		padX     = 18.0
		padY     = 16.0
		chrome   = 36.0
		charW    = 8.05
		lineH    = 19.0
		fontSize = 13.6
		radius   = 12.0
	)
	w := padX*2 + float64(cols)*charW
	h := chrome + padY*2 + float64(rows)*lineH
	if len(lines) < rows {
		// keep the canvas size stable even if the view is shorter
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%.0f" height="%.0f" viewBox="0 0 %.0f %.0f" font-family="'JetBrains Mono','SFMono-Regular',Menlo,Consolas,'Liberation Mono',monospace">`, w, h, w, h)
	b.WriteString(`<defs><clipPath id="c"><rect x="0" y="0" width="` + ftoa(w) + `" height="` + ftoa(h) + `" rx="` + ftoa(radius) + `"/></clipPath></defs>`)
	fmt.Fprintf(&b, `<rect width="%.0f" height="%.0f" rx="%.0f" fill="#0B0E14"/>`, w, h, radius)
	fmt.Fprintf(&b, `<rect width="%.0f" height="%.0f" rx="%.0f" fill="#0B0E14" stroke="#242C3B" stroke-width="1"/>`, w-0.5, h-0.5, radius)

	// window chrome
	fmt.Fprintf(&b, `<g clip-path="url(#c)"><rect x="0" y="0" width="%.0f" height="%.0f" fill="#0F141D"/>`, w, chrome)
	fmt.Fprintf(&b, `<line x1="0" y1="%.0f" x2="%.0f" y2="%.0f" stroke="#1B2330"/>`, chrome, w, chrome)
	for i, c := range []string{"#FF5F57", "#FEBC2E", "#28C840"} {
		fmt.Fprintf(&b, `<circle cx="%.0f" cy="%.0f" r="5.5" fill="%s"/>`, 18+float64(i)*18, chrome/2, c)
	}
	fmt.Fprintf(&b, `<text x="%.0f" y="%.0f" fill="#6B7A90" font-size="12.5" text-anchor="middle">%s</text></g>`,
		w/2, chrome/2+4.5, esc(title))

	fmt.Fprintf(&b, `<g clip-path="url(#c)">`)
	top := chrome + padY
	for i, ln := range lines {
		y := top + float64(i)*lineH
		if y > h {
			break
		}
		col := 0.0
		var text strings.Builder
		for _, r := range ln {
			rw := float64(displayWidth(r.text))
			x := padX + col*charW
			if r.style.bg.set {
				fmt.Fprintf(&b, `<rect x="%.2f" y="%.2f" width="%.2f" height="%.2f" fill="%s"/>`,
					x, y, rw*charW, lineH, hex(r.style.bg))
			}
			if strings.TrimSpace(r.text) != "" {
				fill := "#D7DEEA"
				if r.style.fg.set {
					fill = hex(r.style.fg)
				}
				op := ""
				if r.style.dim {
					op = ` opacity="0.62"`
				}
				fw := ""
				if r.style.bold {
					fw = ` font-weight="700"`
				}
				ul := ""
				if r.style.underline {
					ul = ` text-decoration="underline"`
				}
				fmt.Fprintf(&text, `<tspan x="%.2f" y="%.2f" fill="%s"%s%s%s textLength="%.2f" lengthAdjust="spacingAndGlyphs" xml:space="preserve">%s</tspan>`,
					x, y+fontSize, fill, fw, ul, op, rw*charW, esc(r.text))
			}
			col += rw
		}
		if text.Len() > 0 {
			fmt.Fprintf(&b, `<text font-size="%.1f">%s</text>`, fontSize, text.String())
		}
	}
	b.WriteString(`</g></svg>`)
	return b.String()
}

func ftoa(f float64) string { return strconv.FormatFloat(f, 'f', 2, 64) }

func hex(c color) string {
	if !c.set {
		return "#D7DEEA"
	}
	return fmt.Sprintf("#%02x%02x%02x", c.r, c.g, c.b)
}

func esc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && !(s[j] >= 0x40 && s[j] <= 0x7e) {
				j++
			}
			if j < len(s) {
				j++
			}
			i = j
			continue
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

// parseANSI turns the styled view into lines of runs.
func parseANSI(s string) []line {
	var (
		lines []line
		cur   line
		st    style
		buf   strings.Builder
	)
	flush := func() {
		if buf.Len() == 0 {
			return
		}
		cur = append(cur, run{text: buf.String(), style: st})
		buf.Reset()
	}
	endLine := func() {
		flush()
		lines = append(lines, cur)
		cur = nil
	}

	for i := 0; i < len(s); {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			j := i + 2
			for j < len(s) && !(s[j] >= 0x40 && s[j] <= 0x7e) {
				j++
			}
			if j >= len(s) {
				break
			}
			cmd := s[j]
			args := s[i+2 : j]
			if cmd == 'm' {
				flush()
				st = applySGR(st, args)
			}
			i = j + 1
			continue
		}
		if s[i] == '\n' {
			endLine()
			i++
			continue
		}
		if s[i] == '\r' {
			i++
			continue
		}
		buf.WriteByte(s[i])
		i++
	}
	if buf.Len() > 0 || len(cur) > 0 {
		endLine()
	}
	return lines
}

func applySGR(st style, args string) style {
	if args == "" {
		return style{}
	}
	parts := strings.Split(args, ";")
	for i := 0; i < len(parts); i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			continue
		}
		switch {
		case n == 0:
			st = style{}
		case n == 1:
			st.bold = true
		case n == 2:
			st.dim = true
		case n == 4:
			st.underline = true
		case n == 22:
			st.bold, st.dim = false, false
		case n == 24:
			st.underline = false
		case n == 39:
			st.fg = color{}
		case n == 49:
			st.bg = color{}
		case n >= 30 && n <= 37:
			st.fg = color{set: true, r: uint8(30 + (n - 30)), g: uint8(30 + (n - 30)), b: uint8(30 + (n - 30))}
			st.fg = xterm(n - 30)
		case n >= 90 && n <= 97:
			st.fg = xterm(8 + n - 90)
		case n >= 40 && n <= 47:
			st.bg = xterm(n - 40)
		case n >= 100 && n <= 107:
			st.bg = xterm(8 + n - 100)
		case n == 38 || n == 48:
			var c color
			if i+1 < len(parts) {
				switch parts[i+1] {
				case "5":
					if i+2 < len(parts) {
						if v, err := strconv.Atoi(parts[i+2]); err == nil {
							c = xterm(v)
						}
						i += 2
					}
				case "2":
					if i+4 < len(parts) {
						r, _ := strconv.Atoi(parts[i+2])
						g, _ := strconv.Atoi(parts[i+3])
						bl, _ := strconv.Atoi(parts[i+4])
						c = color{set: true, r: uint8(r), g: uint8(g), b: uint8(bl)}
						i += 4
					}
				}
			}
			if n == 38 {
				st.fg = c
			} else {
				st.bg = c
			}
		}
	}
	return st
}

func xterm(n int) color {
	base := [16][3]uint8{
		{0, 0, 0}, {128, 0, 0}, {0, 128, 0}, {128, 128, 0},
		{0, 0, 128}, {128, 0, 128}, {0, 128, 128}, {192, 192, 192},
		{128, 128, 128}, {255, 0, 0}, {0, 255, 0}, {255, 255, 0},
		{0, 0, 255}, {255, 0, 255}, {0, 255, 255}, {255, 255, 255},
	}
	if n < 0 {
		return color{}
	}
	if n < 16 {
		c := base[n]
		return color{set: true, r: c[0], g: c[1], b: c[2]}
	}
	if n < 232 {
		n -= 16
		steps := []uint8{0, 95, 135, 175, 215, 255}
		return color{set: true, r: steps[n/36], g: steps[(n/6)%6], b: steps[n%6]}
	}
	if n < 256 {
		v := uint8(8 + (n-232)*10)
		return color{set: true, r: v, g: v, b: v}
	}
	return color{}
}

func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		switch {
		case r == 0:
		case r < 32:
		case r >= 0x1100 && (r <= 0x115f || (r >= 0x2e80 && r <= 0xa4cf) || (r >= 0xac00 && r <= 0xd7a3) ||
			(r >= 0xf900 && r <= 0xfaff) || (r >= 0xfe30 && r <= 0xfe6f) || (r >= 0xff00 && r <= 0xff60) ||
			(r >= 0xffe0 && r <= 0xffe6) || (r >= 0x1f300 && r <= 0x1f64f) || (r >= 0x1f900 && r <= 0x1f9ff)):
			w += 2
		default:
			w++
		}
	}
	return w
}

var _ = utf8.RuneLen
