package ui

import (
	"fmt"
	"strings"

	"github.com/RshaCuDeVidro/0800/internal/scan"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// Palette. Deep blue-black base, mint accent, coral for exposure.
var (
	colBg      = lipgloss.Color("#0A0D14")
	colBorder  = lipgloss.Color("#1E2635")
	colBorderF = lipgloss.Color("#3A4C66")
	colText    = lipgloss.Color("#D5DDEA")
	colDim     = lipgloss.Color("#6A7A92")
	colFaint   = lipgloss.Color("#39445A")
	colAccent  = lipgloss.Color("#6EE7C8")
	colBlue    = lipgloss.Color("#7AA2F7")
	colCrit    = lipgloss.Color("#FF5D7A")
	colHigh    = lipgloss.Color("#FFA25C")
	colMed     = lipgloss.Color("#F2C14E")
	colLow     = lipgloss.Color("#7AA2F7")
	colSel     = lipgloss.Color("#16202F")
)

func sevColor(s scan.Severity) lipgloss.Color {
	switch s {
	case scan.SevCritical:
		return colCrit
	case scan.SevHigh:
		return colHigh
	case scan.SevMedium:
		return colMed
	case scan.SevLow:
		return colLow
	default:
		return colDim
	}
}

var (
	styleTitle    = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
	styleSubtitle = lipgloss.NewStyle().Foreground(colDim)
	styleText     = lipgloss.NewStyle().Foreground(colText)
	styleDim      = lipgloss.NewStyle().Foreground(colDim)
	styleFaint    = lipgloss.NewStyle().Foreground(colFaint)
	styleIP       = lipgloss.NewStyle().Foreground(colText)
	styleIPPend   = lipgloss.NewStyle().Foreground(colFaint)
	styleAccent   = lipgloss.NewStyle().Foreground(colAccent)
	styleBlue     = lipgloss.NewStyle().Foreground(colBlue)
	styleCrit     = lipgloss.NewStyle().Foreground(colCrit).Bold(true)
	styleWarn     = lipgloss.NewStyle().Foreground(colMed)
	styleErr      = lipgloss.NewStyle().Foreground(colCrit)
	styleKey      = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
	styleKeyDesc  = lipgloss.NewStyle().Foreground(colDim)
)

// truncate shortens s to w display cells, keeping ANSI styling intact.
func truncate(s string, w int) string {
	if w <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= w {
		return s
	}
	return ansi.Truncate(s, w, "…")
}

// pad right-pads s to w display cells.
func pad(s string, w int) string {
	sw := lipgloss.Width(s)
	if sw >= w {
		return truncate(s, w)
	}
	return s + strings.Repeat(" ", w-sw)
}

// spread places left and right at the edges of a w-cell line.
func spread(left, right string, w int) string {
	lw, rw := lipgloss.Width(left), lipgloss.Width(right)
	if lw+rw+1 > w {
		right = truncate(right, max(0, w-lw-1))
		rw = lipgloss.Width(right)
	}
	if lw+rw > w {
		return truncate(left, w)
	}
	return left + strings.Repeat(" ", w-lw-rw) + right
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// panel renders a rounded box of exactly w x h cells with a title row.
func panel(title, right, body string, w, h int, focused bool) string {
	if w < 6 || h < 4 {
		return truncate(body, max(0, w))
	}
	bc := colBorder
	if focused {
		bc = colBorderF
	}
	innerW := w - 4
	innerH := h - 2

	head := spread(styleSubtitle.Render(title), styleDim.Render(right), innerW)
	lines := strings.Split(body, "\n")
	// Keep one empty row above the bottom border: dense panes otherwise look
	// like they bleed into the frame.
	capacity := max(1, innerH-2)
	if len(lines) > capacity {
		lines = lines[:capacity]
	}
	for i := range lines {
		lines[i] = pad(truncate(lines[i], innerW), innerW)
	}
	for len(lines) < capacity {
		lines = append(lines, strings.Repeat(" ", innerW))
	}
	content := head + "\n" + strings.Join(lines, "\n")

	return lipgloss.NewStyle().
		Width(w-2).
		Height(innerH).
		Padding(0, 1).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(bc).
		Render(content)
}

// pill renders a filled severity badge.
func pill(text string, s scan.Severity) string {
	return lipgloss.NewStyle().
		Foreground(colBg).
		Background(sevColor(s)).
		Bold(true).
		Padding(0, 1).
		Render(text)
}

// dot renders a coloured bullet.
func dot(s scan.Severity) string {
	return lipgloss.NewStyle().Foreground(sevColor(s)).Render("●")
}

// section renders a short, fixed-width section header.
func section(name string) string {
	return styleDim.Render(name) + " " + styleFaint.Render(strings.Repeat("─", 10))
}

// sectionTitle renders "name ─────────" in a dim tone.
func sectionTitle(name string, w int) string {
	line := strings.Repeat("─", max(0, w-lipgloss.Width(name)-1))
	return styleDim.Render(name) + " " + styleFaint.Render(line)
}

// meter renders a proportional mini bar.
func meter(n, total, w int) string {
	if total <= 0 || w <= 0 {
		return styleFaint.Render(strings.Repeat("·", max(0, w)))
	}
	filled := int(float64(n) / float64(total) * float64(w))
	if n > 0 && filled == 0 {
		filled = 1
	}
	if filled > w {
		filled = w
	}
	return styleAccent.Render(strings.Repeat("█", filled)) + styleFaint.Render(strings.Repeat("░", w-filled))
}

// twoColumns joins two blocks line by line.
func twoColumns(left, right []string, lw, rw, gap int) string {
	n := max(len(left), len(right))
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		l, r := "", ""
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		out = append(out, pad(truncate(l, lw), lw)+strings.Repeat(" ", gap)+pad(truncate(r, rw), rw))
	}
	return strings.Join(out, "\n")
}

func humanDuration(d float64) string {
	if d < 1 {
		return "—"
	}
	sec := int(d)
	if sec < 60 {
		return fmt.Sprintf("00:%02d", sec)
	}
	return fmt.Sprintf("%02d:%02d", sec/60, sec%60)
}
