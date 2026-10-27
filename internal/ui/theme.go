package ui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/rsha/0800/internal/scan"
)

// Palette. Tuned for dark terminals; every colour has enough contrast on
// #0B0E14 to stay readable in screenshots and over SSH.
var (
	colBg      = lipgloss.Color("#0B0E14")
	colPanel   = lipgloss.Color("#0F141D")
	colBorder  = lipgloss.Color("#242C3B")
	colBorderF = lipgloss.Color("#3D4A63")
	colText    = lipgloss.Color("#D7DEEA")
	colDim     = lipgloss.Color("#6B7A90")
	colFaint   = lipgloss.Color("#3A4557")
	colAccent  = lipgloss.Color("#7EE7D0")
	colBlue    = lipgloss.Color("#8AB4F8")
	colWarn    = lipgloss.Color("#F5C76B")
	colCrit    = lipgloss.Color("#FF6B81")
	colHigh    = lipgloss.Color("#FF9E64")
	colSel     = lipgloss.Color("#18202E")
)

func sevColor(s scan.Severity) lipgloss.Color {
	switch s {
	case scan.SevCritical:
		return colCrit
	case scan.SevHigh:
		return colHigh
	case scan.SevMedium:
		return colWarn
	case scan.SevLow:
		return colBlue
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
	styleSel      = lipgloss.NewStyle().Background(colSel).Bold(true)
	styleSelBar   = lipgloss.NewStyle().Foreground(colAccent).Background(colSel)
	styleAccent   = lipgloss.NewStyle().Foreground(colAccent)
	styleBlue     = lipgloss.NewStyle().Foreground(colBlue)
	styleCrit     = lipgloss.NewStyle().Foreground(colCrit).Bold(true)
	styleWarn     = lipgloss.NewStyle().Foreground(colWarn)
	styleErr      = lipgloss.NewStyle().Foreground(colCrit)
	styleKey      = lipgloss.NewStyle().Foreground(colAccent).Bold(true)
	styleKeyDesc  = lipgloss.NewStyle().Foreground(colDim)
	styleChip     = lipgloss.NewStyle().Foreground(colBg).Background(colAccent).Padding(0, 1).Bold(true)
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
	innerW := w - 4 // border (2) + horizontal padding (2)
	innerH := h - 2

	head := spread(styleSubtitle.Render(title), styleDim.Render(right), innerW)
	lines := strings.Split(body, "\n")
	if len(lines) > innerH-1 {
		lines = lines[:innerH-1]
	}
	for i := range lines {
		lines[i] = pad(truncate(lines[i], innerW), innerW)
	}
	for len(lines) < innerH-1 {
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

// chip renders a small label.
func chip(text string, c lipgloss.Color) string {
	return lipgloss.NewStyle().
		Foreground(c).
		Background(lipgloss.Color("#151C28")).
		Padding(0, 1).
		Render(text)
}
