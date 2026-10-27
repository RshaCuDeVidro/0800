package ui

import (
	"fmt"
	"strings"

	"github.com/RshaCuDeVidro/0800/internal/scan"
	"github.com/charmbracelet/lipgloss"
)

// findingLines renders the findings of a host as compact single-line rows.
func findingLines(h *scan.HostView, width int) []string {
	if h == nil {
		return nil
	}
	if len(h.Findings) == 0 {
		lines := []string{styleDim.Render("no exposure found on the probed ports")}
		for _, s := range h.Services {
			if s.Banner == "" {
				continue
			}
			lines = append(lines, styleFaint.Render(fmt.Sprintf("%d %s · %s", s.Port, s.Proto, s.Banner)))
		}
		return lines
	}

	out := make([]string, 0, len(h.Findings))
	for _, f := range h.Findings {
		label := lipgloss.NewStyle().Foreground(sevColor(f.Severity)).Bold(true).Render(f.Label)
		detail := styleDim.Render("  " + f.Detail)
		line := dot(f.Severity) + " " + label + detail
		out = append(out, truncate(line, width))
	}
	return out
}

// renderFindings is the compact findings pane shown under the file tree.
func renderFindings(host *scan.HostView, w, height int, focused bool) string {
	if host == nil {
		return panel("findings", "", styleDim.Render("no host selected"), w, height, focused)
	}
	lines := findingLines(host, w-4)
	body := strings.Join(lines, "\n")
	right := fmt.Sprintf("%d", len(host.Findings))
	if host.DC {
		right = "domain controller · " + right
	}
	return panel("findings", right, body, w, height, focused)
}
