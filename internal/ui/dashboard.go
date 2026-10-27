package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"github.com/RshaCuDeVidro/0800/internal/scan"
)

// renderDashboard fills the right pane while no host is open: live counters,
// the top exposures and a streaming feed of the newest findings.
func renderDashboard(snap *scan.Snapshot, w, h int, focused bool) string {
	innerW := w - 4
	if snap == nil {
		return panel("overview", "", "", w, h, focused)
	}

	stats := []string{
		section("scan"),
		"",
		statLine(snap.Open, "ports open", colText),
		statLine(snap.Exposed, "exposed hosts", colAccent),
		statLine(snap.Crit, "critical", colCrit),
		statLine(snap.High, "high", colHigh),
		statLine(snap.Med+snap.Low, "medium / low", colMed),
		"",
	}

	var top []string
	if len(snap.Top) > 0 {
		top = append(top, section("top exposures"), "")
		for i, host := range snap.Top {
			if i >= 5 {
				break
			}
			labels := make([]string, 0, 2)
			for _, f := range host.Findings {
				if f.Severity < scan.SevMedium {
					continue
				}
				labels = append(labels, f.Label)
				if len(labels) == 2 {
					break
				}
			}
			top = append(top, dot(host.Sev)+" "+styleText.Render(pad(host.IP, 15))+" "+
				styleDim.Render(strings.Join(labels, ", ")))
		}
		top = append(top, "")
	}

	services := []string{section("services"), ""}
	total := 0
	for _, n := range snap.ByProto {
		total += n
	}
	shown := 0
	for _, k := range []string{"smb", "ldap", "nfs", "postgres", "mysql", "redis", "kerberos"} {
		n := snap.ByProto[k]
		if n == 0 {
			continue
		}
		services = append(services, fmt.Sprintf("%s %s %s",
			styleText.Render(fmt.Sprintf("%-8s", k)),
			meter(n, max(1, total), 8),
			styleDim.Render(fmt.Sprint(n))))
		shown++
	}
	if shown == 0 {
		services = append(services, styleFaint.Render("waiting for the first response…"))
	}

	feed := []string{section("live activity"), ""}
	if len(snap.Recent) == 0 {
		feed = append(feed,
			styleFaint.Render("findings stream here as hosts answer."),
			styleFaint.Render("press ? for the key map."),
		)
	} else {
		n := 0
		for i := len(snap.Recent) - 1; i >= 0 && n < 14; i-- {
			r := snap.Recent[i]
			line := styleFaint.Render(r.At.Format("15:04:05")) + " " +
				dot(r.Sev) + " " +
				styleText.Render(fmt.Sprintf("%s:%d", r.IP, r.Port)) + " " +
				styleDim.Render(r.Label)
			feed = append(feed, line)
			n++
		}
	}

	var body string
	switch {
	case innerW >= 64:
		lw := min(34, innerW/2-1)
		rw := innerW - lw - 3
		left := append(append(stats, top...), services...)
		body = twoColumns(left, feed, lw, rw, 3)
	case innerW >= 40:
		body = strings.Join(append(append(stats, top...), feed...), "\n")
	default:
		body = strings.Join(stats, "\n")
	}

	right := "live"
	if snap.Finished {
		right = fmt.Sprintf("finished in %s", snap.Elapsed.Round(time.Second))
	}
	title := "overview"
	return panel(title, right, body, w, h, focused)
}

func statLine(n int, label string, c lipgloss.Color) string {
	num := lipgloss.NewStyle().Foreground(c).Bold(true).Render(fmt.Sprintf("%4d", n))
	return num + "  " + styleDim.Render(label)
}
