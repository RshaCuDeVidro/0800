package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/RshaCuDeVidro/0800/internal/scan"
	"github.com/charmbracelet/lipgloss"
)

// renderSummary is the report-style overview (key: s).
func renderSummary(snap *scan.Snapshot, w, h, offset int, focused bool) string {
	if snap == nil {
		return panel("summary", "", "", w, h, focused)
	}
	innerW := w - 4
	innerH := h - 4
	var lines []string

	lines = append(lines, "")
	lines = append(lines, spread(
		styleAccent.Bold(true).Render("EXPOSURE SUMMARY"),
		styleFaint.Render("0800"),
		innerW))
	lines = append(lines, styleFaint.Render(strings.Repeat("─", innerW)))
	lines = append(lines, "")

	lines = append(lines, spread(
		kvBig("targets", snap.Total)+"    "+kvBig("scanned", snap.Done)+"    "+kvBig("elapsed", fmt.Sprint(snap.Elapsed.Round(time.Second))),
		kvBig("open ports", snap.Open),
		innerW))
	lines = append(lines, spread(
		kvBig("exposed hosts", snap.Exposed)+"    "+kvBig("findings", snap.Findings),
		kvBig("smb", snap.ByProto["smb"])+"    "+kvBig("ldap", snap.ByProto["ldap"])+"    "+kvBig("nfs", snap.ByProto["nfs"]),
		innerW))
	lines = append(lines, "")

	lines = append(lines, severityBar(snap, innerW))
	lines = append(lines, "")

	lines = append(lines, sectionTitle("top exposures", innerW))
	vuln := snap.Vulnerable()
	if len(vuln) == 0 {
		lines = append(lines, styleFaint.Render("none — no host accepted an unauthenticated session"))
	}
	for i, host := range vuln {
		if i >= 8 {
			lines = append(lines, styleFaint.Render(fmt.Sprintf("… and %d more", len(vuln)-8)))
			break
		}
		labels := make([]string, 0, 3)
		for _, f := range host.Findings {
			if f.Severity < scan.SevMedium {
				continue
			}
			labels = append(labels, f.Label)
			if len(labels) == 3 {
				break
			}
		}
		line := dot(host.Sev) + " " +
			styleText.Render(pad(host.IP, 15)) + " " +
			styleDim.Render(pad(host.Sev.String(), 9)) + " " +
			styleDim.Render(strings.Join(labels, ", "))
		lines = append(lines, truncate(line, innerW))
	}
	lines = append(lines, "")

	lines = append(lines, sectionTitle("services", innerW))
	total := 0
	for _, n := range snap.ByProto {
		total += n
	}
	for _, k := range []string{"smb", "ldap", "nfs", "postgres", "mysql", "redis", "kerberos"} {
		n := snap.ByProto[k]
		if n == 0 {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s %s %s",
			styleText.Render(fmt.Sprintf("%-8s", k)),
			meter(n, max(1, total), min(30, innerW/3)),
			styleDim.Render(fmt.Sprint(n))))
	}
	lines = append(lines, "")

	if offset > max(0, len(lines)-innerH) {
		offset = max(0, len(lines)-innerH)
	}
	if offset < 0 {
		offset = 0
	}
	end := min(len(lines), offset+innerH)
	body := strings.Join(lines[offset:end], "\n")

	right := ""
	if len(lines) > innerH {
		right = fmt.Sprintf("%d-%d/%d", min(offset+1, len(lines)), end, len(lines))
	}
	return panel("summary", right, body, w, h, focused)
}

func kvBig(k string, v any) string {
	return styleDim.Render(k+" ") + styleText.Bold(true).Render(fmt.Sprint(v))
}

// severityBar draws a stacked, proportional bar.
func severityBar(snap *scan.Snapshot, width int) string {
	counts := []struct {
		n int
		s scan.Severity
	}{
		{snap.Crit, scan.SevCritical},
		{snap.High, scan.SevHigh},
		{snap.Med, scan.SevMedium},
		{snap.Low, scan.SevLow},
	}
	total := 0
	for _, c := range counts {
		total += c.n
	}
	if total == 0 {
		return styleFaint.Render(strings.Repeat("─", width))
	}

	barW := min(max(12, width/2), 72)
	var bar strings.Builder
	for _, c := range counts {
		if c.n == 0 {
			continue
		}
		n := int(float64(c.n) / float64(total) * float64(barW))
		if n == 0 {
			n = 1
		}
		bar.WriteString(lipgloss.NewStyle().Foreground(sevColor(c.s)).Render(strings.Repeat("█", n)))
	}
	used := lipgloss.Width(bar.String())
	if used < barW {
		bar.WriteString(styleFaint.Render(strings.Repeat("░", barW-used)))
	}

	legend := []string{}
	for _, c := range counts {
		if c.n == 0 {
			continue
		}
		label := []string{"crit", "high", "med", "low"}[len(legend)]
		legend = append(legend, dot(c.s)+" "+styleDim.Render(fmt.Sprintf("%d %s", c.n, label)))
	}
	return bar.String() + "  " + strings.Join(legend, " ")
}
