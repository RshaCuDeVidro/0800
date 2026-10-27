package ui

import (
	"fmt"
	"strings"

	"github.com/RshaCuDeVidro/0800/internal/scan"
)

// renderSelection is the preview of the host under the cursor. It updates as
// you move through the list, before you open anything.
func renderSelection(host *scan.HostView, w, height int, focused bool) string {
	if host == nil {
		return panel("selection", "", styleDim.Render("no target selected"), w, height, focused)
	}
	innerW := w - 4
	var lines []string

	lines = append(lines, "")
	head := dot(host.Sev) + " " + styleText.Bold(true).Render(host.IP)
	if host.Name != "" && host.Name != host.IP {
		head += "  " + styleDim.Render(host.Name)
	}
	lines = append(lines, spread(head, styleFaint.Render(host.State.String()), innerW))
	if len(host.Ports) > 0 {
		lines = append(lines, styleDim.Render("ports  ")+styleText.Render(joinPorts(host.Ports)))
	}
	if host.DC {
		lines = append(lines, styleWarn.Render("domain controller indicators"))
	}
	lines = append(lines, "")

	lines = append(lines, findingLines(host, innerW)...)

	// Show the service fingerprints when there is no finding to explain.
	if len(host.Findings) == 0 {
		for _, s := range host.Services {
			if s.Banner == "" {
				continue
			}
			lines = append(lines, styleFaint.Render(fmt.Sprintf("%d %s · %s", s.Port, s.Proto, s.Banner)))
		}
		if host.SMB != nil {
			lines = append(lines, styleFaint.Render(fmt.Sprintf(
				"smb %s · signing %s · auth %s", host.SMB.Dialect, host.SMB.Signing, orDash(host.SMB.Auth))))
		}
		if host.NFS != nil && host.NFS.Note != "" {
			lines = append(lines, styleFaint.Render("nfs · "+host.NFS.Note))
		}
	}

	lines = append(lines, "", styleFaint.Render("enter opens it · tab shows every field"))

	right := ""
	if n := len(host.Findings); n > 0 {
		right = fmt.Sprintf("%d finding(s)", n)
	}
	return panel("selection", right, strings.Join(lines, "\n"), w, height, focused)
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
