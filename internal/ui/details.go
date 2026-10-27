package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/RshaCuDeVidro/0800/internal/scan"
	"github.com/charmbracelet/lipgloss"
)

// detailsLines renders the forensic view of a host. It is deliberately
// verbose: this is the pane a human copies from into a report.
func detailsLines(h *scan.HostView, width int) []string {
	var lines []string
	add := func(s string) { lines = append(lines, truncate(s, width)) }
	add("")
	if h.Name != "" && h.Name != h.IP {
		add(spread(styleText.Render(h.Name), styleDim.Render(h.State.String()), width))
	} else {
		add(styleDim.Render(h.State.String()))
	}
	if len(h.Ports) > 0 {
		add(styleDim.Render("ports  ") + styleText.Render(joinPorts(h.Ports)))
	}
	if h.DC {
		add(styleWarn.Render("domain controller indicators present"))
	}
	add("")

	if h.SMB != nil {
		add(styleAccent.Render("smb"))
		add(kv("dialect", h.SMB.Dialect))
		add(kv("signing", h.SMB.Signing))
		add(kv("smb1", yesNo(h.SMB.SMB1)))
		if h.SMB.Auth != "" {
			add(kv("auth", h.SMB.Auth))
		}
		if h.SMB.NetBIOS != "" {
			add(kv("netbios", h.SMB.NetBIOS))
		}
		if h.SMB.Domain != "" {
			add(kv("domain", h.SMB.Domain))
		}
		for _, s := range h.SMB.Shares {
			perm := s.Type
			if s.Writable {
				perm += ",write"
			}
			c := styleText
			if s.Writable {
				c = styleCrit
			}
			add("  " + c.Render(fmt.Sprintf("%-14s", s.Name)) + styleDim.Render(perm))
			if s.Comment != "" {
				add(styleFaint.Render("    " + s.Comment))
			}
		}
		if h.SMB.EnumErr != "" {
			add(styleDim.Render("  enum: " + h.SMB.EnumErr))
		}
		add("")
	}

	if h.LDAP != nil {
		add(styleAccent.Render("ldap"))
		add(kv("bind", fmt.Sprintf("%d %s", h.LDAP.Code, h.LDAP.Message)))
		if h.LDAP.DefaultDN != "" {
			add(kv("base", h.LDAP.DefaultDN))
		}
		if h.LDAP.DNSHost != "" {
			add(kv("host", h.LDAP.DNSHost))
		}
		if h.LDAP.Entries > 0 {
			add(kv("leaked", fmt.Sprintf("%d object(s)", h.LDAP.Entries)))
			for _, s := range h.LDAP.Sample {
				add(styleFaint.Render("  " + s))
			}
		}
		add("")
	}

	if h.NFS != nil {
		add(styleAccent.Render("nfs"))
		if h.NFS.Version != "" {
			add(kv("version", h.NFS.Version))
		}
		for _, e := range h.NFS.Exports {
			state := styleDim.Render("listed")
			if e.Mounted {
				state = styleWarn.Render("mounted")
			}
			add("  " + styleText.Render(fmt.Sprintf("%-24s", e.Path)) + " " + state)
			if len(e.Groups) > 0 {
				add(styleFaint.Render("    " + strings.Join(e.Groups, ",")))
			}
		}
		if h.NFS.Note != "" {
			add(styleDim.Render("  " + h.NFS.Note))
		}
		add("")
	}

	for _, d := range h.DBs {
		add(styleAccent.Render(d.Proto))
		add(kv("port", fmt.Sprint(d.Port)))
		if d.Version != "" {
			add(kv("version", d.Version))
		}
		add(kv("status", d.Status))
		if d.User != "" {
			add(kv("user", d.User))
		}
		for _, l := range d.Detail {
			add(styleFaint.Render("  " + l))
		}
		add("")
	}

	if len(h.Findings) > 0 {
		add(styleAccent.Render("findings"))
		for _, f := range h.Findings {
			dot := lipgloss.NewStyle().Foreground(sevColor(f.Severity)).Render("● ")
			add("  " + dot + styleText.Render(f.Label) + styleDim.Render("  "+f.Detail))
			for _, ev := range f.Evidence {
				add(styleFaint.Render("    " + ev))
			}
		}
		add("")
	}

	if len(h.Services) > 0 {
		add(styleAccent.Render("services"))
		for _, s := range h.Services {
			line := fmt.Sprintf("%-6d %-10s %s", s.Port, s.Proto, s.Banner)
			add(styleDim.Render(truncate(line, width)))
			for _, kv := range s.KV {
				if kv[1] == "" {
					continue
				}
				add(styleFaint.Render("  " + kv[0] + ": " + kv[1]))
			}
		}
		add("")
	}

	if h.Err != "" {
		add(styleErr.Render("error: " + h.Err))
	}
	if h.Took > 0 {
		add(styleFaint.Render(fmt.Sprintf("scanned in %s", h.Took.Round(time.Millisecond))))
	}
	return lines
}

func renderDetails(h *scan.HostView, w, h2, scroll int, focused bool) string {
	lines := detailsLines(h, w-4)
	inner := h2 - 4
	if inner < 1 {
		inner = 1
	}
	if scroll > max(0, len(lines)-inner) {
		scroll = max(0, len(lines)-inner)
	}
	if scroll < 0 {
		scroll = 0
	}
	end := min(len(lines), scroll+inner)
	body := strings.Join(lines[scroll:end], "\n")

	right := fmt.Sprintf("%d-%d/%d", min(scroll+1, len(lines)), min(scroll+inner, len(lines)), len(lines))
	if h.DC && len(lines) <= inner {
		right = "domain controller"
	}
	return panel(h.IP, right, body, w, h2, focused)
}

func kv(k, v string) string {
	if v == "" {
		return ""
	}
	return styleDim.Render(fmt.Sprintf("%-10s", k)) + styleText.Render(v)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func joinPorts(p []int) string {
	var b strings.Builder
	for i, n := range p {
		if i > 0 {
			b.WriteString(" ")
		}
		fmt.Fprintf(&b, "%d", n)
	}
	return b.String()
}
