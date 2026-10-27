package report

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/RshaCuDeVidro/0800/internal/scan"
)

// WriteMarkdown renders a human report: one section per exposed host, with the
// evidence that proved each finding.
func WriteMarkdown(path string, doc Document) error {
	var b strings.Builder
	b.WriteString("# 0800 — null authentication report\n\n")
	fmt.Fprintf(&b, "- **generated**: %s\n", doc.Finished.Format("2006-01-02 15:04:05 MST"))
	fmt.Fprintf(&b, "- **version**: %s\n", doc.Version)
	fmt.Fprintf(&b, "- **targets**: %d · **scanned**: %d\n", doc.Stats.Targets, doc.Stats.Scanned)
	fmt.Fprintf(&b, "- **open ports**: %d · **exposed hosts**: %d · **findings**: %d\n\n",
		doc.Stats.OpenPorts, doc.Stats.Exposed, doc.Stats.Findings)

	hosts := make([]*scan.HostView, 0, len(doc.Hosts))
	for _, h := range doc.Hosts {
		if h.Discovered() > 0 {
			hosts = append(hosts, h)
		}
	}
	sort.SliceStable(hosts, func(i, j int) bool {
		if hosts[i].Sev != hosts[j].Sev {
			return hosts[i].Sev > hosts[j].Sev
		}
		return hosts[i].Discovered() > hosts[j].Discovered()
	})

	if len(hosts) == 0 {
		b.WriteString("No host accepted an unauthenticated session on the probed ports.\n")
	}

	for _, h := range hosts {
		fmt.Fprintf(&b, "## %s", h.IP)
		if h.Name != "" && h.Name != h.IP {
			fmt.Fprintf(&b, " — %s", h.Name)
		}
		b.WriteString("\n\n")
		sev := h.Sev.String()
		fmt.Fprintf(&b, "- **severity**: %s\n", strings.ToUpper(sev[:1])+sev[1:])
		if len(h.Ports) > 0 {
			fmt.Fprintf(&b, "- **ports**: %s\n", joinPorts(h.Ports))
		}
		if h.DC {
			b.WriteString("- **domain controller**: yes (KDC + LDAP/rootDSE + SMB identity)\n")
		}
		if h.SMB != nil {
			fmt.Fprintf(&b, "- **smb**: dialect %s · signing %s · auth %s",
				h.SMB.Dialect, h.SMB.Signing, orDash(h.SMB.Auth))
			if len(h.SMB.Shares) > 0 {
				names := make([]string, 0, len(h.SMB.Shares))
				for _, s := range h.SMB.Shares {
					n := s.Name
					if s.Writable {
						n += " (write)"
					}
					names = append(names, n)
				}
				fmt.Fprintf(&b, " · shares %s", strings.Join(names, ", "))
			}
			b.WriteString("\n")
		}
		if h.NFS != nil && len(h.NFS.Exports) > 0 {
			paths := make([]string, 0, len(h.NFS.Exports))
			for _, e := range h.NFS.Exports {
				p := e.Path
				if e.Mounted {
					p += " (mounted)"
				}
				paths = append(paths, p)
			}
			fmt.Fprintf(&b, "- **nfs**: %s\n", strings.Join(paths, ", "))
		}
		if h.LDAP != nil && (h.LDAP.Bound || h.LDAP.DefaultDN != "") {
			fmt.Fprintf(&b, "- **ldap**: anonymous bind %d · base %s",
				h.LDAP.Code, orDash(h.LDAP.DefaultDN))
			if h.LDAP.Entries > 0 {
				fmt.Fprintf(&b, " · %d object(s) readable", h.LDAP.Entries)
			}
			b.WriteString("\n")
		}
		for _, d := range h.DBs {
			fmt.Fprintf(&b, "- **%s**: %s%s\n", d.Proto, d.Status, versionSuffix(d.Version))
		}
		b.WriteString("\n")

		if len(h.Findings) > 0 {
			b.WriteString("### Findings\n\n")
			for _, f := range h.Findings {
				fmt.Fprintf(&b, "- **%s** — %s (%s, port %d/%s)\n",
					f.Label, f.Detail, f.Severity, f.Port, f.Proto)
				for _, ev := range f.Evidence {
					fmt.Fprintf(&b, "  - `%s`\n", ev)
				}
			}
			b.WriteString("\n")
		}
	}

	b.WriteString("---\n\n")
	b.WriteString("Only use 0800 against systems you own or have written permission to test.\n")
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func versionSuffix(v string) string {
	if v == "" {
		return ""
	}
	return " " + v
}
