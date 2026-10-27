// Package report renders scan results for machines and humans.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/RshaCuDeVidro/0800/internal/scan"
)

// Document is the top level JSON report.
type Document struct {
	Tool     string           `json:"tool"`
	Version  string           `json:"version"`
	Started  time.Time        `json:"started"`
	Finished time.Time        `json:"finished"`
	Elapsed  string           `json:"elapsed"`
	Stats    Stats            `json:"stats"`
	Hosts    []*scan.HostView `json:"hosts"`

	// Partial marks a report written before every target was scanned (a
	// checkpoint, or a scan stopped early). Pending lists the targets that were
	// not finished, which is what --resume continues with.
	Partial bool     `json:"partial,omitempty"`
	Pending []string `json:"pending,omitempty"`
}

// Stats summarises a scan.
type Stats struct {
	Targets   int `json:"targets"`
	Scanned   int `json:"scanned"`
	OpenPorts int `json:"openPorts"`
	Findings  int `json:"findings"`
	Exposed   int `json:"exposedHosts"`
}

// Build creates a document from a snapshot.
func Build(snap *scan.Snapshot, version string) Document {
	doc := Document{
		Tool:     "0800",
		Version:  version,
		Started:  snap.Started,
		Finished: time.Now(),
		Elapsed:  time.Since(snap.Started).Round(time.Millisecond).String(),
		Stats: Stats{
			Targets:   snap.Total,
			Scanned:   snap.Done,
			OpenPorts: snap.Open,
			Findings:  snap.Findings,
			Exposed:   len(snap.Vulnerable()),
		},
		Hosts: make([]*scan.HostView, 0, len(snap.Hosts)),
	}
	for _, h := range snap.Hosts {
		if h.State != scan.StateDone && snap.Done < snap.Total {
			// Not finished yet: --resume probes it again. Its partial results
			// stay in the report (an interactive export mid-scan wants them),
			// but LoadResume drops them so the re-probe cannot duplicate them.
			doc.Partial = true
			doc.Pending = append(doc.Pending, h.IP)
		}
		if len(h.Ports) == 0 && h.Err == "" {
			continue // silent hosts add noise, not signal
		}
		doc.Hosts = append(doc.Hosts, h)
	}
	return doc
}

// BuildFiltered builds a document from only the hosts keep accepts (the TUI's
// "export marked"). Unlike Build it keeps silent hosts too: if the operator
// starred it, it belongs in the report. Stats are recomputed for the subset.
func BuildFiltered(snap *scan.Snapshot, version string, keep func(*scan.HostView) bool) Document {
	doc := Document{
		Tool:     "0800",
		Version:  version,
		Started:  snap.Started,
		Finished: time.Now(),
		Elapsed:  time.Since(snap.Started).Round(time.Millisecond).String(),
		Hosts:    make([]*scan.HostView, 0),
	}
	for _, h := range snap.Hosts {
		if !keep(h) {
			continue
		}
		doc.Hosts = append(doc.Hosts, h)
		doc.Stats.Targets++
		if h.State == scan.StateDone {
			doc.Stats.Scanned++
		}
		doc.Stats.OpenPorts += len(h.Ports)
		doc.Stats.Findings += h.Discovered()
		if h.Discovered() > 0 {
			doc.Stats.Exposed++
		}
	}
	return doc
}

// WriteJSON writes the document to path.
func WriteJSON(path string, doc Document) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0o644)
}

// PlainLine renders one host as a single log line.
func PlainLine(h *scan.HostView) string {
	var b strings.Builder
	b.WriteString(h.IP)
	if h.Name != "" && h.Name != h.IP {
		fmt.Fprintf(&b, " (%s)", h.Name)
	}
	if len(h.Ports) > 0 {
		fmt.Fprintf(&b, " [%s]", joinPorts(h.Ports))
	}
	if h.DC {
		b.WriteString(" [DC]")
	}
	if h.SMB != nil {
		b.WriteString(" smb")
		if h.SMB.Dialect != "" {
			fmt.Fprintf(&b, "=%s", h.SMB.Dialect)
		}
		if h.SMB.Auth != "" {
			fmt.Fprintf(&b, " auth=%s", h.SMB.Auth)
		}
		if h.SMB.Signing != "" {
			fmt.Fprintf(&b, " signing=%s", h.SMB.Signing)
		}
		if h.SMB.SMB1 {
			b.WriteString(" smb1")
		}
		if n := len(h.SMB.Shares); n > 0 {
			fmt.Fprintf(&b, " shares=%d", n)
		}
	}
	if h.NFS != nil && len(h.NFS.Exports) > 0 {
		fmt.Fprintf(&b, " nfs=%d", len(h.NFS.Exports))
	}
	if h.LDAP != nil && h.LDAP.Entries > 0 {
		fmt.Fprintf(&b, " ldap_anon=%d", h.LDAP.Entries)
	}
	if h.FTP != nil && h.FTP.AnonOK {
		b.WriteString(" ftp_anon=1")
	}
	for _, d := range h.DBs {
		fmt.Fprintf(&b, " %s=%s", d.Proto, d.Status)
	}
	for _, f := range h.Findings {
		if f.Severity < scan.SevMedium {
			continue
		}
		b.WriteString(" | ")
		b.WriteString(f.Label)
		if f.Detail != "" {
			b.WriteString(": ")
			b.WriteString(f.Detail)
		}
	}
	if h.Err != "" {
		b.WriteString(" | error: ")
		b.WriteString(strings.SplitN(h.Err, "\n", 2)[0])
	}
	return b.String()
}

// Summary renders the final counters.
func Summary(snap *scan.Snapshot) string {
	return fmt.Sprintf("%d targets · %d scanned · %d open ports · %d findings · %d exposed hosts · %s",
		snap.Total, snap.Done, snap.Open, snap.Findings, len(snap.Vulnerable()),
		time.Since(snap.Started).Round(time.Second))
}

func joinPorts(p []int) string {
	var b strings.Builder
	for i, n := range p {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%d", n)
	}
	return b.String()
}
