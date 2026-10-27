package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/RshaCuDeVidro/0800/internal/scan"
)

// Change is one finding that appeared or disappeared between two reports.
type Change struct {
	IP       string
	Port     int
	Proto    string
	Kind     string
	Label    string
	Severity scan.Severity
	Detail   string
}

// DiffResult is what changed between an old and a new report.
type DiffResult struct {
	New      []Change // in the new report only
	Resolved []Change // in the old report only
	Same     int      // present in both
	// NewHosts and GoneHosts are hosts with at least one finding that exist in
	// only one of the reports.
	NewHosts  []string
	GoneHosts []string
}

type findingKey struct {
	ip, proto, kind string
	port            int
}

func indexFindings(doc Document) (map[findingKey]Change, map[string]bool) {
	out := map[findingKey]Change{}
	hosts := map[string]bool{}
	for _, h := range doc.Hosts {
		for _, f := range h.Findings {
			k := findingKey{ip: h.IP, proto: f.Proto, kind: f.Kind, port: f.Port}
			out[k] = Change{
				IP: h.IP, Port: f.Port, Proto: f.Proto, Kind: f.Kind,
				Label: f.Label, Severity: f.Severity, Detail: f.Detail,
			}
			hosts[h.IP] = true
		}
	}
	return out, hosts
}

// Diff compares two reports finding by finding (identified by host, port,
// protocol and kind), most severe first.
func Diff(oldDoc, newDoc Document) DiffResult {
	oldF, oldHosts := indexFindings(oldDoc)
	newF, newHosts := indexFindings(newDoc)

	var d DiffResult
	for k, c := range newF {
		if _, ok := oldF[k]; ok {
			d.Same++
		} else {
			d.New = append(d.New, c)
		}
	}
	for k, c := range oldF {
		if _, ok := newF[k]; !ok {
			d.Resolved = append(d.Resolved, c)
		}
	}
	for ip := range newHosts {
		if !oldHosts[ip] {
			d.NewHosts = append(d.NewHosts, ip)
		}
	}
	for ip := range oldHosts {
		if !newHosts[ip] {
			d.GoneHosts = append(d.GoneHosts, ip)
		}
	}

	order := func(cs []Change) {
		sort.Slice(cs, func(i, j int) bool {
			if cs[i].Severity != cs[j].Severity {
				return cs[i].Severity > cs[j].Severity
			}
			if cs[i].IP != cs[j].IP {
				return cs[i].IP < cs[j].IP
			}
			return cs[i].Kind < cs[j].Kind
		})
	}
	order(d.New)
	order(d.Resolved)
	sort.Strings(d.NewHosts)
	sort.Strings(d.GoneHosts)
	return d
}

// NewExposure reports whether the diff contains a new finding at medium or
// above: the signal a CI job or a cron wants an exit code for.
func (d DiffResult) NewExposure() bool {
	for _, c := range d.New {
		if c.Severity >= scan.SevMedium {
			return true
		}
	}
	return false
}

// FormatDiff renders the diff for a terminal.
func FormatDiff(d DiffResult, oldName, newName string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "0800 diff · %s → %s\n\n", oldName, newName)
	fmt.Fprintf(&b, "  %d new · %d resolved · %d unchanged\n", len(d.New), len(d.Resolved), d.Same)

	section := func(title, mark string, cs []Change) {
		if len(cs) == 0 {
			return
		}
		fmt.Fprintf(&b, "\n%s\n", title)
		for _, c := range cs {
			fmt.Fprintf(&b, "  %s %-15s %-8s %-6s %s", mark, c.IP, c.Severity, portProto(c), c.Label)
			if c.Detail != "" {
				fmt.Fprintf(&b, " — %s", c.Detail)
			}
			b.WriteByte('\n')
		}
	}
	section("new", "+", d.New)
	section("resolved", "-", d.Resolved)

	if len(d.NewHosts) > 0 {
		fmt.Fprintf(&b, "\nhosts exposed only now: %s\n", strings.Join(d.NewHosts, ", "))
	}
	if len(d.GoneHosts) > 0 {
		fmt.Fprintf(&b, "\nhosts no longer exposed: %s\n", strings.Join(d.GoneHosts, ", "))
	}
	if len(d.New) == 0 && len(d.Resolved) == 0 {
		b.WriteString("\nno change in exposure.\n")
	}
	return b.String()
}

func portProto(c Change) string {
	if c.Port == 0 {
		return c.Proto
	}
	return fmt.Sprintf("%d/%s", c.Port, c.Proto)
}
