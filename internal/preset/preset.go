// Package preset holds the scan profiles offered by the CLI and the setup
// wizard.
package preset

import (
	"fmt"
	"strconv"
	"strings"
)

// Preset is a named port profile.
type Preset struct {
	Name  string
	Desc  string
	Ports []int
}

// All lists the built-in profiles. "full" is the default.
var All = []Preset{
	{
		Name:  "full",
		Desc:  "SMB, LDAP, NFS, FTP and databases",
		Ports: []int{21, 445, 88, 389, 2049, 3306, 5432, 6379},
	},
	{
		Name:  "quick",
		Desc:  "SMB + LDAP only, fastest sweep",
		Ports: []int{445, 389},
	},
	{
		Name:  "ad",
		Desc:  "domain controller surface",
		Ports: []int{445, 88, 389, 636, 3268},
	},
	{
		Name:  "smb",
		Desc:  "file shares only",
		Ports: []int{445},
	},
	{
		Name:  "db",
		Desc:  "MySQL, PostgreSQL and Redis",
		Ports: []int{3306, 5432, 6379},
	},
}

// Default is the profile used when none is given.
const Default = "full"

// Find returns the preset with the given name (case insensitive).
func Find(name string) (Preset, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, p := range All {
		if p.Name == name {
			return p, true
		}
	}
	return Preset{}, false
}

// ParsePorts parses "445,88,389" into a de-duplicated port list.
func ParsePorts(spec string) ([]int, error) {
	seen := map[int]bool{}
	var out []int
	for _, raw := range strings.Split(spec, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q", raw)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ports to scan")
	}
	return out, nil
}

// Names returns the profile names in display order.
func Names() []string {
	out := make([]string, 0, len(All))
	for _, p := range All {
		out = append(out, p.Name)
	}
	return out
}

// Format renders a preset's ports as a comma separated list.
func (p Preset) Format() string {
	var b strings.Builder
	for i, n := range p.Ports {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(itoa(n))
	}
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
