package scan

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Severity ranks a finding. It drives both the UI colours and the report.
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

// MarshalJSON renders severity as a string so reports stay readable.
func (s Severity) MarshalJSON() ([]byte, error) { return []byte(`"` + s.String() + `"`), nil }

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "critical"
	case SevHigh:
		return "high"
	case SevMedium:
		return "medium"
	case SevLow:
		return "low"
	default:
		return "info"
	}
}

// State is the lifecycle of a single host.
type State int

const (
	StatePending State = iota
	StateScanning
	StateDone
)

func (s State) String() string {
	switch s {
	case StateScanning:
		return "scanning"
	case StateDone:
		return "done"
	default:
		return "pending"
	}
}

// Finding is a single, self-describing result. Evidence is mandatory: a finding
// without a request/response trace is an opinion, not a result.
type Finding struct {
	Port     int      `json:"port"`
	Proto    string   `json:"proto"`
	Kind     string   `json:"kind"`
	Label    string   `json:"label"`
	Severity Severity `json:"severity"`
	Detail   string   `json:"detail"`
	Evidence []string `json:"evidence,omitempty"`
}

// Tag is a compact badge rendered in the host list.
type Tag struct {
	Text string
	Sev  Severity
}

// ShareView is a remote SMB share.
type ShareView struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Comment  string `json:"comment,omitempty"`
	Writable bool   `json:"writable,omitempty"`
}

// SMBView is everything the SMB prober learned about a host.
type SMBView struct {
	Dialect string      `json:"dialect,omitempty"`
	Signing string      `json:"signing,omitempty"`
	SMB1    bool        `json:"smb1"`
	Host    string      `json:"host,omitempty"`
	Domain  string      `json:"domain,omitempty"`
	NetBIOS string      `json:"netbios,omitempty"`
	OS      string      `json:"os,omitempty"`
	Auth    string      `json:"auth,omitempty"` // "", "null", "guest"
	Shares  []ShareView `json:"shares,omitempty"`
	EnumErr string      `json:"enumErr,omitempty"`
	NTLMOff bool        `json:"ntlmDisabled,omitempty"`
}

// ExportView is a single NFS export.
type ExportView struct {
	Path    string   `json:"path"`
	Groups  []string `json:"groups,omitempty"`
	Mounted bool     `json:"mounted"`
}

// NFSView is everything the NFS prober learned about a host.
type NFSView struct {
	Port      uint16       `json:"port,omitempty"`
	MountPort uint16       `json:"mountPort,omitempty"`
	Exports   []ExportView `json:"exports,omitempty"`
	Version   string       `json:"version,omitempty"`
	Note      string       `json:"note,omitempty"`
}

// DBView describes an exposed database service.
type DBView struct {
	Port    int      `json:"port"`
	Proto   string   `json:"proto"`
	Version string   `json:"version,omitempty"`
	User    string   `json:"user,omitempty"`
	Status  string   `json:"status,omitempty"`
	Detail  []string `json:"detail,omitempty"`
}

// LDAPView is the result of the anonymous LDAP probe.
type LDAPView struct {
	Bound     bool     `json:"bound"`
	Code      int      `json:"code"`
	Message   string   `json:"message,omitempty"`
	Entries   int      `json:"entries"`
	Sample    []string `json:"sample,omitempty"`
	DefaultDN string   `json:"defaultDN,omitempty"`
	DNSHost   string   `json:"dnsHost,omitempty"`
	Vendor    string   `json:"vendor,omitempty"`
	Version   string   `json:"version,omitempty"`
	IsDC      bool     `json:"isDC"`
}

// HostView is an immutable snapshot of one host. It is published through
// Store.Snapshot and must never be mutated after publication.
type HostView struct {
	IP       string        `json:"ip"`
	Name     string        `json:"name,omitempty"`
	State    State         `json:"-"`
	Ports    []int         `json:"ports,omitempty"`
	Tags     []Tag         `json:"-"`
	Sev      Severity      `json:"-"`
	Detail   string        `json:"detail,omitempty"`
	Findings []Finding     `json:"findings,omitempty"`
	Services []ServiceView `json:"services,omitempty"`
	SMB      *SMBView      `json:"smb,omitempty"`
	NFS      *NFSView      `json:"nfs,omitempty"`
	LDAP     *LDAPView     `json:"ldap,omitempty"`
	DBs      []DBView      `json:"databases,omitempty"`
	DC       bool          `json:"domainController,omitempty"`
	Err      string        `json:"error,omitempty"`
	Started  time.Time     `json:"-"`
	Took     time.Duration `json:"-"`
}

// ServiceView is a generic open port description.
type ServiceView struct {
	Port   int         `json:"port"`
	Proto  string      `json:"proto"`
	Banner string      `json:"banner,omitempty"`
	KV     [][2]string `json:"-"`
}

// Browsable reports whether the right-hand panel can open a file tree.
func (h *HostView) Browsable() bool {
	if h.SMB != nil && h.SMB.Auth != "" && len(h.SMB.Shares) > 0 && h.SMB.Signing != "required" {
		return true
	}
	return h.NFS != nil && len(h.NFS.Exports) > 0
}

// Has reports whether the host exposes the given port.
func (h *HostView) Has(port int) bool {
	for _, p := range h.Ports {
		if p == port {
			return true
		}
	}
	return false
}

// Discovered counts findings that represent real exposure (auth bypass, open
// share, anonymous service) as opposed to bare port information.
func (h *HostView) Discovered() int {
	n := 0
	for _, f := range h.Findings {
		if f.Severity >= SevMedium {
			n++
		}
	}
	return n
}

// Summary renders a compact, machine-friendly one-liner used by --plain and
// the session log.
func (h *HostView) Summary() string {
	var b strings.Builder
	b.WriteString(h.IP)
	if h.Name != "" && h.Name != h.IP {
		b.WriteString(" (")
		b.WriteString(h.Name)
		b.WriteString(")")
	}
	if len(h.Ports) > 0 {
		b.WriteString(" ports=")
		b.WriteString(joinInts(h.Ports))
	}
	for _, f := range h.Findings {
		b.WriteString(" | ")
		b.WriteString(f.Label)
		if f.Detail != "" {
			b.WriteString(": ")
			b.WriteString(f.Detail)
		}
	}
	if h.Err != "" {
		b.WriteString(" | err: ")
		b.WriteString(h.Err)
	}
	return b.String()
}

func joinInts(v []int) string {
	var b strings.Builder
	for i, n := range v {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%d", n)
	}
	return b.String()
}

// Snapshot is the complete, immutable state published to the UI.
type Snapshot struct {
	Hosts    []*HostView
	Total    int
	Done     int
	Open     int
	Findings int
	Started  time.Time
	Elapsed  time.Duration
	Finished bool
}

// Vulnerable returns the hosts that have at least one medium+ finding.
func (s *Snapshot) Vulnerable() []*HostView {
	out := make([]*HostView, 0, 8)
	for _, h := range s.Hosts {
		if h.Discovered() > 0 {
			out = append(out, h)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Sev > out[j].Sev })
	return out
}
