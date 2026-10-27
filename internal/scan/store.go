package scan

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Store holds all scan state. The UI only ever reads immutable snapshots, so a
// slow render never blocks the workers and there is no data race by design.
type Store struct {
	mu       sync.Mutex
	hosts    []*HostView
	index    map[string]int
	total    int
	done     int
	open     int
	findings int
	started  time.Time
	finished bool
	dirty    bool

	snap atomic.Pointer[Snapshot]

	onFinish func(*HostView)
}

// NewStore creates an empty store for the given hosts. The engine uses it
// internally; tests and the demo mode use it to seed deterministic state.
func NewStore(hosts []string, onFinish func(*HostView)) *Store {
	s := &Store{
		hosts:    make([]*HostView, len(hosts)),
		index:    make(map[string]int, len(hosts)),
		total:    len(hosts),
		started:  time.Now(),
		onFinish: onFinish,
	}
	for i, ip := range hosts {
		s.hosts[i] = &HostView{IP: ip, State: StatePending, Started: time.Now()}
		s.index[ip] = i
	}
	s.publishLocked()
	return s
}

// Refresh publishes pending mutations. The engine does this on a timer; tests
// and the demo mode call it explicitly.
func (s *Store) Refresh() {
	s.mu.Lock()
	s.publishLocked()
	s.dirty = false
	s.mu.Unlock()
}

// Snapshot returns the most recent immutable view of the scan.
func (s *Store) Snapshot() *Snapshot {
	if p := s.snap.Load(); p != nil {
		return p
	}
	return &Snapshot{Started: s.started}
}

// Run starts the snapshot flusher. It exits when ctx is done.
func (s *Store) Run(ctx context.Context) {
	tick := time.NewTicker(80 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			s.flush()
			return
		case <-tick.C:
			s.flush()
		}
	}
}

func (s *Store) flush() {
	s.mu.Lock()
	dirty := s.dirty
	s.dirty = false
	if dirty {
		s.publishLocked()
	}
	s.mu.Unlock()
}

func (s *Store) publishLocked() {
	hosts := make([]*HostView, len(s.hosts))
	copy(hosts, s.hosts)
	s.snap.Store(&Snapshot{
		Hosts:    hosts,
		Total:    s.total,
		Done:     s.done,
		Open:     s.open,
		Findings: s.findings,
		Started:  s.started,
		Elapsed:  time.Since(s.started),
		Finished: s.finished,
	})
}

// mutate applies fn to a fresh copy of the host view and republishes it. The
// copy keeps published snapshots immutable.
func (s *Store) mutate(ip string, fn func(*HostView)) *HostView {
	s.mu.Lock()
	defer s.mu.Unlock()
	i, ok := s.index[ip]
	if !ok {
		return nil
	}
	old := s.hosts[i]
	next := *old
	next.Ports = append([]int(nil), old.Ports...)
	next.Findings = append([]Finding(nil), old.Findings...)
	next.DBs = append([]DBView(nil), old.DBs...)
	next.Services = append([]ServiceView(nil), old.Services...)
	fn(&next)
	derive(&next, s)
	s.hosts[i] = &next
	s.dirty = true
	return &next
}

// derive recomputes the denormalised fields (tags, severity, summary) so the UI
// never has to.
func derive(v *HostView, s *Store) {
	sort.Ints(v.Ports)

	tags := make([]Tag, 0, 8)
	sev := SevInfo

	add := func(text string, sv Severity) {
		tags = append(tags, Tag{Text: text, Sev: sv})
		if sv > sev {
			sev = sv
		}
	}

	if v.SMB != nil {
		switch v.SMB.Auth {
		case "null":
			add("null auth", SevCritical)
		case "guest":
			add("guest", SevHigh)
		}
		if n := len(v.SMB.Shares); n > 0 {
			sv := SevMedium
			for _, sh := range v.SMB.Shares {
				if sh.Writable {
					sv = SevCritical
				}
			}
			add(fmt.Sprintf("%d shares", n), sv)
		}
		if v.SMB.Signing == "disabled" || v.SMB.Signing == "enabled" {
			add("sig off", SevLow)
		}
		if v.SMB.SMB1 {
			add("smb1", SevLow)
		}
		if v.SMB.NTLMOff {
			add("ntlm off", SevLow)
		}
	}
	if v.NFS != nil && len(v.NFS.Exports) > 0 {
		sv := SevMedium
		for _, e := range v.NFS.Exports {
			if e.Mounted {
				sv = SevHigh
			}
		}
		add(fmt.Sprintf("nfs %d", len(v.NFS.Exports)), sv)
	}
	if v.LDAP != nil {
		switch {
		case v.LDAP.Entries > 0:
			add("ldap anon", SevHigh)
		case v.LDAP.Bound:
			add("ldap bind", SevLow)
		}
	}
	for _, db := range v.DBs {
		if db.Status == "open" {
			add(db.Proto, SevCritical)
		} else {
			add(db.Proto+" auth", SevLow)
		}
	}

	// Domain controller confidence: no single port proves it, the combination
	// of KDC + LDAP/rootDSE + an AD-style SMB identity does.
	score := 0
	if v.Has(88) {
		score++
	}
	if v.Has(389) {
		score++
	}
	if v.SMB != nil && v.SMB.Domain != "" {
		score += 2
	}
	if v.LDAP != nil && v.LDAP.DefaultDN != "" {
		score += 2
	}
	v.DC = score >= 3
	if v.DC {
		add("DC?", SevMedium)
	}
	for _, f := range v.Findings {
		if f.Severity > sev {
			sev = f.Severity
		}
	}
	if v.Err != "" {
		add("error", SevLow)
	}

	sort.SliceStable(tags, func(i, j int) bool { return tags[i].Sev > tags[j].Sev })
	v.Tags = tags
	v.Sev = sev
	v.Detail = summarise(v)
}

func summarise(v *HostView) string {
	if v.SMB != nil && v.SMB.Auth != "" {
		parts := ""
		if v.SMB.Host != "" {
			parts = v.SMB.Host
		}
		if v.SMB.Domain != "" && v.SMB.Domain != v.SMB.Host {
			if parts != "" {
				parts += "."
			}
			parts += v.SMB.Domain
		}
		msg := "smb " + v.SMB.Auth + " auth"
		if parts != "" {
			msg += " · " + parts
		}
		if v.SMB.Signing != "" {
			msg += " · signing " + v.SMB.Signing
		}
		return msg
	}
	if v.NFS != nil && len(v.NFS.Exports) > 0 {
		return fmt.Sprintf("nfs · %d export(s)", len(v.NFS.Exports))
	}
	for _, db := range v.DBs {
		if db.Version != "" {
			return db.Proto + " " + db.Version
		}
	}
	if len(v.Ports) > 0 {
		return fmt.Sprintf("%d open port(s)", len(v.Ports))
	}
	return ""
}

// SetState updates the lifecycle state.
func (s *Store) SetState(ip string, st State) {
	s.mutate(ip, func(v *HostView) { v.State = st })
}

// SetName records a reverse-resolved or SMB-provided host name.
func (s *Store) SetName(ip, name string) {
	if name == "" || name == ip {
		return
	}
	s.mutate(ip, func(v *HostView) { v.Name = name })
}

// PortOpen records an open TCP port.
func (s *Store) PortOpen(ip string, port int) {
	s.mu.Lock()
	s.open++
	s.mu.Unlock()
	s.mutate(ip, func(v *HostView) {
		for _, p := range v.Ports {
			if p == port {
				return
			}
		}
		v.Ports = append(v.Ports, port)
	})
}

// SetService records the banner for an open port.
func (s *Store) SetService(ip string, svc ServiceView) {
	s.mutate(ip, func(v *HostView) {
		for i := range v.Services {
			if v.Services[i].Port == svc.Port {
				v.Services[i] = svc
				return
			}
		}
		v.Services = append(v.Services, svc)
	})
}

// AddFinding appends a finding and bumps the global counter when it is real
// exposure (medium or above).
func (s *Store) AddFinding(ip string, f Finding) {
	if f.Severity >= SevMedium {
		s.mu.Lock()
		s.findings++
		s.mu.Unlock()
	}
	s.mutate(ip, func(v *HostView) {
		v.Findings = append(v.Findings, f)
	})
}

// SetSMB stores the SMB fingerprint for a host.
func (s *Store) SetSMB(ip string, smb *SMBView) {
	s.mutate(ip, func(v *HostView) {
		v.SMB = smb
		if smb.Host != "" && v.Name == "" {
			v.Name = smb.Host
		}
	})
}

// SetNFS stores the NFS fingerprint for a host.
func (s *Store) SetNFS(ip string, nfs *NFSView) {
	s.mutate(ip, func(v *HostView) { v.NFS = nfs })
}

// SetLDAP stores the LDAP fingerprint for a host.
func (s *Store) SetLDAP(ip string, l *LDAPView) {
	s.mutate(ip, func(v *HostView) {
		v.LDAP = l
		if l.DNSHost != "" && v.Name == "" {
			v.Name = l.DNSHost
		}
	})
}

// AddDB stores an exposed database fingerprint.
func (s *Store) AddDB(ip string, db DBView) {
	s.mutate(ip, func(v *HostView) {
		for i := range v.DBs {
			if v.DBs[i].Port == db.Port {
				v.DBs[i] = db
				return
			}
		}
		v.DBs = append(v.DBs, db)
	})
}

// SetError records a host level error.
func (s *Store) SetError(ip, msg string) {
	s.mutate(ip, func(v *HostView) { v.Err = msg })
}

// Finish marks a host complete and emits it to the configured sink.
func (s *Store) Finish(ip string, took time.Duration) {
	s.mu.Lock()
	s.done++
	s.mu.Unlock()
	v := s.mutate(ip, func(v *HostView) {
		v.State = StateDone
		v.Took = took
	})
	if v != nil && s.onFinish != nil {
		s.onFinish(v)
	}
}

// Complete flips the global finished flag.
func (s *Store) Complete() {
	s.mu.Lock()
	s.finished = true
	s.dirty = true
	s.mu.Unlock()
	s.flush()
}

// Len returns the number of hosts in the scan.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.hosts)
}
