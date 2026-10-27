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
	recent   []RecentFinding

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

	snap := &Snapshot{
		Hosts:    hosts,
		Total:    s.total,
		Done:     s.done,
		Open:     s.open,
		Findings: s.findings,
		Started:  s.started,
		Elapsed:  time.Since(s.started),
		Finished: s.finished,
		ByProto:  map[string]int{},
	}
	for _, h := range s.hosts {
		if h.SMB != nil {
			snap.ByProto["smb"]++
		}
		if h.LDAP != nil {
			snap.ByProto["ldap"]++
		}
		if h.NFS != nil {
			snap.ByProto["nfs"]++
		}
		if h.FTP != nil {
			snap.ByProto["ftp"]++
		}
		for _, f := range h.Findings {
			switch f.Severity {
			case SevCritical:
				snap.Crit++
			case SevHigh:
				snap.High++
			case SevMedium:
				snap.Med++
			case SevLow:
				snap.Low++
			}
		}
		for _, d := range h.DBs {
			snap.ByProto[d.Proto]++
		}
		if h.Discovered() > 0 {
			snap.Exposed++
		}
	}
	// Top exposures, kept short so the UI never sorts on every frame.
	ranked := make([]*HostView, 0, len(s.hosts))
	for _, h := range s.hosts {
		if h.Discovered() > 0 {
			ranked = append(ranked, h)
		}
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].Sev != ranked[j].Sev {
			return ranked[i].Sev > ranked[j].Sev
		}
		return ranked[i].Discovered() > ranked[j].Discovered()
	})
	if len(ranked) > 8 {
		ranked = ranked[:8]
	}
	snap.Top = ranked
	if n := len(s.recent); n > 0 {
		snap.Recent = append([]RecentFinding(nil), s.recent...)
		sort.SliceStable(snap.Recent, func(i, j int) bool { return snap.Recent[i].At.Before(snap.Recent[j].At) })
	}
	s.snap.Store(snap)
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
		switch v.SMB.Signing {
		case "disabled":
			add("sig off", SevLow)
		case "enabled":
			add("sig optional", SevInfo)
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
	if v.FTP != nil && v.FTP.AnonOK {
		add("ftp anon", SevHigh)
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
	if v.FTP != nil && v.FTP.AnonOK {
		return "ftp · anonymous login"
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

// SetService records the banner for an open port. KV is cloned (see SetSMB):
// callers sometimes build it once and reuse the backing array across calls.
func (s *Store) SetService(ip string, svc ServiceView) {
	svc.KV = append([][2]string(nil), svc.KV...)
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
	if f.At.IsZero() {
		f.At = time.Now()
	}
	s.mu.Lock()
	if f.Severity >= SevMedium {
		s.findings++
	}
	s.recent = append(s.recent, RecentFinding{
		At: f.At, IP: ip, Port: f.Port, Proto: f.Proto,
		Label: f.Label, Detail: f.Detail, Sev: f.Severity,
	})
	if len(s.recent) > 64 {
		s.recent = s.recent[len(s.recent)-64:]
	}
	s.mu.Unlock()
	s.mutate(ip, func(v *HostView) {
		v.Findings = append(v.Findings, f)
	})
}

// SetSMB stores the SMB fingerprint for a host. The view is cloned so a
// caller that keeps mutating its own *SMBView after the call (e.g. to add
// shares found on a later probe) can never reach back into an already
// published, supposedly immutable snapshot.
func (s *Store) SetSMB(ip string, smb *SMBView) {
	smb = cloneSMB(smb)
	s.mutate(ip, func(v *HostView) {
		v.SMB = smb
		if smb != nil && smb.Host != "" && v.Name == "" {
			v.Name = smb.Host
		}
	})
}

// SetNFS stores the NFS fingerprint for a host (cloned; see SetSMB).
func (s *Store) SetNFS(ip string, nfs *NFSView) {
	nfs = cloneNFS(nfs)
	s.mutate(ip, func(v *HostView) { v.NFS = nfs })
}

// SetLDAP stores the LDAP fingerprint for a host (cloned; see SetSMB).
func (s *Store) SetLDAP(ip string, l *LDAPView) {
	l = cloneLDAP(l)
	s.mutate(ip, func(v *HostView) {
		v.LDAP = l
		if l != nil && l.DNSHost != "" && v.Name == "" {
			v.Name = l.DNSHost
		}
	})
}

// cloneSMB returns a deep-enough copy of v: the struct plus its one slice
// field, so the stored snapshot never aliases memory the caller still holds.
func cloneSMB(v *SMBView) *SMBView {
	if v == nil {
		return nil
	}
	c := *v
	c.Shares = append([]ShareView(nil), v.Shares...)
	return &c
}

func cloneNFS(v *NFSView) *NFSView {
	if v == nil {
		return nil
	}
	c := *v
	c.Exports = append([]ExportView(nil), v.Exports...)
	return &c
}

func cloneLDAP(v *LDAPView) *LDAPView {
	if v == nil {
		return nil
	}
	c := *v
	c.Sample = append([]string(nil), v.Sample...)
	return &c
}

// SetFTP stores the FTP fingerprint for a host (cloned; see SetSMB).
func (s *Store) SetFTP(ip string, f *FTPView) {
	if f != nil {
		clone := *f
		f = &clone
	}
	s.mutate(ip, func(v *HostView) { v.FTP = f })
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

// Restore seeds hosts from an earlier run (--resume): their views replace the
// empty ones, derived fields are recomputed, and the global counters account
// for what they contain. The caller still Finishes them so Done counts them.
func (s *Store) Restore(prev []*HostView) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range prev {
		i, ok := s.index[p.IP]
		if !ok {
			continue
		}
		v := *p
		v.Ports = append([]int(nil), p.Ports...)
		v.Findings = append([]Finding(nil), p.Findings...)
		v.DBs = append([]DBView(nil), p.DBs...)
		v.Services = append([]ServiceView(nil), p.Services...)
		v.SMB, v.NFS, v.LDAP = cloneSMB(p.SMB), cloneNFS(p.NFS), cloneLDAP(p.LDAP)
		if p.FTP != nil {
			f := *p.FTP
			v.FTP = &f
		}
		derive(&v, s)
		s.hosts[i] = &v
		s.open += len(v.Ports)
		s.findings += v.Discovered()
	}
	s.dirty = true
}

// Len returns the number of hosts in the scan.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.hosts)
}
