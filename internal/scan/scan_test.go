package scan

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestStoreDerivesTagsAndDC(t *testing.T) {
	st := NewStore([]string{"192.0.2.10"}, nil)
	st.PortOpen("192.0.2.10", 445)
	st.PortOpen("192.0.2.10", 88)
	st.PortOpen("192.0.2.10", 389)
	st.SetSMB("192.0.2.10", &SMBView{
		Dialect: "3.0.2", Signing: "disabled", Auth: "null",
		Host: "DC01", Domain: "corp.local",
		Shares: []ShareView{{Name: "SYSVOL", Type: "disk"}},
	})
	st.AddFinding("192.0.2.10", Finding{
		Port: 445, Proto: "smb", Kind: "smb-null", Label: "null session", Severity: SevCritical,
	})
	st.Finish("192.0.2.10", 100*time.Millisecond)
	st.Refresh()

	snap := st.Snapshot()
	if len(snap.Hosts) != 1 {
		t.Fatalf("hosts = %d", len(snap.Hosts))
	}
	h := snap.Hosts[0]
	if h.Sev != SevCritical {
		t.Errorf("severity = %v", h.Sev)
	}
	if !h.DC {
		t.Error("expected DC heuristics to fire")
	}
	if len(h.Tags) < 2 {
		t.Errorf("tags = %+v", h.Tags)
	}
	if snap.Done != 1 || snap.Open != 3 || snap.Findings != 1 {
		t.Errorf("counters: %+v", snap)
	}
	if len(snap.Vulnerable()) != 1 {
		t.Error("host should be vulnerable")
	}
}

func TestStoreSnapshotsAreImmutable(t *testing.T) {
	st := NewStore([]string{"192.0.2.1"}, nil)
	st.PortOpen("192.0.2.1", 445)
	st.Refresh()
	first := st.Snapshot()

	st.PortOpen("192.0.2.1", 389)
	st.Refresh()
	second := st.Snapshot()

	if len(first.Hosts[0].Ports) != 1 {
		t.Errorf("old snapshot mutated: %v", first.Hosts[0].Ports)
	}
	if len(second.Hosts[0].Ports) != 2 {
		t.Errorf("new snapshot missing port: %v", second.Hosts[0].Ports)
	}
}

// TestStoreSMBViewIsCloned guards against a caller that keeps a *SMBView
// around after SetSMB and mutates it further (common pattern: build it
// once, enrich it as more of the probe completes). A published snapshot
// must never see that later mutation.
func TestStoreSMBViewIsCloned(t *testing.T) {
	st := NewStore([]string{"192.0.2.1"}, nil)
	smb := &SMBView{Auth: "null", Shares: []ShareView{{Name: "C$"}}}
	st.SetSMB("192.0.2.1", smb)
	st.Refresh()
	snap := st.Snapshot()

	// Mutate the struct the caller still holds, after publishing.
	smb.Auth = "guest"
	smb.Shares[0].Name = "mutated"
	smb.Shares = append(smb.Shares, ShareView{Name: "new"})

	got := snap.Hosts[0].SMB
	if got.Auth != "null" {
		t.Errorf("published SMBView.Auth = %q, want %q (unaffected by later mutation)", got.Auth, "null")
	}
	if len(got.Shares) != 1 || got.Shares[0].Name != "C$" {
		t.Errorf("published SMBView.Shares = %+v, want untouched [{C$}]", got.Shares)
	}
}

func TestEngineScansAndEmits(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	var (
		mu     sync.Mutex
		finals []string
	)
	cfg := Config{
		Targets:      []string{"127.0.0.1"},
		Ports:        []int{port},
		Concurrency:  2,
		ProbeWorkers: 1,
		DialTimeout:  500 * time.Millisecond,
		IOTimeout:    time.Second,
		OnFinish: func(h *HostView) {
			mu.Lock()
			finals = append(finals, h.IP)
			mu.Unlock()
		},
		Probe: func(ctx context.Context, e *Engine, ip string, p int) {
			e.store.AddFinding(ip, Finding{
				Port: p, Proto: "test", Kind: "test", Label: "open",
				Severity: SevHigh, Detail: "probe ran",
			})
		},
	}
	eng := New(cfg)
	if eng.Store() == nil {
		t.Fatal("store must exist before Run")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := eng.Run(ctx); err != nil {
		t.Fatal(err)
	}

	snap := eng.Store().Snapshot()
	if snap.Done != 1 || snap.Open != 1 {
		t.Fatalf("counters: done=%d open=%d", snap.Done, snap.Open)
	}
	if snap.Findings != 1 {
		t.Errorf("findings = %d", snap.Findings)
	}
	if !snap.Finished {
		t.Error("scan should be finished")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(finals) != 1 || finals[0] != "127.0.0.1" {
		t.Errorf("onFinish = %v", finals)
	}
}

// TestDispatchFTPAnonymous drives the real FTP prober (internal/ftp) through
// Engine.dispatch end to end: port 21 must route to probeFTP, and an
// anonymous-accepting server must produce both the FTPView and the finding.
func TestDispatchFTPAnonymous(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("220 fake ftp\r\n"))
		buf := make([]byte, 256)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			cmd := string(buf[:n])
			switch {
			case len(cmd) >= 4 && cmd[:4] == "USER":
				_, _ = conn.Write([]byte("331 need password\r\n"))
			case len(cmd) >= 4 && cmd[:4] == "PASS":
				_, _ = conn.Write([]byte("230 logged in\r\n"))
			default:
				_, _ = conn.Write([]byte("221 bye\r\n"))
				return
			}
		}
	}()

	port := ln.Addr().(*net.TCPAddr).Port
	eng := New(Config{
		Targets:      []string{"127.0.0.1"},
		Ports:        []int{port},
		ServicePorts: map[int]string{port: "ftp"}, // ephemeral test port, not 21
	})
	if got := eng.serviceFor(port); got != "ftp" {
		t.Fatalf("serviceFor(%d) = %q, want ftp", port, got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	eng.dispatch(ctx, "127.0.0.1", port)
	eng.store.Refresh()

	snap := eng.store.Snapshot()
	h := snap.Hosts[0]
	if h.FTP == nil || !h.FTP.AnonOK {
		t.Fatalf("FTPView = %+v, want AnonOK", h.FTP)
	}
	if h.Discovered() != 1 {
		t.Errorf("expected one medium+ finding, got %d: %+v", h.Discovered(), h.Findings)
	}
	foundTag := false
	for _, tag := range h.Tags {
		if tag.Text == "ftp anon" {
			foundTag = true
		}
	}
	if !foundTag {
		t.Errorf("tags = %+v, want an \"ftp anon\" tag", h.Tags)
	}
}

// TestDialWithRetrySucceedsAfterTransientFailure starts no listener at
// first (dial fails) and only opens the port after a short delay; a client
// configured with Retries>0 must eventually connect, where Retries=0 would
// give up on the very first attempt.
func TestDialWithRetrySucceedsAfterTransientFailure(t *testing.T) {
	// Reserve a free port, then release it immediately so nothing listens yet.
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().(*net.TCPAddr)
	_ = probe.Close()

	listening := make(chan struct{})
	go func() {
		time.Sleep(200 * time.Millisecond)
		ln, err := net.Listen("tcp", addr.String())
		if err != nil {
			close(listening)
			return
		}
		defer ln.Close()
		close(listening)
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
		}
	}()
	defer func() { <-listening }()

	eng := New(Config{
		Targets: []string{addr.IP.String()}, Ports: []int{addr.Port},
		DialTimeout: 100 * time.Millisecond, Retries: 6,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := eng.dialWithRetry(ctx, addr.IP.String(), addr.Port)
	if err != nil {
		t.Fatalf("dialWithRetry failed even with retries: %v", err)
	}
	_ = conn.Close()
}

func TestDialWithRetryGivesUpAfterConfiguredAttempts(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().(*net.TCPAddr)
	_ = probe.Close() // nothing ever listens on this port

	eng := New(Config{
		Targets: []string{addr.IP.String()}, Ports: []int{addr.Port},
		DialTimeout: 100 * time.Millisecond, Retries: 1,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := eng.dialWithRetry(ctx, addr.IP.String(), addr.Port); err == nil {
		t.Fatal("expected an error dialing a port nobody listens on")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("dialWithRetry took %v, want it bounded by Retries=1", elapsed)
	}
}

func TestEngineClosedPort(t *testing.T) {
	// Grab a free port and close it again.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	eng := New(Config{
		Targets:     []string{"127.0.0.1"},
		Ports:       []int{port},
		Concurrency: 1,
		DialTimeout: 300 * time.Millisecond,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := eng.Run(ctx); err != nil {
		t.Fatal(err)
	}
	snap := eng.Store().Snapshot()
	if snap.Open != 0 || snap.Done != 1 {
		t.Fatalf("open=%d done=%d", snap.Open, snap.Done)
	}
}

func TestEngineCancellation(t *testing.T) {
	eng := New(Config{
		Targets:     []string{"192.0.2.1", "192.0.2.2"},
		Ports:       []int{445},
		Concurrency: 1,
		DialTimeout: 2 * time.Second,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = eng.Run(ctx)
	// Cancellation must not panic and must leave a readable store.
	_ = eng.Store().Snapshot()
}

func TestHostViewHelpers(t *testing.T) {
	h := &HostView{IP: "192.0.2.5", Ports: []int{88, 445}, DC: true}
	if !h.Has(88) || h.Has(389) {
		t.Error("Has failed")
	}
	h.SMB = &SMBView{Auth: "guest", Shares: []ShareView{{Name: "public"}}}
	if !h.Browsable() {
		t.Error("expected browsable")
	}
	s := h.Summary()
	if s == "" || s[0] != '1' {
		t.Errorf("summary = %q", s)
	}
	_ = strconv.Itoa(0)
}
