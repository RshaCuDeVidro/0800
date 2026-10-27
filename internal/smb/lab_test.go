package smb_test

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/RshaCuDeVidro/0800/internal/lab"
	"github.com/RshaCuDeVidro/0800/internal/smb"
)

// TestLabSMBInterop exercises the client against the standalone lab server used
// by `go run ./tools/lab`, i.e. a different implementation than the fake in
// smb_test.go.
func TestLabSMBInterop(t *testing.T) {
	srv := lab.NewSMB(lab.SMBConfig{SMB1: true, Signing: "disabled", NullOK: true})
	svc, err := srv.Start(0)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Listener.Close()

	cfg := smb.DefaultConfig()
	cfg.Port = svc.Port
	cfg.IOTimeout = 3 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	p, err := smb.ProbeHost(ctx, "127.0.0.1", cfg)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if p.AuthKind() != "null" {
		t.Errorf("auth = %q, want null", p.AuthKind())
	}
	if p.Dialect != "3.0.2" {
		t.Errorf("dialect = %q", p.Dialect)
	}
	if !p.SMB1 {
		t.Error("lab advertises SMB1")
	}
	if p.Identity.DNSDomain != "lab.local" {
		t.Errorf("dns domain = %q", p.Identity.DNSDomain)
	}
	names := map[string]bool{}
	for _, s := range p.Shares {
		names[s.Name] = true
	}
	if !names["public"] || !names["storage"] {
		t.Errorf("shares = %+v", p.Shares)
	}

	c, err := smb.Connect(ctx, "127.0.0.1", "null", cfg)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	entries, err := c.ReadDir(ctx, "public", "")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 2 || !entries[0].Dir {
		t.Fatalf("entries = %+v", entries)
	}

	rc, size, err := c.Open(ctx, "public", "passwords.txt")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if size != int64(len(data)) || !strings.Contains(string(data), "lab") {
		t.Errorf("size=%d data=%q", size, data)
	}
}
