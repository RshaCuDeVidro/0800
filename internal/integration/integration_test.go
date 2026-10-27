//go:build integration

// Package integration contains opt-in tests that talk to a real lab.
//
//	0800_SMB_HOST=192.0.2.10 \
//	0800_LDAP_HOST=192.0.2.10 \
//	0800_NFS_HOST=192.0.2.10 \
//	0800_DB_HOST=192.0.2.10 \
//	go test -tags integration ./internal/integration -v
//
// Points them only at systems you own or are authorised to test.
package integration

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/rsha/0800/internal/db"
	"github.com/rsha/0800/internal/ldap"
	"github.com/rsha/0800/internal/nfs"
	"github.com/rsha/0800/internal/smb"
)

func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestSMB(t *testing.T) {
	host := os.Getenv("0800_SMB_HOST")
	if host == "" {
		t.Skip("set 0800_SMB_HOST to run")
	}
	cfg := smb.DefaultConfig()
	cfg.DialTimeout = 5 * time.Second
	cfg.IOTimeout = 15 * time.Second

	p, err := smb.ProbeHost(ctx(t), host, cfg)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	t.Logf("dialect=%s signing=%s smb1=%t auth=%q host=%q domain=%q shares=%d",
		p.Dialect, p.Signing, p.SMB1, p.AuthKind(),
		p.Identity.DNSName, p.Identity.DNSDomain, len(p.Shares))
	if p.Dialect == "" && !p.SMB1 {
		t.Fatal("no SMB dialect detected")
	}
	if p.AuthKind() != "" && p.Signing != "required" && len(p.Shares) == 0 {
		t.Log("note: authenticated but no shares enumerated (RPC may be blocked)")
	}
}

func TestLDAP(t *testing.T) {
	host := os.Getenv("0800_LDAP_HOST")
	if host == "" {
		t.Skip("set 0800_LDAP_HOST to run")
	}
	res, err := ldap.Probe(ctx(t), host+":389", 10*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	t.Logf("bind=%d bound=%t base=%q host=%q entries=%d",
		res.BindCode, res.Bound, res.DefaultDN, res.Host, res.Entries)
}

func TestNFS(t *testing.T) {
	host := os.Getenv("0800_NFS_HOST")
	if host == "" {
		t.Skip("set 0800_NFS_HOST to run")
	}
	res, err := nfs.Probe(ctx(t), host, nfs.Config{Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	t.Logf("version=%s exports=%d", res.Version, len(res.Exports))
	for _, ex := range res.Exports {
		t.Logf("  %s mounted=%t entries=%d", ex.Path, ex.Mounted, ex.Entries)
	}
}

func TestDatabases(t *testing.T) {
	host := os.Getenv("0800_DB_HOST")
	if host == "" {
		t.Skip("set 0800_DB_HOST to run")
	}
	ports := []int{3306, 5432, 6379}
	if raw := os.Getenv("0800_DB_PORTS"); raw != "" {
		ports = ports[:0]
		for _, f := range splitCSV(raw) {
			n, err := strconv.Atoi(f)
			if err != nil {
				t.Fatalf("bad 0800_DB_PORTS: %v", err)
			}
			ports = append(ports, n)
		}
	}
	for _, p := range ports {
		res := db.Probe(ctx(t), host, p, 8*time.Second)
		t.Logf("%d %s status=%s version=%q user=%q err=%q",
			p, res.Proto, res.Status, res.Version, res.User, res.Err)
	}
}

func splitCSV(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == ',' {
			if cur != "" {
				out = append(out, cur)
				cur = ""
			}
			continue
		}
		cur += string(r)
	}
	if cur != "" {
		out = append(out, cur)
	}
	return out
}
