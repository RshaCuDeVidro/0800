package ui

import (
	"context"
	"io"
	"strings"
	"time"

	"github.com/rsha/0800/internal/scan"
)

// NewDemo builds a deterministic model for documentation, screenshots and UI
// tests. It uses only TEST-NET-2 and TEST-NET-3 addresses (RFC 5737).
func NewDemo(width, height int, variant string) *Model {
	hosts := []string{
		"192.0.2.10", "192.0.2.24", "192.0.2.90",
		"198.51.100.7", "198.51.100.42", "198.51.100.200",
		"203.0.113.9", "203.0.113.55",
	}
	st := scan.NewStore(hosts, nil)

	// 1. Domain controller with a null session.
	st.PortOpen("192.0.2.10", 445)
	st.PortOpen("192.0.2.10", 88)
	st.PortOpen("192.0.2.10", 389)
	st.SetSMB("192.0.2.10", &scan.SMBView{
		Dialect: "3.0.2", Signing: "disabled", SMB1: false,
		Host: "DC01", Domain: "corp.local", NetBIOS: "CORP",
		Auth: "null",
		Shares: []scan.ShareView{
			{Name: "C$", Type: "disk", Comment: "Default share"},
			{Name: "IPC$", Type: "pipe", Comment: "Remote IPC"},
			{Name: "NETLOGON", Type: "disk", Comment: "Logon server share"},
			{Name: "SYSVOL", Type: "disk", Comment: "Logon server share"},
		},
	})
	st.SetLDAP("192.0.2.10", &scan.LDAPView{
		Bound: true, Code: 0, Entries: 4, Sample: []string{"svc_backup", "helpdesk", "j.silva", "admin"},
		DefaultDN: "DC=corp,DC=local", DNSHost: "dc01.corp.local",
		Vendor: "Microsoft", Version: "10.0.17763", IsDC: true,
	})
	st.SetService("192.0.2.10", scan.ServiceView{
		Port: 445, Proto: "smb", Banner: "DC01 corp.local",
		KV: [][2]string{{"netbios", "CORP"}, {"dialect", "3.0.2"}, {"signing", "disabled"}},
	})
	st.AddFinding("192.0.2.10", scan.Finding{
		Port: 445, Proto: "smb", Kind: "smb-null", Label: "null session", Severity: scan.SevCritical,
		Detail: "anonymous SMB session accepted · dialect 3.0.2 · signing disabled",
		Evidence: []string{
			"SESSION_SETUP null -> SUCCESS (guest=false null=true)",
			"NetrShareEnum -> 4 shares",
		},
	})
	st.AddFinding("192.0.2.10", scan.Finding{
		Port: 445, Proto: "smb", Kind: "smb-shares", Label: "shares", Severity: scan.SevHigh,
		Detail: "4 share(s): C$, IPC$, NETLOGON, SYSVOL",
	})
	st.AddFinding("192.0.2.10", scan.Finding{
		Port: 389, Proto: "ldap", Kind: "ldap-anon", Label: "anon search", Severity: scan.SevHigh,
		Detail: "anonymous bind returned 4 object(s) from DC=corp,DC=local",
		Evidence: []string{
			"bind(anonym) -> 0",
			"search(DC=corp,DC=local, onelevel, sizeLimit=5) -> 4 entries",
		},
	})
	st.AddFinding("192.0.2.10", scan.Finding{
		Port: 445, Proto: "smb", Kind: "smb-signing", Label: "signing off", Severity: scan.SevLow,
		Detail: "SMB signing disabled (relay surface)",
	})
	st.Finish("192.0.2.10", 820*time.Millisecond)

	// 2. Appliance with a guest-writable share.
	st.PortOpen("192.0.2.24", 445)
	st.SetSMB("192.0.2.24", &scan.SMBView{
		Dialect: "2.1", Signing: "disabled", SMB1: true,
		Host: "BRCM-SAMBA_TEST", Domain: "WORKGROUP", Auth: "guest",
		Shares: []scan.ShareView{
			{Name: "IPC$", Type: "pipe", Comment: "IPC Service (DSL Gateway)"},
			{Name: "public", Type: "disk", Comment: "shared folders on each volume"},
			{Name: "storage", Type: "disk", Comment: "All storage devices", Writable: true},
		},
	})
	st.AddFinding("192.0.2.24", scan.Finding{
		Port: 445, Proto: "smb", Kind: "smb-guest", Label: "guest login", Severity: scan.SevHigh,
		Detail: "guest account accepted with empty password · dialect 2.1 · signing disabled",
		Evidence: []string{
			"SESSION_SETUP guest -> SUCCESS (guest=true)",
			"NetrShareEnum -> 3 shares",
		},
	})
	st.AddFinding("192.0.2.24", scan.Finding{
		Port: 445, Proto: "smb", Kind: "smb-write", Label: "write access", Severity: scan.SevCritical,
		Detail: "writable share(s) as unauthenticated user: storage",
	})
	st.Finish("192.0.2.24", 640*time.Millisecond)

	// 3. Web host: SMB present but closed.
	st.PortOpen("192.0.2.90", 8080)
	st.SetService("192.0.2.90", scan.ServiceView{Port: 8080, Proto: "tcp", Banner: "HTTP/1.1 200 OK"})
	st.Finish("192.0.2.90", 310*time.Millisecond)

	// 4. NFS server with readable exports.
	st.PortOpen("198.51.100.7", 2049)
	st.SetNFS("198.51.100.7", &scan.NFSView{
		Port: 2049, MountPort: 20048, Version: "3",
		Exports: []scan.ExportView{
			{Path: "/srv/backup", Mounted: true, Groups: []string{"*"}},
			{Path: "/srv/media", Mounted: true, Groups: []string{"10.0.0.0/8"}},
		},
	})
	st.AddFinding("198.51.100.7", scan.Finding{
		Port: 2049, Proto: "nfs", Kind: "nfs-read", Label: "nfs read", Severity: scan.SevHigh,
		Detail: "readable without credentials: /srv/backup (42 entries), /srv/media (9 entries)",
		Evidence: []string{
			"MOUNTPROC_EXPORT -> 2 export(s)",
			"MOUNTPROC_MNT -> 2 mounted",
		},
	})
	st.Finish("198.51.100.7", 1_120*time.Millisecond)

	// 5. Postgres in trust mode.
	st.PortOpen("198.51.100.42", 5432)
	st.AddDB("198.51.100.42", scan.DBView{
		Port: 5432, Proto: "postgres", Version: "16.2", User: "postgres", Status: "open",
		Detail: []string{"trust authentication for postgres", "server_version 16.2"},
	})
	st.AddFinding("198.51.100.42", scan.Finding{
		Port: 5432, Proto: "postgres", Kind: "postgres-open", Label: "postgres open",
		Severity: scan.SevCritical,
		Detail:   `postgres accepted user "postgres" with an empty password`,
		Evidence: []string{"StartupMessage -> AuthenticationOk", "server_version 16.2"},
	})
	st.Finish("198.51.100.42", 780*time.Millisecond)

	// 6. Redis without a password.
	st.PortOpen("203.0.113.9", 6379)
	st.AddDB("203.0.113.9", scan.DBView{
		Port: 6379, Proto: "redis", Version: "7.2.4", Status: "open",
		Detail: []string{"PING answered without credentials", "dbsize 1284"},
	})
	st.AddFinding("203.0.113.9", scan.Finding{
		Port: 6379, Proto: "redis", Kind: "redis-open", Label: "redis open",
		Severity: scan.SevCritical, Detail: "PING answered without credentials",
		Evidence: []string{"+PONG", "INFO server -> redis_version:7.2.4"},
	})
	st.Finish("203.0.113.9", 410*time.Millisecond)

	// 7. Hardened-ish host: port open, guest denied.
	st.PortOpen("203.0.113.55", 445)
	st.SetSMB("203.0.113.55", &scan.SMBView{
		Dialect: "3.1.1", Signing: "required", SMB1: false,
		Host: "WIN-V1L1EQID3OA", Domain: "WIN-V1L1EQID3OA",
		EnumErr: "STATUS_ACCESS_DENIED",
	})
	st.Finish("203.0.113.55", 590*time.Millisecond)

	// 8. Still scanning (visible in the progress bar).
	st.PortOpen("198.51.100.200", 88)
	st.SetState("198.51.100.200", scan.StateScanning)

	st.Refresh()

	m := New(Config{
		Store:      st,
		LootDir:    "0800-loot",
		Version:    "0.1.0",
		Width:      width,
		Height:     height,
		NFSTimeout: 8 * time.Second,
	})

	switch variant {
	case "browser":
		m.cursor = indexOf(m.hosts, "192.0.2.24")
		m.focus = 1
		m.browser = browser{
			mode: modeDir, proto: "smb", auth: "guest",
			hostIP: "192.0.2.24", hostTag: "BRCM-SAMBA_TEST",
			share: "public", path: "financeiro/2026",
			cursor: 3,
			fs:     demoFS{},
			entries: []remoteEntry{
				{Name: "..", Dir: true, up: true},
				{Name: "contratos", Dir: true},
				{Name: "fornecedores", Dir: true},
				{Name: "planilhas", Dir: true},
				{Name: "backup-2026-03.zip", Size: 18_432_112, ModTime: time.Now()},
				{Name: "folha-pagamento.xlsx", Size: 412_880, ModTime: time.Now()},
				{Name: "notas-fiscais.xml", Size: 9_442, ModTime: time.Now()},
				{Name: "senhas.txt", Size: 1_284, ModTime: time.Now()},
			},
		}
		m.browser.cursor = 3

	case "details":
		m.cursor = indexOf(m.hosts, "192.0.2.10")
		m.showDetails = true
		m.focus = 1

	case "help":
		m.showHelp = true
	}

	return m
}

func indexOf(hosts []*scan.HostView, ip string) int {
	for i, h := range hosts {
		if h.IP == ip {
			return i
		}
	}
	return 0
}

// demoFS lets the browser render without touching the network.
type demoFS struct{}

func (demoFS) List(context.Context, string) ([]remoteEntry, error) {
	return []remoteEntry{
		{Name: "contratos", Dir: true},
		{Name: "fornecedores", Dir: true},
		{Name: "planilhas", Dir: true},
		{Name: "backup-2026-03.zip", Size: 18_432_112},
		{Name: "folha-pagamento.xlsx", Size: 412_880},
		{Name: "notas-fiscais.xml", Size: 9_442},
		{Name: "senhas.txt", Size: 1_284},
	}, nil
}

func (demoFS) Open(context.Context, string) (io.ReadCloser, int64, error) {
	return io.NopCloser(strings.NewReader("")), 0, nil
}

func (demoFS) Close() error { return nil }
