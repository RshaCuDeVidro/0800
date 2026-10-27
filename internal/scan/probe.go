package scan

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/RshaCuDeVidro/0800/internal/db"
	"github.com/RshaCuDeVidro/0800/internal/ftp"
	"github.com/RshaCuDeVidro/0800/internal/ldap"
	"github.com/RshaCuDeVidro/0800/internal/nfs"
	"github.com/RshaCuDeVidro/0800/internal/smb"
)

// dispatch routes an open port to the matching protocol prober.
func (e *Engine) dispatch(ctx context.Context, ip string, port int) {
	switch e.serviceFor(port) {
	case "smb":
		e.probeSMB(ctx, ip, port)
	case "ldap":
		e.probeLDAP(ctx, ip, port)
	case "nfs":
		e.probeNFS(ctx, ip, port)
	case "mysql", "postgres", "redis":
		e.probeDB(ctx, ip, port)
	case "kerberos":
		e.probeKerberos(ctx, ip)
	case "ftp":
		e.probeFTP(ctx, ip, port)
	default:
		e.banner(ctx, ip, port)
	}
}

func (e *Engine) serviceFor(port int) string {
	if e.cfg.ServicePorts != nil {
		if svc, ok := e.cfg.ServicePorts[port]; ok {
			return svc
		}
	}
	switch port {
	case 445:
		return "smb"
	case 389, 636, 3268:
		return "ldap"
	case 2049:
		return "nfs"
	case 3306:
		return "mysql"
	case 5432:
		return "postgres"
	case 6379:
		return "redis"
	case 88:
		return "kerberos"
	case 21:
		return "ftp"
	}
	return ""
}

func (e *Engine) probeSMB(ctx context.Context, ip string, port int) {
	cfg := smb.DefaultConfig()
	cfg.Port = port
	cfg.DialTimeout = e.cfg.DialTimeout
	cfg.IOTimeout = e.cfg.IOTimeout
	cfg.EnumTimeout = minDuration(3*time.Second, e.cfg.IOTimeout)
	cfg.ShareMode = smb.SharesOff
	if e.cfg.EnumShares {
		cfg.ShareMode = smb.SharesQuick
	}

	p, err := smb.ProbeHost(ctx, ip, cfg)
	if err != nil {
		e.store.SetService(ip, ServiceView{Port: port, Proto: "smb", Banner: err.Error()})
		return
	}

	view := &SMBView{
		Port:    port,
		Dialect: p.Dialect,
		Signing: p.Signing,
		SMB1:    p.SMB1,
		Host:    p.Identity.DNSName,
		Domain:  p.Identity.DNSDomain,
		NetBIOS: p.Identity.NetBIOSName,
		OS:      p.Identity.OSVersion,
		EnumErr: p.EnumErr,
	}
	if view.Host == "" {
		view.Host = p.Identity.NetBIOSName
	}
	if view.Domain == "" {
		view.Domain = p.Identity.NetBIOSDom
	}
	for _, a := range p.Auth {
		if !a.OK {
			continue
		}
		view.Auth = a.Kind
		if a.Guest {
			view.Auth = "guest"
		}
	}
	for _, s := range p.Shares {
		view.Shares = append(view.Shares, ShareView{
			Name: s.Name, Type: s.Type, Comment: s.Comment, Writable: s.Writable,
		})
	}
	if len(p.Notes) > 0 && strings.Contains(strings.Join(p.Notes, " "), "NTLM") {
		view.NTLMOff = true
	}
	e.store.SetSMB(ip, view)

	var evidence []string
	for _, a := range p.Auth {
		if a.OK {
			evidence = append(evidence, fmt.Sprintf("SESSION_SETUP %s -> SUCCESS (guest=%t null=%t)", a.Kind, a.Guest, a.Null))
		} else {
			evidence = append(evidence, fmt.Sprintf("SESSION_SETUP %s -> %s", a.Kind, a.Status))
		}
	}

	base := fmt.Sprintf("dialect %s · signing %s", p.Dialect, p.Signing)
	switch view.Auth {
	case "null":
		e.store.AddFinding(ip, Finding{
			Port: port, Proto: "smb", Kind: "smb-null", Label: "null session",
			Severity: SevCritical, Detail: "anonymous SMB session accepted · " + base,
			Evidence: evidence,
		})
	case "guest":
		e.store.AddFinding(ip, Finding{
			Port: port, Proto: "smb", Kind: "smb-guest", Label: "guest login",
			Severity: SevHigh, Detail: "guest account accepted with empty password · " + base,
			Evidence: evidence,
		})
	}

	if p.Signing == "disabled" {
		e.store.AddFinding(ip, Finding{
			Port: port, Proto: "smb", Kind: "smb-signing", Label: "signing off",
			Severity: SevLow, Detail: "SMB signing disabled (relay surface)",
		})
	}
	if p.SMB1 {
		e.store.AddFinding(ip, Finding{
			Port: port, Proto: "smb", Kind: "smb1", Label: "smb1",
			Severity: SevLow, Detail: "SMB1 dialect accepted (" + p.SMB1Signing + " signing)",
		})
		// This is a protocol-negotiation heuristic, not an exploit attempt:
		// SMB1 without mandatory signing is exactly the surface MS17-010
		// (EternalBlue) and SMB relay target. Flag it distinctly from the
		// bare "smb1" note above so it isn't buried as low severity.
		if p.SMB1Signing != "required" {
			e.store.AddFinding(ip, Finding{
				Port: port, Proto: "smb", Kind: "smb1-legacy-exploit-surface",
				Label: "legacy SMB1 exploit surface", Severity: SevHigh,
				Detail: "SMB1 enabled without mandatory signing: exposed to the MS17-010/" +
					"EternalBlue exploit class and SMB relay on an unpatched host " +
					"(negotiation-based heuristic — no exploit was attempted)",
			})
		}
	}
	if len(view.Shares) > 0 {
		names := make([]string, 0, len(view.Shares))
		sev := SevHigh
		var writable []string
		for _, s := range view.Shares {
			names = append(names, s.Name)
			if s.Writable && s.Type == "disk" {
				writable = append(writable, s.Name)
				sev = SevCritical
			}
		}
		sort.Strings(names)
		e.store.AddFinding(ip, Finding{
			Port: port, Proto: "smb", Kind: "smb-shares", Label: "shares",
			Severity: sev,
			Detail:   fmt.Sprintf("%d share(s): %s", len(names), strings.Join(names, ", ")),
			Evidence: append(evidence, fmt.Sprintf("NetrShareEnum -> %d shares", len(names))),
		})
		if len(writable) > 0 {
			e.store.AddFinding(ip, Finding{
				Port: port, Proto: "smb", Kind: "smb-write", Label: "write access",
				Severity: SevCritical,
				Detail:   "writable share(s) as unauthenticated user: " + strings.Join(writable, ", "),
			})
		}
	} else if p.EnumErr != "" {
		e.store.AddFinding(ip, Finding{
			Port: port, Proto: "smb", Kind: "smb-enum", Label: "enum denied",
			Severity: SevInfo, Detail: "share enumeration failed: " + p.EnumErr,
			Evidence: evidence,
		})
	}

	if p.Identity.DNSDomain != "" || p.Identity.NetBIOSDom != "" {
		e.store.SetService(ip, ServiceView{
			Port: 445, Proto: "smb",
			Banner: strings.TrimSpace(p.Identity.DNSName + " " + p.Identity.DNSDomain),
			KV: [][2]string{
				{"netbios", p.Identity.NetBIOSName},
				{"domain", p.Identity.NetBIOSDom},
				{"dns", p.Identity.DNSName},
				{"dns domain", p.Identity.DNSDomain},
				{"dialect", p.Dialect},
			},
		})
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func (e *Engine) probeLDAP(ctx context.Context, ip string, port int) {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	res, err := ldap.Probe(ctx, addr, e.cfg.IOTimeout)
	if err != nil {
		e.store.SetService(ip, ServiceView{Port: port, Proto: "ldap", Banner: err.Error()})
		return
	}
	view := &LDAPView{
		Bound:     res.Bound,
		Code:      res.BindCode,
		Message:   res.BindMessage,
		Entries:   res.Entries,
		Sample:    res.Sample,
		DefaultDN: res.DefaultDN,
		DNSHost:   res.Host,
		Vendor:    res.Vendor,
		Version:   res.Version,
		IsDC:      res.IsDC,
	}
	e.store.SetLDAP(ip, view)

	kv := [][2]string{{"bind", strconv.Itoa(res.BindCode) + " " + res.BindMessage}}
	if res.DefaultDN != "" {
		kv = append(kv, [2]string{"base DN", res.DefaultDN})
	}
	if res.Host != "" {
		kv = append(kv, [2]string{"dns host", res.Host})
	}
	if res.Vendor != "" {
		kv = append(kv, [2]string{"vendor", strings.TrimSpace(res.Vendor + " " + res.Version)})
	}
	e.store.SetService(ip, ServiceView{Port: port, Proto: "ldap", Banner: res.DefaultDN, KV: kv})

	if res.Entries > 0 {
		e.store.AddFinding(ip, Finding{
			Port: port, Proto: "ldap", Kind: "ldap-anon", Label: "anon search",
			Severity: SevHigh,
			Detail: fmt.Sprintf("anonymous bind returned %d object(s) from %s",
				res.Entries, res.DefaultDN),
			Evidence: []string{
				fmt.Sprintf("bind(anonym) -> %d", res.BindCode),
				fmt.Sprintf("search(%s, onelevel, sizeLimit=5) -> %d entries", res.DefaultDN, res.Entries),
			},
		})
	} else if res.Bound {
		e.store.AddFinding(ip, Finding{
			Port: port, Proto: "ldap", Kind: "ldap-bind", Label: "anon bind",
			Severity: SevLow, Detail: "anonymous bind accepted, no objects readable",
		})
	}
}

func (e *Engine) probeNFS(ctx context.Context, ip string, port int) {
	res, err := nfs.Probe(ctx, ip, nfs.Config{Timeout: e.cfg.IOTimeout, Port: uint16(port)})
	if err != nil {
		e.store.SetService(ip, ServiceView{Port: port, Proto: "nfs", Banner: err.Error()})
		return
	}
	view := &NFSView{Version: res.Version, Note: res.Note, Port: res.Port, MountPort: res.MountPort}
	var mounted, listed []string
	for _, ex := range res.Exports {
		view.Exports = append(view.Exports, ExportView{
			Path: ex.Path, Groups: ex.Groups, Mounted: ex.Mounted,
		})
		listed = append(listed, ex.Path)
		if ex.Mounted {
			mounted = append(mounted, fmt.Sprintf("%s (%d entries)", ex.Path, ex.Entries))
		}
	}
	e.store.SetNFS(ip, view)

	if len(view.Exports) == 0 {
		return
	}
	sev := SevMedium
	if len(mounted) > 0 {
		sev = SevHigh
	}
	e.store.AddFinding(ip, Finding{
		Port: port, Proto: "nfs", Kind: "nfs-export", Label: "exports",
		Severity: sev,
		Detail:   strings.Join(listed, ", "),
		Evidence: []string{
			fmt.Sprintf("MOUNTPROC_EXPORT -> %d export(s)", len(view.Exports)),
			fmt.Sprintf("MOUNTPROC_MNT -> %d mounted", len(mounted)),
		},
	})
	if len(mounted) > 0 {
		e.store.AddFinding(ip, Finding{
			Port: port, Proto: "nfs", Kind: "nfs-read", Label: "nfs read",
			Severity: SevHigh, Detail: "readable without credentials: " + strings.Join(mounted, ", "),
		})
	}
}

func (e *Engine) probeKerberos(ctx context.Context, ip string) {
	e.store.SetService(ip, ServiceView{
		Port: 88, Proto: "kerberos", Banner: "KDC",
	})
	e.store.AddFinding(ip, Finding{
		Port: 88, Proto: "kerberos", Kind: "kdc", Label: "kdc",
		Severity: SevInfo, Detail: "Kerberos KDC reachable",
	})
}

// probeFTP tries an anonymous login. It never opens a data channel: no file
// is listed or transferred, only the control-channel login is exercised.
func (e *Engine) probeFTP(ctx context.Context, ip string, port int) {
	res, err := ftp.Probe(ctx, ip, port, e.cfg.IOTimeout)
	if err != nil {
		banner := err.Error()
		if res != nil && res.Banner != "" {
			banner = res.Banner
		}
		e.store.SetService(ip, ServiceView{Port: port, Proto: "ftp", Banner: banner})
		return
	}

	view := &FTPView{Port: port, Banner: res.Banner, AnonOK: res.AnonOK, Code: res.Code, Message: res.Message}
	e.store.SetFTP(ip, view)
	e.store.SetService(ip, ServiceView{Port: port, Proto: "ftp", Banner: res.Banner})

	if res.AnonOK {
		e.store.AddFinding(ip, Finding{
			Port: port, Proto: "ftp", Kind: "ftp-anon", Label: "anonymous login",
			Severity: SevHigh,
			Detail:   "FTP server accepted anonymous/anonymous@0800.scan with no further checks",
			Evidence: []string{
				fmt.Sprintf("220 %s", res.Banner),
				fmt.Sprintf("USER anonymous / PASS anonymous@0800.scan -> %d %s", res.Code, res.Message),
			},
		})
	}
}

func (e *Engine) probeDB(ctx context.Context, ip string, port int) {
	res := db.Probe(ctx, ip, port, e.cfg.IOTimeout)
	view := DBView{
		Port: port, Proto: res.Proto, Version: res.Version,
		User: res.User, Status: res.Status, Detail: res.Detail,
	}
	e.store.AddDB(ip, view)
	e.store.SetService(ip, ServiceView{Port: port, Proto: res.Proto, Banner: res.Version})

	if res.Status == "open" {
		e.store.AddFinding(ip, Finding{
			Port: port, Proto: res.Proto, Kind: res.Proto + "-open", Label: res.Proto + " open",
			Severity: SevCritical,
			Detail:   fmt.Sprintf("%s accepted user %q with an empty password", res.Proto, res.User),
			Evidence: res.Detail,
		})
	}
}

func (e *Engine) banner(ctx context.Context, ip string, port int) {
	d := net.Dialer{Timeout: e.cfg.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
	buf := make([]byte, 256)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return
	}
	banner := strings.TrimSpace(string(buf[:n]))
	banner = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, banner)
	if len(banner) > 80 {
		banner = banner[:80]
	}
	e.store.SetService(ip, ServiceView{Port: port, Proto: "tcp", Banner: banner})
}
