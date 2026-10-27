package smb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// Share is a remote share with its access mask.
type Share struct {
	Name     string
	Type     string
	Comment  string
	Writable bool
}

// Probe is the complete result of fingerprinting one SMB endpoint.
type Probe struct {
	Dialect     string
	Signing     string
	SMB1        bool
	SMB1Signing string
	Identity    ServerIdentity
	Auth        []AuthResult
	Shares      []Share
	EnumErr     string
	Notes       []string
}

// AuthKind returns the credential that worked, if any.
func (p *Probe) AuthKind() string {
	for _, a := range p.Auth {
		if a.OK {
			if a.Guest {
				return "guest"
			}
			return a.Kind
		}
	}
	return ""
}

// ProbeHost fingerprints an SMB endpoint without touching any file.
func ProbeHost(ctx context.Context, ip string, cfg Config) (p *Probe, err error) {
	addr := cfg.address(ip)
	p = &Probe{}
	// A malformed reply from a hostile server must not discard the auth result
	// we already obtained; turn any panic into an enumeration note.
	defer func() {
		if r := recover(); r != nil {
			p.EnumErr = fmt.Sprintf("enumeration panic: %v", r)
			err = nil
		}
	}()

	// SMB1 is probed on its own connection (servers that disabled it may reset
	// the socket) and concurrently with the SMB2 handshake, so it costs latency
	// only once.
	type smb1Result struct {
		ok      bool
		signing string
	}
	smb1ch := make(chan smb1Result, 1)
	go func() {
		var r smb1Result
		if c, err := dial(ctx, addr, cfg); err == nil {
			r.ok, r.signing, _ = c.negotiateSMB1(ctx)
			_ = c.Close()
		}
		smb1ch <- r
	}()
	var smb1Once sync.Once
	var smb1 smb1Result
	getSMB1 := func() smb1Result {
		smb1Once.Do(func() { smb1 = <-smb1ch })
		return smb1
	}
	defer func() {
		r := getSMB1()
		p.SMB1 = r.ok
		p.SMB1Signing = r.signing
	}()

	authKinds := []string{"null", "guest"}
	var lastErr error
	for _, kind := range authKinds {
		c, err := dial(ctx, addr, cfg)
		if err != nil {
			lastErr = err
			continue
		}
		nr, err := c.negotiateSMB2(ctx)
		if err != nil {
			_ = c.Close()
			lastErr = err
			continue
		}
		p.Dialect = dialectName(nr.Dialect)
		p.Signing = nr.Signing
		if p.Identity.isZero() {
			// identity is filled during session setup
		}
		res, err := c.loginWithRetry(ctx, kind)
		identity := c.serverIdentity
		_ = c.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if p.Identity.isZero() {
			p.Identity = identity
		}
		p.Auth = append(p.Auth, res)
		if res.OK {
			break
		}
		if res.Status == StatusNotSupported {
			p.Notes = append(p.Notes, "NTLM authentication disabled")
			break
		}
	}

	if p.Dialect == "" && !p.SMB1 {
		if lastErr != nil {
			return nil, lastErr
		}
		return nil, errors.New("not an SMB service")
	}

	// Enumerate shares with the credential that worked.
	if kind := p.AuthKind(); kind != "" && p.Signing != "required" {
		cl, err := Connect(ctx, ip, kind, cfg)
		if err == nil {
			enumCtx := ctx
			cancel := func() {}
			if cfg.EnumTimeout > 0 {
				enumCtx, cancel = context.WithTimeout(ctx, cfg.EnumTimeout)
			}
			shares, err := cl.ListShares(enumCtx, cfg.ShareMode)
			cancel()
			if err != nil {
				p.EnumErr = err.Error()
			} else {
				p.Shares = shares
			}
			_ = cl.Close()
		} else {
			p.EnumErr = err.Error()
		}
	} else if p.Signing == "required" {
		p.Notes = append(p.Notes, "SMB signing required: session usable for auth only")
	}
	return p, nil
}

func (id ServerIdentity) isZero() bool {
	return id == (ServerIdentity{})
}

// Client is an authenticated SMB session used for browsing.
type Client struct {
	c    *conn
	host string
	auth string
}

// Connect opens a session using the given credential kind ("null" or "guest").
func Connect(ctx context.Context, ip, kind string, cfg Config) (*Client, error) {
	c, err := dial(ctx, cfg.address(ip), cfg)
	if err != nil {
		return nil, err
	}
	if _, err := c.negotiateSMB2(ctx); err != nil {
		_ = c.Close()
		return nil, err
	}
	res, err := c.loginWithRetry(ctx, kind)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	if !res.OK {
		_ = c.Close()
		return nil, fmt.Errorf("smb: authentication failed: %s", res.Status)
	}
	return &Client{c: c, host: ip, auth: kind}, nil
}

// loginWithRetry falls back to a raw Type 3 token for appliances that reject
// the SPNEGO-wrapped variant.
func (c *conn) loginWithRetry(ctx context.Context, kind string) (AuthResult, error) {
	res, err := c.login(ctx, kind, true)
	if err != nil || res.OK || res.Status == StatusLogonFailure || res.Status == StatusAccessDenied {
		return res, err
	}
	if res.Status != StatusInvalidParameter && res.Status != StatusNotSupported {
		return res, nil
	}
	return c.login(ctx, kind, false)
}

// Auth reports which credential the client uses.
func (c *Client) Auth() string { return c.auth }

// Close logs off and closes the socket.
func (c *Client) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	c.c.logoff(ctx)
	return c.c.Close()
}

// ListShares enumerates shares. It first asks srvsvc over IPC$; when RPC is
// blocked and mode allows it, it probes a curated list of share names (one
// round trip each, so the scan uses the short list and the browser the full).
func (c *Client) ListShares(ctx context.Context, mode ShareMode) ([]Share, error) {
	shares, err := c.srvsvcListShares(ctx)
	if err == nil && len(shares) > 0 {
		return shares, nil
	}
	if mode == SharesOff {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("share enumeration denied")
	}
	names := quickShareNames
	if mode == SharesFull {
		names = commonShareNames
	}
	fb := c.probeCommonShares(ctx, names)
	if len(fb) == 0 {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("share enumeration denied")
	}
	return fb, nil
}

// ReadDir lists a directory inside a share. An empty dir means the share root.
func (c *Client) ReadDir(ctx context.Context, share, dir string) ([]Entry, error) {
	tree, err := c.connectShare(ctx, share)
	if err != nil {
		return nil, err
	}
	defer c.c.treeDisconnect(ctx, tree.id)

	path := normaliseSharePath(dir)
	id, _, _, err := c.c.create(ctx, tree.id, path,
		fileListDirectory|fileReadAttributes|readControl,
		0x80, 7, fileOpen, fileDirectoryFile|fileSynchronousIoNonAlert)
	if err != nil {
		return nil, err
	}
	defer c.c.closeFile(ctx, tree.id, id)

	entries, err := c.c.queryDirectory(ctx, tree.id, id)
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Dir != entries[j].Dir {
			return entries[i].Dir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	return entries, nil
}

// Open starts streaming a remote file.
func (c *Client) Open(ctx context.Context, share, path string) (io.ReadCloser, int64, error) {
	tree, err := c.connectShare(ctx, share)
	if err != nil {
		return nil, 0, err
	}
	id, size, _, err := c.c.create(ctx, tree.id, normaliseSharePath(path),
		fileReadData|fileReadAttributes|synchronize,
		0x80, 7, fileOpen, fileNonDirectoryFile|fileSynchronousIoNonAlert)
	if err != nil {
		c.c.treeDisconnect(ctx, tree.id)
		return nil, 0, err
	}
	return &fileReader{c: c.c, treeID: tree.id, id: id, ctx: context.WithoutCancel(ctx), size: size}, size, nil
}

type treeConn struct {
	id     uint32
	typ    string
	access uint32
}

func (c *Client) connectShare(ctx context.Context, share string) (treeConn, error) {
	treeID, typ, access, err := c.c.treeConnect(ctx, c.host, share)
	if err != nil {
		return treeConn{}, err
	}
	return treeConn{id: treeID, typ: typ, access: access}, nil
}

// probeCommonShares tries a curated list of share names. This is the fallback
// when srvsvc is unavailable, and it is also how writable shares are detected.
func (c *Client) probeCommonShares(ctx context.Context, names []string) []Share {
	var out []Share
	seen := map[string]bool{}
	for _, name := range names {
		if ctx.Err() != nil {
			break
		}
		treeID, typ, access, err := c.c.treeConnect(ctx, c.host, name)
		if err != nil {
			continue
		}
		c.c.treeDisconnect(ctx, treeID)
		key := strings.ToUpper(name)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, Share{Name: name, Type: typ, Writable: access&0x2 != 0})
	}
	return out
}

// quickShareNames is the short list used during a scan: the most common
// appliance/server shares, 14 round trips at most.
var quickShareNames = []string{
	"IPC$", "C$", "ADMIN$", "SYSVOL", "NETLOGON",
	"public", "storage", "share", "shared", "users",
	"home", "data", "backup", "print$",
}

var commonShareNames = []string{
	"IPC$", "C$", "ADMIN$", "SYSVOL", "NETLOGON",
	"public", "storage", "share", "shared", "users", "home", "homes",
	"data", "files", "docs", "documents", "downloads", "transfer",
	"backup", "backups", "temp", "tmp", "software", "install",
	"profiles", "print$", "www", "web", "ftp", "media", "music",
	"photos", "videos", "scans", "scan", "it", "ti", "financeiro",
	"comercial", "vendas", "rh", "projetos", "suporte", "arquivos",
	"compartilhado", "dados", "documentos", "midia", "publico",
}
