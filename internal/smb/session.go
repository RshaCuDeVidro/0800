package smb

import (
	"context"
	"errors"
	"fmt"
)

// AuthResult is the outcome of one credential attempt.
type AuthResult struct {
	Kind    string // "null" | "guest"
	User    string
	OK      bool
	Guest   bool
	Null    bool
	Status  Status
	Message string
}

// login performs NTLMSSP session setup. wrap selects SPNEGO-wrapped Type 3
// (standards compliant) versus a raw token (some appliances only accept that).
func (c *conn) login(ctx context.Context, kind string, wrap bool) (AuthResult, error) {
	res := AuthResult{Kind: kind}
	user, domain, anonymous := "", "", true
	if kind == "guest" {
		user, anonymous = "guest", false
	}

	blob := spnegoInit(negoType1())
	h, resp, err := c.call(ctx, cmdSessionSetup, 0, 0, sessionSetupBody(blob))
	if err != nil {
		return res, err
	}
	res.Status = h.Status
	if h.Status != StatusMoreProcessingRequired {
		res.Message = h.Status.String()
		return res, nil
	}

	sec := sessionSetupSecurity(resp)
	ch, ok := parseType2(extractNTLM(sec))
	if !ok {
		return res, errors.New("smb: server did not return an NTLM challenge")
	}
	c.serverIdentity = ch.Identity
	if ch.Identity.DNSDomain == "" && ch.Target != "" {
		c.serverIdentity.DNSDomain = ch.Target
	}

	sessionID := h.SessionID
	if ch.Identity.NetBIOSDom != "" {
		// Sending the server's own domain improves compatibility with AD.
		domain = ch.Identity.NetBIOSDom
	}
	tok := type3(user, domain, ch, anonymous)
	if wrap {
		tok = spnegoResp(tok)
	}

	h2, resp2, err := c.call(ctx, cmdSessionSetup, 0, sessionID, sessionSetupBody(tok))
	if err != nil {
		return res, err
	}
	res.Status = h2.Status
	if !h2.Status.OK() {
		res.Message = h2.Status.String()
		return res, nil
	}

	c.sessionID = h2.SessionID
	if c.sessionID == 0 {
		c.sessionID = sessionID
	}
	flags := u16(resp2, 2)
	res.OK = true
	res.Guest = flags&0x0001 != 0
	res.Null = flags&0x0002 != 0
	if res.Guest {
		res.User = "guest"
	}
	return res, nil
}

func sessionSetupBody(blob []byte) []byte {
	const fixed = 24
	b := make([]byte, fixed+len(blob))
	putU16(b, 0, 25)
	b[2] = 0 // flags
	b[3] = 1 // security mode: signing enabled
	putU16(b, 4, 0)
	putU32(b, 8, 0)  // capabilities
	putU32(b, 12, 0) // channel
	putU16(b, 16, uint16(smb2HeaderSize+fixed))
	putU16(b, 18, uint16(len(blob)))
	putU64(b, 20, 0) // previous session id
	copy(b[fixed:], blob)
	return b
}

func sessionSetupSecurity(resp []byte) []byte {
	if len(resp) < 8 {
		return nil
	}
	off := int(u16(resp, 4))
	n := int(u16(resp, 6))
	off -= smb2HeaderSize
	if off < 0 || n <= 0 || off+n > len(resp) {
		return nil
	}
	return resp[off : off+n]
}

// treeConnect attaches to \\host\share and returns the tree id, share type and
// the maximal access mask granted by the server.
func (c *conn) treeConnect(ctx context.Context, host, share string) (uint32, string, uint32, error) {
	path := utf16le(joinUNCPath(host, share))
	const fixed = 8
	b := make([]byte, fixed+len(path))
	putU16(b, 0, 9)
	putU16(b, 2, 0)
	putU16(b, 4, uint16(smb2HeaderSize+fixed))
	putU16(b, 6, uint16(len(path)))
	copy(b[fixed:], path)

	h, resp, err := c.call(ctx, cmdTreeConnect, 0, c.sessionID, b)
	if err != nil {
		return 0, "", 0, err
	}
	if !h.Status.OK() {
		return 0, "", 0, h.Status
	}
	if len(resp) < 16 {
		return 0, "", 0, fmt.Errorf("smb: short tree connect response")
	}
	return h.TreeID, shareTypeName(resp[2]), u32(resp, 12), nil
}

func (c *conn) treeDisconnect(ctx context.Context, treeID uint32) {
	body := make([]byte, 4)
	putU16(body, 0, 4)
	_, _, _ = c.call(ctx, cmdTreeDisconnect, treeID, c.sessionID, body)
}

func (c *conn) logoff(ctx context.Context) {
	body := make([]byte, 4)
	putU16(body, 0, 4)
	_, _, _ = c.call(ctx, cmdLogoff, 0, c.sessionID, body)
}
