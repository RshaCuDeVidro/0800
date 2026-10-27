package smb

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// smb2Dialects is the offer set. We stop at 3.0.2 on purpose: 3.1.1 requires
// pre-authentication integrity (negotiate contexts) which adds no value for
// fingerprinting and would make the client stricter, not more compatible.
var smb2Dialects = []uint16{dialect2002, dialect21, dialect30, dialect302}

// negotiateResp holds the parsed NEGOTIATE response.
type negotiateResp struct {
	Dialect    uint16
	Signing    string // "required" | "enabled" | "disabled"
	SMB1       bool
	ServerGUID [16]byte
	MaxRead    uint32
	MaxWrite   uint32
	MaxTrans   uint32
	ServerTime time.Time
}

func (c *conn) negotiateSMB2(ctx context.Context) (*negotiateResp, error) {
	body := make([]byte, 36+len(smb2Dialects)*2)
	putU16(body, 0, 36)
	putU16(body, 2, uint16(len(smb2Dialects)))
	putU16(body, 4, 0x01) // security mode: signing enabled
	putU32(body, 8, 0)
	copy(body[12:28], c.cfg.ClientGUID[:])
	for i, d := range smb2Dialects {
		putU16(body, 36+i*2, d)
	}

	h, resp, err := c.call(ctx, cmdNegotiate, 0, 0, body)
	if err != nil {
		return nil, err
	}
	if !h.Status.OK() {
		return nil, h.Status
	}
	if len(resp) < 64 {
		return nil, fmt.Errorf("smb: short negotiate response (%d bytes)", len(resp))
	}

	r := &negotiateResp{
		Dialect:  u16(resp, 4),
		MaxTrans: u32(resp, 28),
		MaxRead:  u32(resp, 32),
		MaxWrite: u32(resp, 36),
	}
	mode := u16(resp, 2)
	switch {
	case mode&0x0002 != 0:
		r.Signing = "required"
	case mode&0x0001 != 0:
		r.Signing = "enabled"
	default:
		r.Signing = "disabled"
	}
	copy(r.ServerGUID[:], resp[8:24])

	if ft := u64(resp, 40); ft > 0 {
		r.ServerTime = time.Unix(int64(ft)/1e7-11644473600, 0)
	}

	c.dialect = r.Dialect
	c.maxRead = clamp(r.MaxRead, 64*1024, 8<<20)
	c.maxWrite = clamp(r.MaxWrite, 64*1024, 8<<20)
	c.maxTrans = clamp(r.MaxTrans, 64*1024, 8<<20)
	c.serverGUID = r.ServerGUID
	c.signingEnabled = mode&0x0001 != 0
	c.signingRequired = mode&0x0002 != 0
	return r, nil
}

// negotiateSMB1 performs an SMB1 multi-protocol negotiate with a single
// "NT LM 0.12" dialect. Success means the server still answers SMB1, which is
// itself a finding on modern networks.
func (c *conn) negotiateSMB1(ctx context.Context) (bool, string, error) {
	dialect := append([]byte{0x02}, append([]byte("NT LM 0.12"), 0)...)
	body := make([]byte, 35+len(dialect))
	body[0] = 0xFF
	body[1], body[2], body[3], body[4] = 'S', 'M', 'B', 0x72
	body[9] = 0x18                  // flags: canonicalized paths, case insensitive
	body[10], body[11] = 0x03, 0xC8 // flags2: long names + NT status
	putU16(body, 26, 0xFEFF)        // PID
	body[32] = 0                    // word count
	putU16(body, 33, uint16(len(dialect)))
	copy(body[35:], dialect)

	if err := c.Conn.SetDeadline(c.deadline(ctx)); err != nil {
		return false, "", err
	}
	if err := c.writeFrame(body); err != nil {
		return false, "", err
	}
	frame, err := c.readFrame()
	if err != nil {
		return false, "", err
	}
	if len(frame) < 33 || frame[0] != 0xFF || frame[1] != 'S' || frame[2] != 'M' || frame[3] != 'B' {
		return false, "", fmt.Errorf("smb: not an SMB1 response")
	}
	status := Status(u32(frame, 5))
	if !status.OK() {
		return false, "", nil
	}
	wordCount := int(frame[32])
	if wordCount < 2 || len(frame) < 38 {
		return false, "", nil
	}
	mode := byte(u16(frame, 35)) // SecurityMode is the second parameter word
	signing := "disabled"
	switch {
	case mode&0x02 != 0:
		signing = "required"
	case mode&0x01 != 0:
		signing = "enabled"
	}
	return true, signing, nil
}

func dialectName(d uint16) string {
	switch d {
	case dialect2002:
		return "2.0.2"
	case dialect21:
		return "2.1"
	case dialect30:
		return "3.0"
	case dialect302:
		return "3.0.2"
	case 0x0311:
		return "3.1.1"
	default:
		return fmt.Sprintf("0x%04x", d)
	}
}

func clamp(v, lo, hi uint32) uint32 {
	if v == 0 {
		return lo
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// shareTypeName maps the TREE_CONNECT share type to a label.
func shareTypeName(t uint8) string {
	switch t {
	case 1:
		return "disk"
	case 2:
		return "pipe"
	case 3:
		return "print"
	default:
		return "device"
	}
}

// joinUNCPath builds \\server\share from its parts.
func joinUNCPath(host, share string) string {
	return `\\` + strings.Trim(host, `\`) + `\` + share
}
