package smb

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
	"unicode/utf16"
)

// Commands (MS-SMB2 2.2.1.2).
const (
	cmdNegotiate      = 0x0000
	cmdSessionSetup   = 0x0001
	cmdLogoff         = 0x0002
	cmdTreeConnect    = 0x0003
	cmdTreeDisconnect = 0x0004
	cmdCreate         = 0x0005
	cmdClose          = 0x0006
	cmdRead           = 0x0008
	cmdWrite          = 0x0009
	cmdEcho           = 0x000D
	cmdQueryDirectory = 0x000E
	cmdQueryInfo      = 0x0010
	cmdIOCTL          = 0x0011
)

// Dialects (MS-SMB2 2.2.3).
const (
	dialect2002 uint16 = 0x0202
	dialect21   uint16 = 0x0210
	dialect30   uint16 = 0x0300
	dialect302  uint16 = 0x0302
)

// ShareMode selects how hard to look for shares when srvsvc is blocked.
type ShareMode int

const (
	// SharesOff only asks srvsvc (fastest).
	SharesOff ShareMode = iota
	// SharesQuick probes the 14 most common names (scan default).
	SharesQuick
	// SharesFull probes the whole list (used when opening a host).
	SharesFull
)

// Config controls timeouts and identification.
type Config struct {
	Port        int
	DialTimeout time.Duration
	IOTimeout   time.Duration
	ClientGUID  [16]byte
	// ShareMode controls the common-name fallback when srvsvc is blocked.
	ShareMode ShareMode
	// EnumTimeout caps share enumeration during a scan.
	EnumTimeout time.Duration
}

// DefaultConfig returns sane defaults for internet scale probing.
func DefaultConfig() Config {
	var guid [16]byte
	_, _ = rand.Read(guid[:])
	return Config{Port: 445, DialTimeout: 3 * time.Second, IOTimeout: 6 * time.Second, EnumTimeout: 4 * time.Second, ShareMode: SharesQuick, ClientGUID: guid}
}

type header struct {
	Status    Status
	Command   uint16
	Credits   uint16
	Flags     uint32
	Next      uint32
	MessageID uint64
	TreeID    uint32
	SessionID uint64
}

const smb2HeaderSize = 64

var errShortFrame = errors.New("smb: short frame")

func parseHeader(b []byte) (header, error) {
	if len(b) < smb2HeaderSize {
		return header{}, errShortFrame
	}
	if b[0] != 0xFE || b[1] != 'S' || b[2] != 'M' || b[3] != 'B' {
		return header{}, fmt.Errorf("smb: bad protocol id %x", b[:4])
	}
	return header{
		Status:    Status(binary.LittleEndian.Uint32(b[8:])),
		Command:   binary.LittleEndian.Uint16(b[12:]),
		Credits:   binary.LittleEndian.Uint16(b[14:]),
		Flags:     binary.LittleEndian.Uint32(b[16:]),
		Next:      binary.LittleEndian.Uint32(b[20:]),
		MessageID: binary.LittleEndian.Uint64(b[24:]),
		TreeID:    binary.LittleEndian.Uint32(b[36:]),
		SessionID: binary.LittleEndian.Uint64(b[40:]),
	}, nil
}

// conn is a single SMB2 connection with one negotiated session.
type conn struct {
	net.Conn
	cfg Config

	nextMsgID uint64
	sessionID uint64
	treeID    uint32

	dialect    uint16
	maxRead    uint32
	maxWrite   uint32
	maxTrans   uint32
	serverGUID [16]byte

	signingEnabled  bool
	signingRequired bool

	// serverIdentity is filled from the NTLM challenge and is available even
	// when authentication fails.
	serverIdentity ServerIdentity
}

// ServerIdentity is the passive fingerprint leaked by the NTLM challenge.
type ServerIdentity struct {
	NetBIOSName string
	NetBIOSDom  string
	DNSName     string
	DNSDomain   string
	Forest      string
	OSVersion   string
	Time        time.Time
}

func (c Config) address(ip string) string {
	port := c.Port
	if port == 0 {
		port = 445
	}
	return net.JoinHostPort(ip, strconv.Itoa(port))
}

func dial(ctx context.Context, addr string, cfg Config) (*conn, error) {
	d := net.Dialer{Timeout: cfg.DialTimeout}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return &conn{Conn: nc, cfg: cfg, maxRead: 1 << 20, maxWrite: 1 << 20, maxTrans: 1 << 20}, nil
}

func (c *conn) Close() error { return c.Conn.Close() }

func (c *conn) deadline(ctx context.Context) time.Time {
	d := time.Now().Add(c.cfg.IOTimeout)
	if t, ok := ctx.Deadline(); ok && t.Before(d) {
		return t
	}
	return d
}

func (c *conn) writeFrame(payload []byte) error {
	if len(payload) > 0xFFFFFF {
		return fmt.Errorf("smb: frame too large (%d)", len(payload))
	}
	hdr := [4]byte{0, byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload))}
	if _, err := c.Conn.Write(hdr[:]); err != nil {
		return err
	}
	_, err := c.Conn.Write(payload)
	return err
}

func (c *conn) readFrame() ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(c.Conn, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0 {
		return nil, fmt.Errorf("smb: unexpected netbios type %d", hdr[0])
	}
	n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if n < smb2HeaderSize || n > 32<<20 {
		return nil, fmt.Errorf("smb: invalid frame length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.Conn, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// call performs one request/response round trip. Non-success NTSTATUS values are
// returned in hdr.Status, not as a Go error, because callers sometimes need to
// inspect them.
func (c *conn) call(ctx context.Context, cmd uint16, treeID uint32, sessionID uint64, body []byte) (header, []byte, error) {
	if err := c.Conn.SetDeadline(c.deadline(ctx)); err != nil {
		return header{}, nil, err
	}

	msgID := c.nextMsgID
	c.nextMsgID++

	buf := make([]byte, smb2HeaderSize+len(body))
	buf[0], buf[1], buf[2], buf[3] = 0xFE, 'S', 'M', 'B'
	binary.LittleEndian.PutUint16(buf[4:], 64) // structure size
	binary.LittleEndian.PutUint16(buf[6:], 1)  // credit charge
	binary.LittleEndian.PutUint16(buf[12:], cmd)
	binary.LittleEndian.PutUint16(buf[14:], 64) // credit request
	binary.LittleEndian.PutUint64(buf[24:], msgID)
	binary.LittleEndian.PutUint32(buf[36:], treeID)
	binary.LittleEndian.PutUint64(buf[40:], sessionID)
	copy(buf[smb2HeaderSize:], body)

	if err := c.writeFrame(buf); err != nil {
		return header{}, nil, err
	}

	for i := 0; i < 8; i++ {
		frame, err := c.readFrame()
		if err != nil {
			return header{}, nil, err
		}
		h, err := parseHeader(frame)
		if err != nil {
			return header{}, nil, err
		}
		if h.MessageID != msgID {
			// Stale async notification or echoed credit grant; ignore.
			continue
		}
		if h.Status == StatusPending {
			continue
		}
		return h, frame[smb2HeaderSize:], nil
	}
	return header{}, nil, errors.New("smb: no matching response")
}

// --- little endian helpers -------------------------------------------------

func putU16(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
func putU32(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
func putU64(b []byte, off int, v uint64) { binary.LittleEndian.PutUint64(b[off:], v) }

func u16(b []byte, off int) uint16 {
	if off+2 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint16(b[off:])
}

func u32(b []byte, off int) uint32 {
	if off+4 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint32(b[off:])
}

func u64(b []byte, off int) uint64 {
	if off+8 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint64(b[off:])
}

func align4(n int) int { return (n + 3) &^ 3 }

func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(out[i*2:], v)
	}
	return out
}

func fromUTF16LE(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}
