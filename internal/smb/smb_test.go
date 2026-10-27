package smb

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// --- a tiny SMB2 server ---------------------------------------------------

type fakeSMB struct {
	ln       net.Listener
	signMode uint16
	nullOK   bool
	guestOK  bool
	conns    atomic.Int32
}

func startFake(t *testing.T, signMode uint16) *fakeSMB {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMB{ln: ln, signMode: signMode, nullOK: true, guestOK: false}
	t.Cleanup(func() { _ = ln.Close() })
	go f.serve()
	return f
}

func (f *fakeSMB) addr() (string, int) {
	ta := f.ln.Addr().(*net.TCPAddr)
	return "127.0.0.1", ta.Port
}

func (f *fakeSMB) serve() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		f.conns.Add(1)
		go f.handle(c)
	}
}

func (f *fakeSMB) handle(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	var (
		session uint64
		stage   int
	)
	for {
		frame, err := readNBSS(br)
		if err != nil {
			return
		}
		if len(frame) < 5 {
			return
		}
		if frame[0] == 0xFF { // SMB1 negotiate
			if len(frame) > 4 && frame[4] == 0x72 {
				_, _ = c.Write(nbss(smb1Resp(f.signMode)))
			}
			continue
		}
		if len(frame) < 64 {
			return
		}
		h, err := parseHeader(frame)
		if err != nil {
			return
		}
		body := frame[64:]

		switch h.Command {
		case cmdNegotiate:
			f.reply(c, cmdNegotiate, StatusSuccess, h.MessageID, 0, 0, negotiateBody(f.signMode))

		case cmdSessionSetup:
			stage++
			if stage == 1 {
				blob := spnegoInit(fakeType2())
				session = 7
				f.reply(c, cmdSessionSetup, StatusMoreProcessingRequired, h.MessageID, session, 0, sessionSetupResp(0, blob))
			} else {
				flags := uint16(0x0002) // IS_NULL
				if !f.nullOK {
					if f.guestOK {
						flags = 0x0001
					} else {
						f.reply(c, cmdSessionSetup, StatusLogonFailure, h.MessageID, session, 0, sessionSetupResp(0, nil))
						continue
					}
				}
				f.reply(c, cmdSessionSetup, StatusSuccess, h.MessageID, session, 0, sessionSetupResp(flags, nil))
			}

		case cmdTreeConnect:
			name := utf16At(body, 4, 6)
			share := name
			if i := strings.LastIndex(name, `\`); i >= 0 {
				share = name[i+1:]
			}
			if share == "public" || share == "IPC$" || share == "" {
				resp := make([]byte, 16)
				putU16(resp, 0, 16)
				resp[2] = 1 // disk
				putU32(resp, 12, 0x001F01FF)
				f.reply(c, cmdTreeConnect, StatusSuccess, h.MessageID, session, 1, resp)
			} else {
				f.reply(c, cmdTreeConnect, StatusBadNetworkName, h.MessageID, session, 0, nil)
			}

		case cmdCreate:
			name := utf16At(body, 44, 46)
			if strings.HasPrefix(strings.ToLower(name), "srvsvc") {
				f.reply(c, cmdCreate, StatusObjectNameNotFound, h.MessageID, session, h.TreeID, nil)
				continue
			}
			resp := make([]byte, 88)
			putU16(resp, 0, 89)
			if name == "" {
				putU32(resp, 56, 0x10) // directory
			} else {
				putU64(resp, 48, 10) // "hello smb!"
			}
			for i := 0; i < 16; i++ {
				resp[64+i] = byte(i + 1)
			}
			f.reply(c, cmdCreate, StatusSuccess, h.MessageID, session, h.TreeID, resp)

		case cmdQueryDirectory:
			flags := body[3]
			if flags&0x01 == 0 {
				f.reply(c, cmdQueryDirectory, StatusNoMoreFiles, h.MessageID, session, h.TreeID, nil)
				continue
			}
			first := dirEntry("docs", 0x10, 0)
			putU32(first, 0, uint32(len(first)))
			buf := append(first, dirEntry("readme.txt", 0, 128)...)
			resp := make([]byte, 8+len(buf))
			putU16(resp, 0, 9)
			putU16(resp, 2, 72) // 64 + 8
			putU32(resp, 4, uint32(len(buf)))
			copy(resp[8:], buf)
			f.reply(c, cmdQueryDirectory, StatusSuccess, h.MessageID, session, h.TreeID, resp)

		case cmdClose, cmdTreeDisconnect, cmdLogoff:
			size := 4
			if h.Command == cmdClose {
				size = 60
			}
			resp := make([]byte, size)
			putU16(resp, 0, uint16(size+1))
			f.reply(c, h.Command, StatusSuccess, h.MessageID, session, h.TreeID, resp)

		case cmdRead:
			off := u64(body, 8)
			if off > 0 {
				f.reply(c, cmdRead, StatusEndOfFile, h.MessageID, session, h.TreeID, nil)
				continue
			}
			data := []byte("hello smb!")
			resp := make([]byte, 16+len(data))
			putU16(resp, 0, 17)
			resp[2] = 80 // 64 + 16
			putU32(resp, 4, uint32(len(data)))
			copy(resp[16:], data)
			f.reply(c, cmdRead, StatusSuccess, h.MessageID, session, h.TreeID, resp)

		case cmdWrite:
			resp := make([]byte, 16)
			putU16(resp, 0, 17)
			f.reply(c, cmdWrite, StatusSuccess, h.MessageID, session, h.TreeID, resp)

		default:
			f.reply(c, h.Command, StatusNotSupported, h.MessageID, session, h.TreeID, nil)
		}
	}
}

func (f *fakeSMB) reply(c net.Conn, cmd uint16, st Status, msgID, session uint64, tree uint32, body []byte) {
	b := make([]byte, smb2HeaderSize+len(body))
	copy(b, []byte{0xFE, 'S', 'M', 'B'})
	putU16(b, 4, 64)
	putU32(b, 8, uint32(st))
	putU16(b, 12, cmd)
	putU16(b, 14, 64)
	putU64(b, 24, msgID)
	putU32(b, 36, tree)
	putU64(b, 40, session)
	copy(b[smb2HeaderSize:], body)
	_, _ = c.Write(nbss(b))
}

func readNBSS(br *bufio.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, err
	}
	n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if n < 0 || n > 8<<20 {
		return nil, io.ErrUnexpectedEOF
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(br, buf)
	return buf, err
}

func nbss(b []byte) []byte {
	hdr := []byte{0, byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}
	return append(hdr, b...)
}

func negotiateBody(signMode uint16) []byte {
	resp := make([]byte, 64)
	putU16(resp, 0, 65)
	putU16(resp, 2, signMode)
	putU16(resp, 4, dialect302)
	putU32(resp, 28, 1<<20)
	putU32(resp, 32, 1<<20)
	putU32(resp, 36, 1<<20)
	return resp
}

func sessionSetupResp(flags uint16, blob []byte) []byte {
	resp := make([]byte, 8+len(blob))
	putU16(resp, 0, 9)
	putU16(resp, 2, flags)
	if len(blob) > 0 {
		putU16(resp, 4, 72)
		putU16(resp, 6, uint16(len(blob)))
		copy(resp[8:], blob)
	}
	return resp
}

func smb1Resp(signMode uint16) []byte {
	b := make([]byte, 69)
	copy(b, []byte{0xFF, 'S', 'M', 'B'})
	b[4] = 0x72
	b[9] = 0x18
	b[32] = 17 // word count
	b[33] = 0  // dialect index
	putU16(b, 35, signMode)
	putU16(b, 67, 0)
	return b
}

// utf16At reads a length-prefixed path from a request body.
func utf16At(body []byte, offField, lenField int) string {
	off := int(u16(body, offField)) - smb2HeaderSize
	n := int(u16(body, lenField))
	if off < 0 || n < 0 || off+n > len(body) {
		return ""
	}
	return fromUTF16LE(body[off : off+n])
}

func fakeType2() []byte {
	var ti []byte
	add := func(id uint16, s string) {
		u := utf16le(s)
		var hdr [4]byte
		binary.LittleEndian.PutUint16(hdr[0:], id)
		binary.LittleEndian.PutUint16(hdr[2:], uint16(len(u)))
		ti = append(ti, hdr[:]...)
		ti = append(ti, u...)
	}
	add(1, "DC01")
	add(2, "CORP")
	add(3, "dc01.corp.test")
	add(4, "corp.test")
	add(5, "corp.test")
	ti = append(ti, 0, 0, 0, 0)

	b := make([]byte, 48+len(ti))
	copy(b, ntlmSignature)
	putU32(b, 8, 2)
	putU32(b, 20, 0x00008201)
	copy(b[24:32], []byte("12345678"))
	putU16(b, 40, uint16(len(ti)))
	putU32(b, 44, 48)
	copy(b[48:], ti)
	return b
}

func dirEntry(name string, attrs uint32, size uint64) []byte {
	u := utf16le(name)
	b := make([]byte, 104+len(u))
	putU32(b, 56, attrs)
	putU32(b, 60, uint32(len(u)))
	putU64(b, 40, size)
	putU64(b, 24, 133000000000000000) // mtime
	copy(b[104:], u)
	return b
}

// --- tests ----------------------------------------------------------------

func TestProbeHostNullSession(t *testing.T) {
	f := startFake(t, 0x01)
	host, port := f.addr()

	cfg := DefaultConfig()
	cfg.Port = port
	cfg.DialTimeout = 2 * time.Second
	cfg.IOTimeout = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	p, err := ProbeHost(ctx, host, cfg)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if p.Dialect != "3.0.2" {
		t.Errorf("dialect = %q, want 3.0.2", p.Dialect)
	}
	if p.Signing != "enabled" {
		t.Errorf("signing = %q, want enabled", p.Signing)
	}
	if !p.SMB1 {
		t.Error("expected SMB1 to be detected")
	}
	if got := p.AuthKind(); got != "null" {
		t.Errorf("auth = %q, want null", got)
	}
	if p.Identity.DNSName != "dc01.corp.test" {
		t.Errorf("dns name = %q", p.Identity.DNSName)
	}
	if p.Identity.DNSDomain != "corp.test" {
		t.Errorf("dns domain = %q", p.Identity.DNSDomain)
	}
	var found bool
	for _, s := range p.Shares {
		if s.Name == "public" {
			found = true
		}
	}
	if !found {
		t.Errorf("public share not enumerated: %+v", p.Shares)
	}
}

func TestClientListAndRead(t *testing.T) {
	f := startFake(t, 0x01)
	host, port := f.addr()

	cfg := DefaultConfig()
	cfg.Port = port
	cfg.IOTimeout = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := Connect(ctx, host, "null", cfg)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close()

	entries, err := c.ReadDir(ctx, "public", "")
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d: %+v", len(entries), entries)
	}
	if entries[0].Name != "docs" || !entries[0].Dir {
		t.Errorf("first = %+v", entries[0])
	}

	rc, size, err := c.Open(ctx, "public", "readme.txt")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer rc.Close()
	if size != 10 {
		t.Errorf("size = %d", size)
	}
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "hello smb!" {
		t.Errorf("data = %q", data)
	}
}

func TestProbeHostSigningRequired(t *testing.T) {
	f := startFake(t, 0x03)
	host, port := f.addr()

	cfg := DefaultConfig()
	cfg.Port = port
	cfg.IOTimeout = 2 * time.Second

	p, err := ProbeHost(context.Background(), host, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if p.Signing != "required" {
		t.Fatalf("signing = %q, want required", p.Signing)
	}
	if len(p.Shares) != 0 {
		t.Errorf("shares must not be enumerated when signing is required")
	}
}

func TestParseType2(t *testing.T) {
	ch, ok := parseType2(fakeType2())
	if !ok {
		t.Fatal("parse failed")
	}
	if ch.Identity.NetBIOSName != "DC01" || ch.Identity.NetBIOSDom != "CORP" {
		t.Errorf("identity = %+v", ch.Identity)
	}
	if ch.TargetInfo[3] == nil {
		t.Error("missing DNS computer name AV pair")
	}
}

func TestType3Shape(t *testing.T) {
	ch, _ := parseType2(fakeType2())
	anon := type3("", "", ch, true)
	if binary.LittleEndian.Uint32(anon[8:]) != 3 {
		t.Fatal("not a type 3 message")
	}
	if n := u16(anon, 20); n != 0 {
		t.Errorf("anonymous NT response length = %d, want 0", n)
	}
	guest := type3("guest", "CORP", ch, false)
	if n := u16(guest, 20); n != 24 {
		t.Errorf("guest NT response length = %d, want 24", n)
	}
	if guest[64+24] == 0 {
		t.Error("guest payload missing domain")
	}
}

func TestDESExpand(t *testing.T) {
	k := desExpand([]byte{0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9})
	if len(k) != 8 {
		t.Fatalf("key length = %d", len(k))
	}
	if k[0] != 0x18 {
		t.Errorf("k[0] = %#x, want 0x18", k[0])
	}
}

func TestParseDirEntries(t *testing.T) {
	buf := append(dirEntry("a.txt", 0, 10), dirEntry("b", 0x10, 0)...)
	// link the entries
	putU32(buf, 0, uint32(104+len(utf16le("a.txt"))))

	resp := make([]byte, 8+len(buf))
	putU16(resp, 0, 9)
	putU16(resp, 2, 72)
	putU32(resp, 4, uint32(len(buf)))
	copy(resp[8:], buf)

	entries, err := parseDirEntries(resp)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d", len(entries))
	}
	if entries[0].Name != "a.txt" || entries[0].Size != 10 {
		t.Errorf("first = %+v", entries[0])
	}
	if !entries[1].Dir {
		t.Error("second entry should be a directory")
	}
}

func TestNDRShareEnumRoundTrip(t *testing.T) {
	req := ndrShareEnumRequest(`\\127.0.0.1`)
	if len(req) < 28 {
		t.Fatalf("short request: %d", len(req))
	}
	if u32(req, 0) != 0x00020000 {
		t.Errorf("ServerName referent = %#x", u32(req, 0))
	}
	if u32(req, 4) != 1 || u32(req, 8) != 1 {
		t.Error("level must be 1")
	}
	if u32(req, 12) != 0x00020004 {
		t.Errorf("container referent = %#x", u32(req, 12))
	}

	// Build a response stub with two shares and parse it back.
	w := &ndrWriter{}
	w.u32(1)          // Level
	w.u32(0x00020004) // container
	w.u32(0x00020008) // total entries
	w.u32(0x0002000C) // resume handle
	w.u32(2)          // EntriesRead
	w.u32(0x00020010) // buffer
	w.u32(2)          // max count
	w.u32(0x00020014) // share[0].name
	w.u32(0)          // type
	w.u32(0x00020018) // share[0].remark
	w.u32(0x0002001C) // share[1].name
	w.u32(1)          // type print
	w.u32(0)          // remark null
	w.str("public")
	w.str("shared folders")
	w.str("print$")
	w.u32(2) // total
	w.u32(0) // resume

	shares, err := ndrParseShareEnum(w.b)
	if err != nil {
		t.Fatal(err)
	}
	if len(shares) != 2 {
		t.Fatalf("shares = %d: %+v", len(shares), shares)
	}
	if shares[0].Name != "public" || shares[0].Comment != "shared folders" {
		t.Errorf("share[0] = %+v", shares[0])
	}
	if shares[1].Type != "print" {
		t.Errorf("share[1] type = %q", shares[1].Type)
	}
}

func FuzzParseDirEntries(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = parseDirEntries(data)
	})
}

func FuzzParseType2(f *testing.F) {
	f.Add(fakeType2())
	f.Fuzz(func(t *testing.T, data []byte) {
		ch, ok := parseType2(data)
		if ok && ch.Identity.DNSName != "" {
			_ = ch.Identity.DNSName
		}
	})
}
