package smb

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
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

	// min311 models a server whose minimum protocol is SMB 3.1.1: a NEGOTIATE
	// that does not offer it gets STATUS_NOT_SUPPORTED, and one that does must
	// carry the pre-authentication integrity context.
	openTrees  atomic.Int32 // tree connects not yet disconnected
	min311     bool
	ctxChecked atomic.Bool // set once a valid 3.1.1 request was seen
	// quirkyCreate makes the share-root CREATE fail with
	// STATUS_INVALID_PARAMETER when CreateOptions is non-zero, mimicking the
	// embedded NAS stacks that reject FILE_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT.
	quirkyCreate bool
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
			if f.min311 {
				offered311 := false
				for i := 0; i < int(u16(body, 2)); i++ {
					if u16(body, 36+i*2) == dialect311 {
						offered311 = true
					}
				}
				if !offered311 {
					f.reply(c, cmdNegotiate, StatusNotSupported, h.MessageID, 0, 0, nil)
					continue
				}
				if !validPreauthContext(body) {
					f.reply(c, cmdNegotiate, StatusInvalidParameter, h.MessageID, 0, 0, nil)
					continue
				}
				f.ctxChecked.Store(true)
				resp := negotiateBody(f.signMode)
				putU16(resp, 4, dialect311)
				f.reply(c, cmdNegotiate, StatusSuccess, h.MessageID, 0, 0, resp)
				continue
			}
			f.reply(c, cmdNegotiate, StatusSuccess, h.MessageID, 0, 0, negotiateBody(f.signMode))

		case cmdSessionSetup:
			if u16(body, 14) == 0 {
				// A real server would reject an empty security buffer.
				return
			}
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
				f.openTrees.Add(1)
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
			if f.quirkyCreate && name == "" && u32(body, 40) != 0 {
				f.reply(c, cmdCreate, StatusInvalidParameter, h.MessageID, session, h.TreeID, nil)
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
			if h.Command == cmdTreeDisconnect {
				f.openTrees.Add(-1)
			}
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

// validPreauthContext checks the NEGOTIATE request carries exactly what
// MS-SMB2 2.2.3.1.1 requires for 3.1.1: one SMB2_PREAUTH_INTEGRITY_CAPABILITIES
// context, 8-byte aligned, offering SHA-512 with a 32-byte salt.
func validPreauthContext(body []byte) bool {
	off := int(u32(body, 28)) - smb2HeaderSize
	if u16(body, 32) != 1 || off < 36 || off%8 != (smb2HeaderSize%8) || off+8 > len(body) {
		return false
	}
	if (int(u32(body, 28)))%8 != 0 {
		return false
	}
	ctx := body[off:]
	if u16(ctx, 0) != 0x0001 {
		return false
	}
	dataLen := int(u16(ctx, 2))
	if dataLen < 38 || 8+dataLen > len(ctx) {
		return false
	}
	return u16(ctx, 8) == 1 && u16(ctx, 10) == 32 && u16(ctx, 12) == 0x0001
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

// TestProbeHostNotSMBNoPanic covers a port that accepts TCP but never speaks
// SMB (it closes the connection immediately). This used to crash the prober
// with "nil pointer dereference": a deferred SMB1 collector wrote to the Probe
// after the not-an-SMB-service path had set it to nil. The probe must now
// return a plain error instead.
func TestProbeHostNotSMBNoPanic(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close() // never negotiate
		}
	}()

	cfg := DefaultConfig()
	cfg.Port = ln.Addr().(*net.TCPAddr).Port
	cfg.DialTimeout = time.Second
	cfg.IOTimeout = time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	p, err := ProbeHost(ctx, "127.0.0.1", cfg)
	if err == nil {
		t.Fatalf("expected an error for a non-SMB port, got probe %+v", p)
	}
	if p != nil {
		t.Errorf("probe must be nil on error, got %+v", p)
	}
}

// TestClientListAndReadQuirkyNAS reproduces a NAS appliance that answers
// STATUS_INVALID_PARAMETER to the textbook directory CREATE: ReadDir must
// fall back to the minimal CreateOptions and still list the share.
func TestClientListAndReadQuirkyNAS(t *testing.T) {
	f := startFake(t, 0x01)
	f.quirkyCreate = true
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
		t.Fatalf("readdir should have fallen back to minimal CreateOptions: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d: %+v", len(entries), entries)
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
	n := int(u16(guest, 20))
	if n < 32 || n != len(guest)-64-int(u16(guest, 28))-int(u16(guest, 36))-int(u16(guest, 44)) {
		t.Errorf("guest NT response length = %d (message %d bytes)", n, len(guest))
	}
	if string(guest[64+16:64+20]) != "\x01\x01\x00\x00" {
		t.Errorf("missing NTLMv2 blob signature: %x", guest[64+16:64+20])
	}
	if u32(guest, 60)&0x00080000 == 0 {
		t.Error("NTLMv2 response must advertise extended session security")
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

	entries, err := parseDirEntries(resp, 0x25)
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

// TestParseDirEntriesRejectsShortNextOffset guards against a malformed (or
// hostile) QUERY_DIRECTORY reply whose NextEntryOffset points into the
// middle of the entry it belongs to instead of past it: parsing must fail
// loudly instead of decoding garbage as a second entry.
func TestParseDirEntriesRejectsShortNextOffset(t *testing.T) {
	buf := dirEntry("a.txt", 0, 10)
	putU32(buf, 0, 1) // NextEntryOffset = 1, far below the 104-byte fixed header

	resp := make([]byte, 8+len(buf))
	putU16(resp, 0, 9)
	putU16(resp, 2, 72)
	putU32(resp, 4, uint32(len(buf)))
	copy(resp[8:], buf)

	if _, err := parseDirEntries(resp, 0x25); err == nil {
		t.Fatal("expected an error for a NextEntryOffset shorter than the fixed entry header")
	}
}

func TestFiletimeToTime(t *testing.T) {
	if got := filetimeToTime(0); !got.IsZero() {
		t.Errorf("filetimeToTime(0) = %v, want zero time", got)
	}
	// 2021-01-01T00:00:00Z expressed as FILETIME ticks (100ns since
	// 1601-01-01), computed independently of the function under test.
	want := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	ticks := uint64(want.Unix()+11644473600) * 10_000_000
	if got := filetimeToTime(ticks).UTC(); !got.Equal(want) {
		t.Errorf("filetimeToTime(%d) = %v, want %v", ticks, got, want)
	}
}

func TestNDRShareEnumRoundTrip(t *testing.T) {
	req := ndrShareEnumRequest(`\\127.0.0.1`)
	if len(req) < 24 {
		t.Fatalf("short request: %d", len(req))
	}
	if u32(req, 0) != 0x00020000 {
		t.Errorf("ServerName referent = %#x", u32(req, 0))
	}
	max, off, actual := u32(req, 4), u32(req, 8), u32(req, 12)
	if max != actual || off != 0 || actual != 12 {
		t.Fatalf("string header max=%d off=%d actual=%d", max, off, actual)
	}
	pos := align4(16 + int(actual)*2)
	if got := u32(req, pos); got != 1 {
		t.Errorf("Level = %d", got)
	}
	if got := u32(req, pos+4); got != 1 {
		t.Errorf("union tag = %d", got)
	}
	if got := u32(req, pos+8); got != 0x00020004 {
		t.Errorf("container referent = %#x", got)
	}
	if got := u32(req, pos+20); got != 0xFFFFFFFF {
		t.Errorf("PreferedMaximumLength = %#x", got)
	}

	// Build a response stub with two shares and parse it back.
	w := &ndrWriter{}
	w.u32(1)          // Level
	w.u32(1)          // union tag
	w.u32(0x00020004) // container
	w.u32(2)          // EntriesRead
	w.u32(0x00020010) // buffer
	w.u32(2)          // array max count
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
	w.u32(0) // resume ref
	w.u32(0) // resume value
	w.u32(0) // win32 error

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
		_, _ = parseDirEntries(data, 0x25)
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

func TestSessionSetupOffsets(t *testing.T) {
	tok := negoType1()
	blob := spnegoInit(tok)
	body := sessionSetupBody(blob)

	if got := u16(body, 0); got != 25 {
		t.Errorf("StructureSize = %d", got)
	}
	if got := u16(body, 12); got != smb2HeaderSize+24 {
		t.Errorf("SecurityBufferOffset = %d, want %d", got, smb2HeaderSize+24)
	}
	if got := u16(body, 14); got != uint16(len(blob)) {
		t.Errorf("SecurityBufferLength = %d, want %d", got, len(blob))
	}
	if off := int(u16(body, 12)) - smb2HeaderSize; string(body[off:off+1]) != "\x60" {
		t.Errorf("security buffer does not start with a GSS-API token: %x", body[off:off+4])
	}
}

func TestBindBodyLayout(t *testing.T) {
	b := bindBody()
	if len(b) != 56 {
		t.Fatalf("bind body length = %d, want 56", len(b))
	}
	if b[8] != 1 { // one presentation context
		t.Errorf("num contexts = %d", b[8])
	}
	if b[14] != 1 { // one transfer syntax
		t.Errorf("num transfer syntaxes = %d", b[14])
	}
	if b[12] != 0 || b[13] != 0 { // context id must be zero
		t.Errorf("context id = %d", int(b[12])|int(b[13])<<8)
	}
	if !bytesEqual(b[16:32], uuidSRVSVC[:]) {
		t.Error("abstract syntax uuid mismatch")
	}
	if !bytesEqual(b[36:52], uuidNDR32[:]) {
		t.Error("transfer syntax uuid mismatch")
	}
	if got := u32(b, 32); got != 3 {
		t.Errorf("interface version = %d", got)
	}
	if got := u32(b, 52); got != 2 {
		t.Errorf("ndr version = %d", got)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Captured from a real NetrShareEnum response (two disk shares). This pins the
// NDR layout that a real server emits, which is easy to get subtly wrong.
func TestNDRParseRealResponse(t *testing.T) {
	const hexStub = "010000000100000041690000020000009b79000002000000d6c500000000000030840000ed88" +
		"000000000000fca2000005000000000000000500000049005000430024000000abab010000" +
		"0000000000010000000000abab05000000000000000500000054004500530054000000abab" +
		"0100000000000000010000000000bfbf020000000b4600000000000000000000"
	stub, err := hex.DecodeString(hexStub)
	if err != nil {
		t.Fatal(err)
	}
	shares, err := ndrParseShareEnum(stub)
	if err != nil {
		t.Fatal(err)
	}
	if len(shares) != 2 {
		t.Fatalf("shares = %d: %+v", len(shares), shares)
	}
	if shares[0].Name != "IPC$" || shares[0].Type != "disk" {
		t.Errorf("share[0] = %+v", shares[0])
	}
	if shares[1].Name != "TEST" {
		t.Errorf("share[1] = %+v", shares[1])
	}
}

func FuzzParseShareEnum(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 1, 0, 0, 0, 4, 0, 2, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = ndrParseShareEnum(data)
	})
}

// TestNegotiateFallsBackTo311 is the README limitation "SMB 3.1.1 ... is not
// implemented": a server with a 3.1.1 minimum refuses the default offer, and
// the client must retry offering 3.1.1 with the pre-auth integrity context.
func TestNegotiateFallsBackTo311(t *testing.T) {
	f := startFake(t, 0x01)
	f.min311 = true
	host, port := f.addr()

	cfg := DefaultConfig()
	cfg.Port = port
	cfg.IOTimeout = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	p, err := ProbeHost(ctx, host, cfg)
	if err != nil {
		t.Fatalf("probe against a 3.1.1-only server: %v", err)
	}
	if p.Dialect != "3.1.1" {
		t.Errorf("dialect = %q, want 3.1.1", p.Dialect)
	}
	if !f.ctxChecked.Load() {
		t.Error("server never saw a valid pre-auth integrity negotiate context")
	}
	if p.AuthKind() != "null" {
		t.Errorf("auth = %q, want null: %+v", p.AuthKind(), p.Auth)
	}
}

func TestNegotiateRequestShape(t *testing.T) {
	var guid [16]byte
	// Without 3.1.1 the request must stay the classic layout: no contexts and
	// ClientStartTime (offsets 28..35) all zero.
	plain := buildNegotiateRequest(smb2Dialects, guid)
	if got := len(plain); got != 36+2*len(smb2Dialects) {
		t.Errorf("plain request length = %d", got)
	}
	if u32(plain, 28) != 0 || u16(plain, 32) != 0 {
		t.Error("a request without 3.1.1 must not carry negotiate contexts")
	}

	body := buildNegotiateRequest(smb2Dialects311, guid)
	if !validPreauthContext(body) {
		t.Errorf("3.1.1 request has a malformed pre-auth context: %x", body)
	}
}

func TestRefusedDialects(t *testing.T) {
	for err, want := range map[error]bool{
		StatusNotSupported:      true,
		io.EOF:                  true,
		io.ErrUnexpectedEOF:     true,
		StatusAccessDenied:      false,
		errShortFrame:           false,
		errors.New("bad frame"): false,
	} {
		if got := refusedDialects(err); got != want {
			t.Errorf("refusedDialects(%v) = %v, want %v", err, got, want)
		}
	}
}

// TestOpenDoesNotLeakTreeConnects: every Client.Open made its own tree
// connect and Close only released the file handle, so opening many files
// (previews, recursive downloads) piled up trees on the session.
func TestOpenDoesNotLeakTreeConnects(t *testing.T) {
	f := startFake(t, 0x01)
	host, port := f.addr()
	cfg := DefaultConfig()
	cfg.Port = port
	cfg.IOTimeout = 2 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, err := Connect(ctx, host, "null", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	base := f.openTrees.Load()
	for i := 0; i < 5; i++ {
		rc, _, err := c.Open(ctx, "public", "readme.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(rc); err != nil {
			t.Fatal(err)
		}
		_ = rc.Close()
	}
	if got := f.openTrees.Load(); got != base {
		t.Errorf("open trees = %d after 5 open/close cycles, want %d (leak)", got, base)
	}
}

// TestConcurrentCallsOnOneSession reproduces the TUI pattern: a download
// streams in one goroutine while the user keeps listing directories on the
// same connection. Unserialised, frames interleave and a response is dropped.
func TestConcurrentCallsOnOneSession(t *testing.T) {
	f := startFake(t, 0x01)
	host, port := f.addr()
	cfg := DefaultConfig()
	cfg.Port = port
	cfg.IOTimeout = 3 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	c, err := Connect(ctx, host, "null", cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				if g%2 == 0 {
					if _, err := c.ReadDir(ctx, "public", ""); err != nil {
						errs <- err
						return
					}
					continue
				}
				rc, _, err := c.Open(ctx, "public", "readme.txt")
				if err != nil {
					errs <- err
					return
				}
				if _, err := io.ReadAll(rc); err != nil {
					errs <- err
				}
				_ = rc.Close()
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent call failed: %v", err)
	}
}

func TestParseDirEntriesClass01(t *testing.T) {
	// FileDirectoryInformation: 64-byte header, name at 64.
	name := utf16le("notes.txt")
	buf := make([]byte, 64+len(name))
	putU32(buf, 60, uint32(len(name)))
	putU32(buf, 56, 0) // regular file
	putU64(buf, 40, 42)
	copy(buf[64:], name)

	resp := make([]byte, 8+len(buf))
	putU16(resp, 0, 9)
	putU16(resp, 2, 72)
	putU32(resp, 4, uint32(len(buf)))
	copy(resp[8:], buf)

	entries, err := parseDirEntries(resp, 0x01)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "notes.txt" || entries[0].Size != 42 {
		t.Fatalf("entries = %+v", entries)
	}
}
