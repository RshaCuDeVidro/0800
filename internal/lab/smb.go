package lab

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf16"
)

// SMB is a deliberately open SMB2 server: it accepts an anonymous session and
// exposes two shares. Nothing here is hardened on purpose.
type SMB struct {
	ln      net.Listener
	accepts atomic.Int32
	smb1    bool
	signing uint16 // 0x01 enabled, 0x02 required, 0x03 both
}

// SMBConfig tunes the fake server.
type SMBConfig struct {
	Port    int
	SMB1    bool
	Signing string // "disabled" | "enabled" | "required"
	NullOK  bool
}

// NewSMB creates the server. Call Start to listen.
func NewSMB(cfg SMBConfig) *SMB {
	s := &SMB{smb1: cfg.SMB1, signing: 0x01}
	switch cfg.Signing {
	case "disabled":
		s.signing = 0x00
	case "required":
		s.signing = 0x02
	}
	return s
}

// Start listens on the configured port (0 = ephemeral).
func (s *SMB) Start(port int) (Service, error) {
	ln, err := listen(port)
	if err != nil {
		return Service{}, err
	}
	s.ln = ln
	go s.serve()
	return Service{Name: "smb", Port: ln.Addr().(*net.TCPAddr).Port, Listener: ln}, nil
}

// Connections reports how many TCP sessions were accepted.
func (s *SMB) Connections() int { return int(s.accepts.Load()) }

func (s *SMB) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.accepts.Add(1)
		go s.handle(c)
	}
}

const lbHeader = 64

func (s *SMB) handle(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Minute))
	br := bufio.NewReader(c)
	var (
		session uint64
		stage   int
	)

	for {
		frame, err := lbRead(br)
		if err != nil {
			return
		}
		if len(frame) < 5 {
			return
		}
		if frame[0] == 0xFF { // SMB1
			if frame[4] == 0x72 {
				_, _ = c.Write(lbFrame(lbSMB1Resp(s.signing)))
			}
			continue
		}
		if len(frame) < lbHeader {
			return
		}
		status := lbU32(frame, 8)
		_ = status
		cmd := lbU16(frame, 12)
		msgID := lbU64(frame, 24)
		treeID := lbU32(frame, 36)
		body := frame[lbHeader:]

		switch cmd {
		case 0: // negotiate
			s.reply(c, 0, 0, msgID, 0, 0, lbNegotiate(s.signing))

		case 1: // session setup
			stage++
			if stage == 1 {
				session = 7
				s.reply(c, 1, 0xC0000016, msgID, session, 0, lbSessionResp(0, lbSpnego(lbType2())))
				continue
			}
			s.reply(c, 1, 0, msgID, session, 0, lbSessionResp(0x0002, nil))

		case 3: // tree connect
			name := lbUTF16At(body, 4, 6)
			share := name
			if i := strings.LastIndex(name, `\`); i >= 0 {
				share = name[i+1:]
			}
			switch strings.ToLower(share) {
			case "public", "storage", "ipc$", "":
				resp := make([]byte, 16)
				lbPut16(resp, 0, 16)
				resp[2] = 1
				access := uint32(0x001200A9) // read
				if strings.EqualFold(share, "storage") {
					access = 0x001F01FF // full
				}
				lbPut32(resp, 12, access)
				s.reply(c, 3, 0, msgID, session, 1, resp)
			default:
				s.reply(c, 3, 0xC00000CC, msgID, session, 0, nil)
			}

		case 5: // create
			name := lbUTF16At(body, 44, 46)
			if strings.EqualFold(name, "srvsvc") {
				s.reply(c, 5, 0xC0000034, msgID, session, treeID, nil)
				continue
			}
			resp := make([]byte, 88)
			lbPut16(resp, 0, 89)
			if name == "" {
				lbPut32(resp, 56, 0x10)
			} else {
				lbPut64(resp, 48, uint64(len(labFile)))
			}
			for i := 0; i < 16; i++ {
				resp[64+i] = byte(i + 1)
			}
			s.reply(c, 5, 0, msgID, session, treeID, resp)

		case 14: // query directory
			if body[3]&0x01 == 0 {
				s.reply(c, 14, 0x80000006, msgID, session, treeID, nil)
				continue
			}
			first := lbDirEntry("financeiro", 0x10, 0)
			lbPut32(first, 0, uint32(len(first)))
			buf := append(first, lbDirEntry("passwords.txt", 0, uint64(len(labFile)))...)
			resp := make([]byte, 8+len(buf))
			lbPut16(resp, 0, 9)
			lbPut16(resp, 2, 72)
			lbPut32(resp, 4, uint32(len(buf)))
			copy(resp[8:], buf)
			s.reply(c, 14, 0, msgID, session, treeID, resp)

		case 8: // read
			off := lbU64(body, 8)
			if off >= uint64(len(labFile)) {
				s.reply(c, 8, 0xC0000011, msgID, session, treeID, nil)
				continue
			}
			data := labFile[off:]
			if len(data) > 4096 {
				data = data[:4096]
			}
			resp := make([]byte, 16+len(data))
			lbPut16(resp, 0, 17)
			resp[2] = 80
			lbPut32(resp, 4, uint32(len(data)))
			copy(resp[16:], data)
			s.reply(c, 8, 0, msgID, session, treeID, resp)

		case 6, 4, 2: // close, tree disconnect, logoff
			size := 4
			if cmd == 6 {
				size = 60
			}
			resp := make([]byte, size)
			lbPut16(resp, 0, uint16(size+1))
			s.reply(c, cmd, 0, msgID, session, treeID, resp)

		case 9: // write
			resp := make([]byte, 16)
			lbPut16(resp, 0, 17)
			s.reply(c, 9, 0, msgID, session, treeID, resp)

		default:
			s.reply(c, cmd, 0xC00000BB, msgID, session, treeID, nil)
		}
	}
}

var labFile = []byte("0800 lab file\nuser=lab\npassword=not-a-real-secret\n")

func (s *SMB) reply(c net.Conn, cmd uint16, status uint32, msgID, session uint64, tree uint32, body []byte) {
	b := make([]byte, lbHeader+len(body))
	copy(b, []byte{0xFE, 'S', 'M', 'B'})
	lbPut16(b, 4, 64)
	lbPut32(b, 8, status)
	lbPut16(b, 12, cmd)
	lbPut16(b, 14, 64)
	lbPut64(b, 24, msgID)
	lbPut32(b, 36, tree)
	lbPut64(b, 40, session)
	copy(b[lbHeader:], body)
	_, _ = c.Write(lbFrame(b))
}

func lbFrame(b []byte) []byte {
	hdr := []byte{0, byte(len(b) >> 16), byte(len(b) >> 8), byte(len(b))}
	return append(hdr, b...)
}

func lbRead(br *bufio.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, err
	}
	n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if n < 32 || n > 8<<20 {
		return nil, io.ErrUnexpectedEOF
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(br, buf)
	return buf, err
}

func lbNegotiate(sign uint16) []byte {
	resp := make([]byte, 64)
	lbPut16(resp, 0, 65)
	lbPut16(resp, 2, sign)
	lbPut16(resp, 4, 0x0302)
	lbPut32(resp, 28, 1<<20)
	lbPut32(resp, 32, 1<<20)
	lbPut32(resp, 36, 1<<20)
	return resp
}

func lbSessionResp(flags uint16, blob []byte) []byte {
	resp := make([]byte, 8+len(blob))
	lbPut16(resp, 0, 9)
	lbPut16(resp, 2, flags)
	if len(blob) > 0 {
		lbPut16(resp, 4, 72)
		lbPut16(resp, 6, uint16(len(blob)))
		copy(resp[8:], blob)
	}
	return resp
}

func lbSMB1Resp(sign uint16) []byte {
	b := make([]byte, 69)
	copy(b, []byte{0xFF, 'S', 'M', 'B'})
	b[4] = 0x72
	b[9] = 0x18
	b[32] = 17
	lbPut16(b, 35, sign)
	return b
}

func lbType2() []byte {
	var ti []byte
	for _, av := range []struct {
		id uint16
		s  string
	}{{1, "LAB-DC"}, {2, "LAB"}, {3, "lab-dc.lab.local"}, {4, "lab.local"}, {5, "lab.local"}} {
		u := lbUTF16(av.s)
		hdr := make([]byte, 4)
		binary.LittleEndian.PutUint16(hdr, av.id)
		binary.LittleEndian.PutUint16(hdr[2:], uint16(len(u)))
		ti = append(ti, hdr...)
		ti = append(ti, u...)
	}
	ti = append(ti, 0, 0, 0, 0)

	b := make([]byte, 48+len(ti))
	copy(b, []byte("NTLMSSP\x00"))
	lbPut32(b, 8, 2)
	lbPut32(b, 20, 0x00008201)
	copy(b[24:32], []byte("LABCHAL!"))
	lbPut16(b, 40, uint16(len(ti)))
	lbPut32(b, 44, 48)
	copy(b[48:], ti)
	return b
}

func lbSpnego(tok []byte) []byte {
	oid := []byte{0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A}
	mechTypes := lbDer(0xA0, lbDer(0x30, oid))
	mechToken := lbDer(0xA2, lbDer(0x04, tok))
	init := lbDer(0x30, mechTypes, mechToken)
	return lbDer(0x60, []byte{0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02}, lbDer(0xA0, init))
}

func lbDer(tag byte, parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	out := []byte{tag}
	n := len(body)
	if n < 0x80 {
		out = append(out, byte(n))
	} else {
		var tmp []byte
		for n > 0 {
			tmp = append([]byte{byte(n)}, tmp...)
			n >>= 8
		}
		out = append(out, 0x80|byte(len(tmp)))
		out = append(out, tmp...)
	}
	return append(out, body...)
}

func lbDirEntry(name string, attrs uint32, size uint64) []byte {
	u := lbUTF16(name)
	b := make([]byte, 104+len(u))
	lbPut32(b, 56, attrs)
	lbPut32(b, 60, uint32(len(u)))
	lbPut64(b, 40, size)
	lbPut64(b, 24, 133000000000000000)
	copy(b[104:], u)
	return b
}

func lbUTF16At(body []byte, offField, lenField int) string {
	off := int(lbU16(body, offField)) - lbHeader
	n := int(lbU16(body, lenField))
	if off < 0 || n < 0 || off+n > len(body) {
		return ""
	}
	return lbFromUTF16(body[off : off+n])
}

func lbUTF16(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, len(u)*2)
	for i, v := range u {
		binary.LittleEndian.PutUint16(out[i*2:], v)
	}
	return out
}

func lbFromUTF16(b []byte) string {
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	return string(utf16.Decode(u))
}

func lbU16(b []byte, off int) uint16 {
	if off+2 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint16(b[off:])
}

func lbU32(b []byte, off int) uint32 {
	if off+4 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint32(b[off:])
}

func lbU64(b []byte, off int) uint64 {
	if off+8 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint64(b[off:])
}

func lbPut16(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
func lbPut32(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
func lbPut64(b []byte, off int, v uint64) { binary.LittleEndian.PutUint64(b[off:], v) }
