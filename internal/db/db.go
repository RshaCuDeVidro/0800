// Package db probes database services for missing authentication.
package db

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Result describes one database endpoint.
type Result struct {
	Port    int
	Proto   string
	Version string
	User    string
	Status  string // "open", "auth", "error"
	Detail  []string
	Err     string
}

// Probe dispatches by port.
func Probe(ctx context.Context, ip string, port int, timeout time.Duration) Result {
	switch port {
	case 3306:
		return probeMySQL(ctx, ip, port, timeout)
	case 5432:
		return probePostgres(ctx, ip, port, timeout)
	case 6379:
		return probeRedis(ctx, ip, port, timeout)
	default:
		return Result{Port: port, Proto: "tcp", Status: "error", Err: "unsupported port"}
	}
}

func dial(ctx context.Context, ip string, port int, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	dl := time.Now().Add(timeout * 2)
	if t, ok := ctx.Deadline(); ok && t.Before(dl) {
		dl = t
	}
	_ = c.SetDeadline(dl)
	return c, nil
}

// --- MySQL ----------------------------------------------------------------

func probeMySQL(ctx context.Context, ip string, port int, timeout time.Duration) Result {
	res := Result{Port: port, Proto: "mysql", Status: "error"}
	nc, err := dial(ctx, ip, port, timeout)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer nc.Close()

	br := bufio.NewReaderSize(nc, 32*1024)
	pkt, err := readMySQLPacket(br)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	hs, err := parseHandshake(pkt)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	res.Version = hs.version
	res.Detail = append(res.Detail, "version "+hs.version)
	if hs.plugin != "" {
		res.Detail = append(res.Detail, "auth plugin "+hs.plugin)
	}

	users := []string{"root", "mysql", "admin"}
	for _, user := range users {
		if err := writeMySQLPacket(nc, 1, handshakeResponse(user, hs)); err != nil {
			continue
		}
		for attempt := 0; attempt < 2; attempt++ {
			resp, err := readMySQLPacket(br)
			if err != nil {
				break
			}
			if len(resp) == 0 {
				break
			}
			switch resp[0] {
			case 0x00: // OK
				res.Status = "open"
				res.User = user
				res.Detail = append(res.Detail, "empty password accepted for "+user)
				return res
			case 0xFF: // ERR
				msg := mysqlError(resp)
				res.Status = "auth"
				res.Detail = append(res.Detail, "rejected: "+msg)
				attempt = 2
			case 0xFE: // auth switch
				if len(resp) > 1 {
					// Empty password: answer the switch with an empty blob.
					if err := writeMySQLPacket(nc, 3, nil); err != nil {
						attempt = 2
					}
					continue
				}
				attempt = 2
			case 0x01: // more data (caching_sha2 public key request)
				res.Status = "auth"
				res.Detail = append(res.Detail, "server requires full authentication (TLS/RSA)")
				return res
			default:
				attempt = 2
			}
		}
	}
	if res.Status != "auth" {
		res.Status = "auth"
	}
	return res
}

type handshake struct {
	version  string
	salt     []byte
	plugin   string
	caps     uint32
	charset  byte
	salt2    []byte
	protocol byte
	threadID uint32
}

func parseHandshake(p []byte) (handshake, error) {
	var hs handshake
	if len(p) < 34 {
		return hs, errors.New("mysql: short handshake")
	}
	if p[0] == 0xFF {
		return hs, errors.New("mysql: server refused connection")
	}
	hs.protocol = p[0]
	off := 1
	ver, n, ok := cstring(p[off:])
	if !ok {
		return hs, errors.New("mysql: bad version string")
	}
	hs.version = ver
	off += n
	if off+4+8+1+2 > len(p) {
		return hs, errors.New("mysql: truncated handshake")
	}
	hs.threadID = binary.LittleEndian.Uint32(p[off:])
	off += 4
	hs.salt = append(hs.salt, p[off:off+8]...)
	off += 8
	off++ // filler
	capsLo := uint32(binary.LittleEndian.Uint16(p[off:]))
	off += 2
	if off >= len(p) {
		hs.caps = capsLo
		return hs, nil
	}
	hs.charset = p[off]
	off++
	off += 2 // status flags
	if off+2 <= len(p) {
		hi := uint32(binary.LittleEndian.Uint16(p[off:]))
		hs.caps = capsLo | hi<<16
		off += 2
	}
	authLen := 0
	if off < len(p) {
		authLen = int(p[off])
		off++
	}
	off += 10 // reserved
	if hs.caps&0x8000 != 0 && off < len(p) {
		n := authLen - 8
		if n <= 0 {
			n = 13
		}
		if n > 32 {
			n = 32
		}
		if off+n > len(p) {
			n = len(p) - off
		}
		hs.salt2 = append(hs.salt2, p[off:off+n]...)
		off += n
	}
	if hs.caps&0x80000 != 0 && off < len(p) {
		if pl, _, ok := cstring(p[off:]); ok {
			hs.plugin = pl
		}
	}
	hs.salt = append(hs.salt, hs.salt2...)
	return hs, nil
}

func handshakeResponse(user string, hs handshake) []byte {
	const (
		clientLongPassword  = 0x00000001
		clientProtocol41    = 0x00000200
		clientTransactions  = 0x00002000
		clientSecureConn    = 0x00008000
		clientPluginAuth    = 0x00080000
		clientConnectWithDB = 0x00000008
	)
	caps := uint32(clientLongPassword | clientProtocol41 | clientSecureConn | clientPluginAuth | clientTransactions)

	var b []byte
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], caps)
	b = append(b, tmp[:]...)
	binary.LittleEndian.PutUint32(tmp[:], 16*1024*1024)
	b = append(b, tmp[:]...)
	b = append(b, 33)                  // utf8_general_ci
	b = append(b, make([]byte, 23)...) // filler
	b = append(b, []byte(user)...)
	b = append(b, 0)
	b = append(b, 0) // empty auth response
	if caps&clientPluginAuth != 0 && hs.plugin != "" {
		b = append(b, []byte(hs.plugin)...)
		b = append(b, 0)
	}
	return b
}

func readMySQLPacket(r *bufio.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:3]); err != nil {
		return nil, err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if n < 0 || n > 16<<20 {
		return nil, fmt.Errorf("mysql: invalid packet length %d", n)
	}
	if _, err := io.ReadFull(r, hdr[3:]); err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func writeMySQLPacket(w io.Writer, seq byte, payload []byte) error {
	hdr := []byte{byte(len(payload)), byte(len(payload) >> 8), byte(len(payload) >> 16), seq}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func mysqlError(p []byte) string {
	if len(p) < 3 {
		return "unknown error"
	}
	code := binary.LittleEndian.Uint16(p[1:])
	msg := string(p[3:])
	if i := strings.IndexByte(msg, '#'); i == 0 && len(msg) >= 6 {
		msg = msg[6:]
	}
	return fmt.Sprintf("%d %s", code, sanitise(msg))
}

// --- PostgreSQL -----------------------------------------------------------

func probePostgres(ctx context.Context, ip string, port int, timeout time.Duration) Result {
	res := Result{Port: port, Proto: "postgres", Status: "error"}
	nc, err := dial(ctx, ip, port, timeout)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer nc.Close()
	br := bufio.NewReaderSize(nc, 32*1024)

	users := []string{"postgres", "root", "admin"}
	for _, user := range users {
		if _, err := nc.Write(startupMessage(user)); err != nil {
			res.Err = err.Error()
			return res
		}
		status, version, msg, err := readPostgresStartup(br)
		if err != nil {
			res.Err = err.Error()
			return res
		}
		if version != "" {
			res.Version = version
		}
		switch status {
		case "trust":
			res.Status = "open"
			res.User = user
			res.Detail = append(res.Detail, "trust authentication for "+user)
			return res
		case "password":
			res.Status = "auth"
			res.Detail = append(res.Detail, "password required for "+user)
			return res
		default:
			if msg != "" {
				res.Detail = append(res.Detail, msg)
			}
		}
	}
	if res.Status == "error" {
		res.Status = "auth"
	}
	return res
}

func startupMessage(user string) []byte {
	var body []byte
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], 196608)
	body = append(body, tmp[:]...)
	for _, kv := range [][2]string{{"user", user}, {"database", "postgres"}, {"application_name", "0800"}} {
		body = append(body, kv[0]...)
		body = append(body, 0)
		body = append(body, kv[1]...)
		body = append(body, 0)
	}
	body = append(body, 0)
	out := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(4+len(body)))
	return append(out, body...)
}

func readPostgresStartup(r *bufio.Reader) (status, version, msg string, err error) {
	trust := false
	for i := 0; i < 64; i++ {
		typ, payload, err := readPostgresMessage(r)
		if err != nil {
			return "", version, msg, err
		}
		switch typ {
		case 'R':
			if len(payload) < 4 {
				return "", version, msg, errors.New("postgres: short auth message")
			}
			code := binary.BigEndian.Uint32(payload)
			switch code {
			case 0:
				// Trust: keep reading so server_version is captured.
				trust = true
			case 3, 5, 10:
				return "password", version, msg, nil
			}
		case 'S':
			name, val, _ := strings.Cut(string(payload), "\x00")
			if name == "server_version" {
				version = strings.TrimRight(val, "\x00")
			}
		case 'E':
			msg = postgresError(payload)
		case 'Z':
			if trust {
				return "trust", version, msg, nil
			}
			return "ready", version, msg, nil
		case 'K':
			// backend key, keep reading
		}
	}
	return "unknown", version, msg, nil
}

func readPostgresMessage(r *bufio.Reader) (byte, []byte, error) {
	typ, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	var l [4]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint32(l[:])) - 4
	if n < 0 || n > 8<<20 {
		return 0, nil, fmt.Errorf("postgres: invalid message length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return typ, buf, nil
}

func postgresError(p []byte) string {
	var sev, msg string
	for len(p) > 1 {
		field := p[0]
		p = p[1:]
		s, n, ok := cstring(p)
		if !ok {
			break
		}
		p = p[n:]
		switch field {
		case 'S':
			sev = s
		case 'M':
			msg = s
		}
	}
	return strings.TrimSpace(sev + ": " + msg)
}

// --- Redis ----------------------------------------------------------------

func probeRedis(ctx context.Context, ip string, port int, timeout time.Duration) Result {
	res := Result{Port: port, Proto: "redis", Status: "error"}
	nc, err := dial(ctx, ip, port, timeout)
	if err != nil {
		res.Err = err.Error()
		return res
	}
	defer nc.Close()
	br := bufio.NewReaderSize(nc, 32*1024)

	if _, err := nc.Write([]byte("PING\r\n")); err != nil {
		res.Err = err.Error()
		return res
	}
	line, err := br.ReadString('\n')
	if err != nil {
		res.Err = err.Error()
		return res
	}
	line = strings.TrimSpace(line)
	switch {
	case strings.HasPrefix(line, "+PONG"):
		res.Status = "open"
	case strings.HasPrefix(line, "-NOAUTH"), strings.HasPrefix(line, "-WRONGPASS"):
		res.Status = "auth"
		res.Detail = append(res.Detail, "authentication required")
		return res
	case strings.HasPrefix(line, "-DENIED"):
		res.Status = "auth"
		res.Detail = append(res.Detail, "command denied")
		return res
	case strings.HasPrefix(line, "-"):
		res.Status = "auth"
		res.Detail = append(res.Detail, strings.TrimPrefix(line, "-"))
		return res
	default:
		res.Status = "open"
	}

	res.Detail = append(res.Detail, "PING answered without credentials")
	if _, err := nc.Write([]byte("INFO server\r\n")); err == nil {
		if info, err := readRedisBulk(br); err == nil {
			for _, ln := range strings.Split(info, "\n") {
				ln = strings.TrimSpace(ln)
				if v, ok := strings.CutPrefix(ln, "redis_version:"); ok {
					res.Version = strings.TrimSpace(v)
					res.Detail = append(res.Detail, "redis "+res.Version)
				} else if v, ok := strings.CutPrefix(ln, "os:"); ok {
					res.Detail = append(res.Detail, "os "+strings.TrimSpace(v))
				}
			}
		}
	}
	if _, err := nc.Write([]byte("DBSIZE\r\n")); err == nil {
		if line, err := br.ReadString('\n'); err == nil {
			if n, ok := strings.CutPrefix(strings.TrimSpace(line), ":"); ok {
				res.Detail = append(res.Detail, "dbsize "+n)
			}
		}
	}
	return res
}

func readRedisBulk(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "$") {
		return "", fmt.Errorf("redis: unexpected reply %q", line)
	}
	n, err := strconv.Atoi(strings.TrimPrefix(line, "$"))
	if err != nil || n < 0 || n > 1<<20 {
		return "", errors.New("redis: invalid bulk length")
	}
	buf := make([]byte, n+2)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// --- helpers --------------------------------------------------------------

func cstring(b []byte) (string, int, bool) {
	i := strings.IndexByte(string(b), 0)
	if i < 0 {
		return "", 0, false
	}
	return string(b[:i]), i + 1, true
}

func sanitise(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return strings.TrimSpace(s)
}
