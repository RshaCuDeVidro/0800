package db

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func listen(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func ctxT(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// --- MySQL ----------------------------------------------------------------

func mysqlHandshake(ok bool) net.Listener {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				_ = writeMySQLPacket(c, 0, mysqlGreeting())
				for {
					if _, err := readMySQLPacket(br); err != nil {
						return
					}
					if ok {
						_ = writeMySQLPacket(c, 2, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})
						return
					}
					// ERR 1045
					p := []byte{0xFF, 0x15, 0x04, '#', '2', '8', '0', '0', '0'}
					p = append(p, []byte("Access denied for user")...)
					_ = writeMySQLPacket(c, 2, p)
				}
			}(c)
		}
	}()
	return ln
}

func mysqlGreeting() []byte {
	var b []byte
	b = append(b, 10) // protocol
	b = append(b, []byte("8.0.35")...)
	b = append(b, 0)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], 42)
	b = append(b, tmp[:]...)
	b = append(b, []byte("12345678")...)
	b = append(b, 0)
	// capabilities: protocol41 | secure connection | plugin auth
	caps := uint32(0x00088200)
	binary.LittleEndian.PutUint16(tmp[:2], uint16(caps))
	b = append(b, tmp[:2]...)
	b = append(b, 33)
	binary.LittleEndian.PutUint16(tmp[:2], 2)
	b = append(b, tmp[:2]...)
	binary.LittleEndian.PutUint16(tmp[:2], uint16(caps>>16))
	b = append(b, tmp[:2]...)
	b = append(b, 21)
	b = append(b, make([]byte, 10)...)
	b = append(b, []byte("abcdefghijkl")...)
	b = append(b, 0)
	b = append(b, []byte("caching_sha2_password")...)
	b = append(b, 0)
	return b
}

func TestMySQLOpen(t *testing.T) {
	ln := mysqlHandshake(true)
	port := ln.Addr().(*net.TCPAddr).Port
	res := probeMySQL(ctxT(t), "127.0.0.1", port, 2*time.Second)
	if res.Status != "open" || res.User != "root" {
		t.Fatalf("status=%q user=%q detail=%v err=%q", res.Status, res.User, res.Detail, res.Err)
	}
	if res.Version != "8.0.35" {
		t.Errorf("version = %q", res.Version)
	}
}

func TestMySQLAuthRequired(t *testing.T) {
	ln := mysqlHandshake(false)
	port := ln.Addr().(*net.TCPAddr).Port
	res := probeMySQL(ctxT(t), "127.0.0.1", port, 2*time.Second)
	if res.Status != "auth" {
		t.Fatalf("status = %q (err %q)", res.Status, res.Err)
	}
}

func TestParseHandshakeTruncated(t *testing.T) {
	if _, err := parseHandshake([]byte{10, 'a', 0}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := parseHandshake([]byte{0xFF}); err == nil {
		t.Fatal("expected error")
	}
}

// --- PostgreSQL -----------------------------------------------------------

func postgresFake(auth uint32) net.Listener {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				// startup message
				var l [4]byte
				if _, err := io.ReadFull(br, l[:]); err != nil {
					return
				}
				n := int(binary.BigEndian.Uint32(l[:])) - 4
				if n < 0 || n > 1<<20 {
					return
				}
				_, _ = io.ReadFull(br, make([]byte, n))
				writePG(c, 'R', u32bytes(auth))
				if auth == 0 {
					writePG(c, 'S', append([]byte("server_version\x00"), []byte("16.2\x00")...))
					writePG(c, 'Z', []byte{'I'})
				}
			}(c)
		}
	}()
	return ln
}

func writePG(w io.Writer, typ byte, payload []byte) {
	buf := make([]byte, 5+len(payload))
	buf[0] = typ
	binary.BigEndian.PutUint32(buf[1:], uint32(len(payload)+4))
	copy(buf[5:], payload)
	_, _ = w.Write(buf)
}

func u32bytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func TestPostgresTrust(t *testing.T) {
	ln := postgresFake(0)
	port := ln.Addr().(*net.TCPAddr).Port
	res := probePostgres(ctxT(t), "127.0.0.1", port, 2*time.Second)
	if res.Status != "open" || res.User != "postgres" {
		t.Fatalf("status=%q user=%q err=%q", res.Status, res.User, res.Err)
	}
	if res.Version != "16.2" {
		t.Errorf("version = %q", res.Version)
	}
}

func TestPostgresPassword(t *testing.T) {
	ln := postgresFake(5)
	port := ln.Addr().(*net.TCPAddr).Port
	res := probePostgres(ctxT(t), "127.0.0.1", port, 2*time.Second)
	if res.Status != "auth" {
		t.Fatalf("status = %q", res.Status)
	}
}

// --- Redis ----------------------------------------------------------------

func redisFake(noAuth bool) net.Listener {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					line, err := br.ReadString('\n')
					if err != nil {
						return
					}
					switch {
					case strings.HasPrefix(line, "PING"):
						if noAuth {
							_, _ = c.Write([]byte("-NOAUTH Authentication required.\r\n"))
						} else {
							_, _ = c.Write([]byte("+PONG\r\n"))
						}
					case strings.HasPrefix(line, "INFO"):
						info := "# Server\r\nredis_version:7.2.4\r\nos:Linux 6.1\r\n"
						_, _ = c.Write([]byte("$" + itoa(len(info)) + "\r\n" + info + "\r\n"))
					case strings.HasPrefix(line, "DBSIZE"):
						_, _ = c.Write([]byte(":42\r\n"))
					}
				}
			}(c)
		}
	}()
	return ln
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func TestRedisOpen(t *testing.T) {
	ln := redisFake(false)
	port := ln.Addr().(*net.TCPAddr).Port
	res := probeRedis(ctxT(t), "127.0.0.1", port, 2*time.Second)
	if res.Status != "open" {
		t.Fatalf("status=%q err=%q", res.Status, res.Err)
	}
	if res.Version != "7.2.4" {
		t.Errorf("version = %q", res.Version)
	}
	found := false
	for _, d := range res.Detail {
		if strings.Contains(d, "dbsize 42") {
			found = true
		}
	}
	if !found {
		t.Errorf("detail = %v", res.Detail)
	}
}

func TestRedisAuth(t *testing.T) {
	ln := redisFake(true)
	port := ln.Addr().(*net.TCPAddr).Port
	res := probeRedis(ctxT(t), "127.0.0.1", port, 2*time.Second)
	if res.Status != "auth" {
		t.Fatalf("status = %q", res.Status)
	}
}
