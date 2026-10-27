package lab

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
	"strings"
)

// StartMySQL serves a handshake that accepts any empty-password login.
func StartMySQL(port int) (Service, error) {
	ln, err := listen(port)
	if err != nil {
		return Service{}, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				_ = lbMySQLPacket(c, 0, labGreeting())
				for {
					if _, err := lbReadMySQL(br); err != nil {
						return
					}
					_ = lbMySQLPacket(c, 2, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00})
				}
			}(c)
		}
	}()
	return Service{Name: "mysql", Port: ln.Addr().(*net.TCPAddr).Port, Listener: ln}, nil
}

func labGreeting() []byte {
	var b []byte
	b = append(b, 10)
	b = append(b, []byte("8.0.35-lab")...)
	b = append(b, 0)
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], 42)
	b = append(b, tmp[:]...)
	b = append(b, []byte("12345678")...)
	b = append(b, 0)
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

func lbReadMySQL(r *bufio.Reader) ([]byte, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	var seq [1]byte
	_, _ = io.ReadFull(r, seq[:])
	return buf, nil
}

func lbMySQLPacket(w io.Writer, seq byte, p []byte) error {
	if _, err := w.Write([]byte{byte(len(p)), byte(len(p) >> 8), byte(len(p) >> 16), seq}); err != nil {
		return err
	}
	_, err := w.Write(p)
	return err
}

// StartPostgres serves "trust" authentication.
func StartPostgres(port int) (Service, error) {
	ln, err := listen(port)
	if err != nil {
		return Service{}, err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				var l [4]byte
				if _, err := io.ReadFull(br, l[:]); err != nil {
					return
				}
				n := int(binary.BigEndian.Uint32(l[:])) - 4
				if n < 0 || n > 1<<20 {
					return
				}
				if _, err := io.ReadFull(br, make([]byte, n)); err != nil {
					return
				}
				lbPG(c, 'R', []byte{0, 0, 0, 0})
				lbPG(c, 'S', append([]byte("server_version\x00"), []byte("18.6-lab\x00")...))
				lbPG(c, 'Z', []byte{'I'})
			}(c)
		}
	}()
	return Service{Name: "postgres", Port: ln.Addr().(*net.TCPAddr).Port, Listener: ln}, nil
}

func lbPG(w io.Writer, t byte, payload []byte) {
	buf := make([]byte, 5+len(payload))
	buf[0] = t
	binary.BigEndian.PutUint32(buf[1:], uint32(len(payload)+4))
	copy(buf[5:], payload)
	_, _ = w.Write(buf)
}

// StartRedis serves an instance without a password.
func StartRedis(port int) (Service, error) {
	ln, err := listen(port)
	if err != nil {
		return Service{}, err
	}
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
						_, _ = c.Write([]byte("+PONG\r\n"))
					case strings.HasPrefix(line, "INFO"):
						info := "# Server\r\nredis_version:7.2.4-lab\r\nos:Linux lab\r\n"
						_, _ = c.Write([]byte("$" + itoa(len(info)) + "\r\n" + info + "\r\n"))
					case strings.HasPrefix(line, "DBSIZE"):
						_, _ = c.Write([]byte(":1337\r\n"))
					}
				}
			}(c)
		}
	}()
	return Service{Name: "redis", Port: ln.Addr().(*net.TCPAddr).Port, Listener: ln}, nil
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
