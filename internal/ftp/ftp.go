// Package ftp implements a minimal, read-only FTP anonymous-login check.
//
// It never opens a data channel: no LIST, no RETR, no STOR. It connects,
// reads the banner, tries USER anonymous / PASS anonymous@0800.scan, reads
// the result and quits. That is enough to tell whether the server grants an
// unauthenticated session, which is the only thing 0800 cares about.
package ftp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Result is what the prober learned about one FTP control connection.
type Result struct {
	Banner  string // the 220 greeting, trimmed
	AnonOK  bool   // true if anonymous/anonymous@0800.scan was accepted
	Code    int    // final reply code (230 on success)
	Message string // final reply text
}

// Probe attempts an anonymous FTP login against ip:port.
func Probe(ctx context.Context, ip string, port int, timeout time.Duration) (*Result, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout))
	}

	r := bufio.NewReader(conn)
	res := &Result{}

	code, msg, err := readReply(r)
	if err != nil {
		return nil, fmt.Errorf("ftp: reading banner: %w", err)
	}
	res.Banner = msg
	if code/100 != 2 {
		return res, fmt.Errorf("ftp: server refused the connection (%d %s)", code, msg)
	}

	if err := send(conn, "USER anonymous\r\n"); err != nil {
		return nil, err
	}
	code, msg, err = readReply(r)
	if err != nil {
		return nil, fmt.Errorf("ftp: reading USER reply: %w", err)
	}

	switch code {
	case 230:
		res.AnonOK = true
		res.Code, res.Message = code, msg
	case 331, 332:
		if err := send(conn, "PASS anonymous@0800.scan\r\n"); err != nil {
			return nil, err
		}
		code, msg, err = readReply(r)
		if err != nil {
			return nil, fmt.Errorf("ftp: reading PASS reply: %w", err)
		}
		res.Code, res.Message = code, msg
		res.AnonOK = code == 230
	default:
		res.Code, res.Message = code, msg
	}

	_ = send(conn, "QUIT\r\n")
	return res, nil
}

func send(conn net.Conn, line string) error {
	_, err := conn.Write([]byte(line))
	return err
}

// readReply reads one FTP control reply (RFC 959 4.2), including the
// continuation lines of a multi-line reply such as "220-Welcome\r\n...\r\n220 ready\r\n".
func readReply(r *bufio.Reader) (int, string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return 0, "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) < 3 {
		return 0, "", fmt.Errorf("short reply %q", line)
	}
	code, err := strconv.Atoi(line[:3])
	if err != nil {
		return 0, "", fmt.Errorf("bad reply code %q", line)
	}
	msg := line
	if len(line) > 3 && line[3] == '-' {
		final := line[:3] + " "
		for i := 0; i < 256; i++ { // bounded: the socket deadline is the real limit
			cont, err := r.ReadString('\n')
			if err != nil {
				return 0, "", err
			}
			cont = strings.TrimRight(cont, "\r\n")
			if strings.HasPrefix(cont, final) {
				msg = cont
				break
			}
		}
	}
	return code, strings.TrimSpace(msg[min(4, len(msg)):]), nil
}
