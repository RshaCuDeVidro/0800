package ftp

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"testing"
	"time"
)

// fakeFTP starts a minimal scripted FTP server and returns its address.
// script maps an uppercased command verb ("USER", "PASS") to the exact
// reply line to send back.
func fakeFTP(t *testing.T, banner string, script map[string]string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte(banner + "\r\n"))
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			verb := ""
			for i, c := range line {
				if c == ' ' || c == '\r' || c == '\n' {
					verb = line[:i]
					break
				}
			}
			if verb == "" {
				verb = line
			}
			switch verb {
			case "QUIT":
				_, _ = conn.Write([]byte("221 bye\r\n"))
				return
			default:
				if reply, ok := script[verb]; ok {
					_, _ = conn.Write([]byte(reply + "\r\n"))
				} else {
					_, _ = conn.Write([]byte("500 unknown\r\n"))
				}
			}
		}
	}()
	return ln.Addr().String()
}

func mustSplitHostPort(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return host, port
}

func TestProbeAnonymousAccepted(t *testing.T) {
	addr := fakeFTP(t, "220 Welcome", map[string]string{
		"USER": "331 password required",
		"PASS": "230 Logged in anonymously",
	})
	host, port := mustSplitHostPort(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := Probe(ctx, host, port, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !res.AnonOK {
		t.Errorf("AnonOK = false, want true: %+v", res)
	}
	if res.Code != 230 {
		t.Errorf("Code = %d, want 230", res.Code)
	}
}

func TestProbeAnonymousRejected(t *testing.T) {
	addr := fakeFTP(t, "220 Welcome", map[string]string{
		"USER": "331 password required",
		"PASS": "530 login incorrect",
	})
	host, port := mustSplitHostPort(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := Probe(ctx, host, port, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if res.AnonOK {
		t.Errorf("AnonOK = true, want false: %+v", res)
	}
	if res.Code != 530 {
		t.Errorf("Code = %d, want 530", res.Code)
	}
}

func TestProbeAnonymousAcceptedAtUserStage(t *testing.T) {
	// Some servers accept anonymous without ever asking for a password.
	addr := fakeFTP(t, "220 Welcome", map[string]string{
		"USER": "230 Logged in anonymously",
	})
	host, port := mustSplitHostPort(t, addr)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := Probe(ctx, host, port, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !res.AnonOK {
		t.Errorf("AnonOK = false, want true: %+v", res)
	}
}

func TestProbeMultilineBanner(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("220-Multi\r\n220-line\r\n220 ready\r\n"))
		r := bufio.NewReader(conn)
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			switch {
			case len(line) >= 4 && line[:4] == "USER":
				_, _ = conn.Write([]byte("530 anonymous disabled\r\n"))
			default:
				_, _ = conn.Write([]byte("221 bye\r\n"))
				return
			}
		}
	}()
	host, port := mustSplitHostPort(t, ln.Addr().String())

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	res, err := Probe(ctx, host, port, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if res.AnonOK {
		t.Errorf("AnonOK = true, want false: %+v", res)
	}
	if res.Banner != "ready" {
		t.Errorf("Banner = %q, want %q (multi-line banner collapsed to final line)", res.Banner, "ready")
	}
}

func TestProbeDialFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := Probe(ctx, "127.0.0.1", 1, 300*time.Millisecond); err == nil {
		t.Error("expected an error dialing a closed port")
	}
}
