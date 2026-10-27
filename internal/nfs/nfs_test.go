package nfs

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

type fakeNFS struct {
	mountLn   net.Listener
	nfsLn     net.Listener
	mountPort uint16
	nfsPort   uint16
}

func startFakeNFS(t *testing.T) *fakeNFS {
	t.Helper()
	mountLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	nfsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mountLn.Close(); _ = nfsLn.Close() })

	f := &fakeNFS{
		mountLn:   mountLn,
		nfsLn:     nfsLn,
		mountPort: uint16(mountLn.Addr().(*net.TCPAddr).Port),
		nfsPort:   uint16(nfsLn.Addr().(*net.TCPAddr).Port),
	}
	go serveRPC(mountLn, mountHandler)
	go serveRPC(nfsLn, nfsHandler)
	return f
}

func serveRPC(ln net.Listener, handler func(proc uint32) []byte) {
	serveRPCArgs(ln, func(proc uint32, _ *xdrReader) []byte { return handler(proc) })
}

// serveRPCArgs is serveRPC for handlers that need the call arguments (e.g. the
// cookie of a paged READDIR).
func serveRPCArgs(ln net.Listener, handler func(proc uint32, args *xdrReader) []byte) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			br := bufio.NewReader(c)
			for {
				body, err := readRecord(br)
				if err != nil {
					return
				}
				r := &xdrReader{b: body}
				xid := r.u32()
				if r.u32() != 0 {
					return
				}
				r.u32() // rpcvers
				r.u32() // prog
				r.u32() // vers
				proc := r.u32()
				r.u32() // cred flavor
				r.skip(int(r.u32()))
				r.u32() // verifier flavor
				r.skip(int(r.u32()))
				w := &xdrWriter{}
				w.u32(xid)
				w.u32(1) // reply
				w.u32(0) // accepted
				w.u32(0) // verifier flavor
				w.u32(0)
				w.u32(0) // success
				w.b = append(w.b, handler(proc, r)...)
				hdr := make([]byte, 4)
				binary.BigEndian.PutUint32(hdr, 0x80000000|uint32(len(w.b)))
				_, _ = c.Write(append(hdr, w.b...))
			}
		}(c)
	}
}

func readRecord(br *bufio.Reader) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(br, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:]) & 0x7FFFFFFF)
	if n > 1<<20 {
		return nil, io.ErrUnexpectedEOF
	}
	buf := make([]byte, n)
	_, err := io.ReadFull(br, buf)
	return buf, err
}

func mountHandler(proc uint32) []byte {
	w := &xdrWriter{}
	switch proc {
	case mountProcExport:
		for _, p := range []string{"/srv/backup", "/srv/media"} {
			w.u32(1)
			w.str(p)
			w.u32(1)
			w.str("*")
			w.u32(0)
		}
		w.u32(0)
	case mountProcMnt:
		w.u32(0) // status
		w.opaque([]byte("HANDLE-1"))
		w.u32(1) // one auth flavor
		w.u32(1) // AUTH_UNIX
	default:
	}
	return w.b
}

func nfsHandler(proc uint32) []byte {
	w := &xdrWriter{}
	switch proc {
	case nfsProcNull:
		return nil
	case nfsProcReaddir:
		w.u32(0)
		w.u32(0) // no dir attrs
		w.fixed(make([]byte, 8))
		w.u32(1)
		w.u64(7) // fileid (fileid3 is a uint64, RFC 1813)
		w.str("docs")
		w.u64(1)
		w.u32(0)
		w.u32(1) // eof
	case nfsProcReaddirPl:
		w.u32(0)
		w.u32(0)
		w.fixed(make([]byte, 8))
		// docs (directory)
		w.u32(1)
		w.u64(1) // fileid
		w.str("docs")
		w.u64(1)
		w.u32(1)
		writeFattr(w, typeDir, 4096)
		w.u32(1)
		w.opaque([]byte("FH-DOCS"))
		// readme.txt (file)
		w.u32(1)
		w.u64(2) // fileid
		w.str("readme.txt")
		w.u64(2)
		w.u32(1)
		writeFattr(w, typeReg, 12)
		w.u32(1)
		w.opaque([]byte("FH-README"))
		w.u32(0)
		w.u32(1)
	case nfsProcLookup:
		w.u32(0)
		w.opaque([]byte("FH-README"))
		w.u32(1)
		writeFattr(w, typeReg, 12)
		w.u32(0)
	case nfsProcGetattr:
		w.u32(0)
		writeFattr(w, typeReg, 12)
	case nfsProcRead:
		w.u32(0)
		w.u32(0)
		w.u32(12)
		w.u32(1)
		w.opaque([]byte("hello world\n"))
	}
	return w.b
}

func writeFattr(w *xdrWriter, typ uint32, size uint64) {
	w.u32(typ)
	w.u32(0o755)
	w.u32(1)
	w.u32(0)
	w.u32(0)
	w.u64(size)
	w.u64(size)
	w.u32(0)
	w.u32(0)
	w.u64(1)
	w.u64(1)
	for i := 0; i < 6; i++ {
		w.u32(0)
	}
}

func TestProbe(t *testing.T) {
	f := startFakeNFS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := Probe(ctx, "127.0.0.1", Config{
		Timeout:   2 * time.Second,
		Port:      f.nfsPort,
		MountPort: f.mountPort,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Exports) != 2 {
		t.Fatalf("exports = %d: %+v", len(res.Exports), res.Exports)
	}
	if !res.Exports[0].Mounted {
		t.Errorf("export not mounted: %+v", res.Exports[0])
	}
	if res.Exports[0].Entries != 1 {
		t.Errorf("entries = %d, want 1", res.Exports[0].Entries)
	}
}

func TestFSBrowse(t *testing.T) {
	f := startFakeNFS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fs, err := MountFS(ctx, "127.0.0.1", Config{
		Timeout:   2 * time.Second,
		Port:      f.nfsPort,
		MountPort: f.mountPort,
	}, "/srv/backup")
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()

	entries, err := fs.List(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries = %d: %+v", len(entries), entries)
	}
	if !entries[0].Dir || entries[0].Name != "docs" {
		t.Errorf("first = %+v", entries[0])
	}
	if entries[1].Size != 12 {
		t.Errorf("readme size = %d", entries[1].Size)
	}

	rc, size, err := fs.Open(ctx, "readme.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if size != 12 {
		t.Errorf("size = %d", size)
	}
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello world\n" {
		t.Errorf("data = %q", data)
	}
}

func TestXDRAlignment(t *testing.T) {
	w := &xdrWriter{}
	w.u32(1)
	w.str("abc")
	w.u64(2)
	w.opaque([]byte("xyz"))

	if len(w.b)%4 != 0 {
		t.Fatalf("buffer not aligned: %d", len(w.b))
	}
	r := &xdrReader{b: w.b}
	if r.u32() != 1 {
		t.Fatal("u32")
	}
	if r.str() != "abc" {
		t.Fatal("str")
	}
	if r.u64() != 2 {
		t.Fatal("u64")
	}
	if string(r.opaque()) != "xyz" {
		t.Fatal("opaque")
	}
	if r.err != nil {
		t.Fatal(r.err)
	}
}

func FuzzXDRReader(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 0, 0, 0, 3, 'a', 'b', 'c', 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		r := &xdrReader{b: data}
		for i := 0; i < 8; i++ {
			r.u32()
			r.str()
			r.opaque()
		}
	})
}

// pagedNFS serves a directory of total entries, perPage at a time, honouring
// the cookie the client sends back (RFC 1813 READDIRPLUS / READDIR paging).
func pagedNFS(total, perPage int, plus bool) func(proc uint32, args *xdrReader) []byte {
	verf := []byte("VERF0001")
	return func(proc uint32, args *xdrReader) []byte {
		w := &xdrWriter{}
		switch proc {
		case nfsProcNull:
			return nil
		case nfsProcReaddir, nfsProcReaddirPl:
			args.opaque() // dir fh
			cookie := args.u64()
			if got := args.bytes(8); cookie != 0 && string(got) != string(verf) {
				w.u32(10003) // NFS3ERR_BAD_COOKIE: client must echo the verifier
				w.u32(0)
				return w.b
			}
			w.u32(0)
			w.u32(0) // no dir attrs
			w.fixed(verf)
			n := 0
			for i := int(cookie); i < total && n < perPage; i++ {
				w.u32(1)
				w.u64(uint64(100 + i)) // fileid
				w.str(fmt.Sprintf("file-%04d", i))
				w.u64(uint64(i + 1)) // cookie: resume after this entry
				if plus {
					w.u32(1)
					writeFattr(w, typeReg, uint64(i))
					w.u32(0) // no file handle
				}
				n++
			}
			w.u32(0) // no more entries in this reply
			if int(cookie)+n >= total {
				w.u32(1) // eof
			} else {
				w.u32(0)
			}
		}
		return w.b
	}
}

// startPagedFS mounts a fake export whose root directory has total entries
// delivered perPage at a time.
func startPagedFS(t *testing.T, total, perPage int, plus bool) *FS {
	t.Helper()
	mountLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	nfsLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mountLn.Close(); _ = nfsLn.Close() })
	go serveRPC(mountLn, mountHandler)
	go serveRPCArgs(nfsLn, pagedNFS(total, perPage, plus))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fs, err := MountFS(ctx, "127.0.0.1", Config{
		Timeout:   2 * time.Second,
		Port:      uint16(nfsLn.Addr().(*net.TCPAddr).Port),
		MountPort: uint16(mountLn.Addr().(*net.TCPAddr).Port),
	}, "/srv/backup")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fs.Close() })
	return fs
}

// TestReaddirPlusFollowsCookies is the README limitation "directories larger
// than a single READDIRPLUS reply are truncated": 10 entries, 3 per reply,
// must come back as 10, in order, with the verifier echoed on every page.
func TestReaddirPlusFollowsCookies(t *testing.T) {
	fs := startPagedFS(t, 10, 3, true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	entries, err := fs.List(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 10 {
		t.Fatalf("entries = %d, want 10 (paging stopped early)", len(entries))
	}
	seen := map[string]bool{}
	for _, e := range entries {
		seen[e.Name] = true
	}
	for i := 0; i < 10; i++ {
		if name := fmt.Sprintf("file-%04d", i); !seen[name] {
			t.Errorf("missing %s", name)
		}
	}
}

// TestReaddirFallbackFollowsCookies covers the same paging on the plain
// READDIR path used when READDIRPLUS is unavailable.
func TestReaddirFallbackFollowsCookies(t *testing.T) {
	fs := startPagedFS(t, 7, 2, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	names, err := fs.readdirNames(ctx, fs.root)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 7 {
		t.Fatalf("names = %d, want 7: %v", len(names), names)
	}
}

// TestReaddirNoFileidMisparse pins the wire format: fileid3 is a uint64
// that precedes the name. A client that reads it as 32 bits (or not at all)
// parses a real server's reply out of alignment.
func TestReaddirNoFileidMisparse(t *testing.T) {
	fs := startPagedFS(t, 2, 10, true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	entries, err := fs.List(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Name != "file-0000" || entries[1].Name != "file-0001" {
		t.Fatalf("entries = %+v", entries)
	}
}
