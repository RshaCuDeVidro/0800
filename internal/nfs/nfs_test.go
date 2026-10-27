package nfs

import (
	"bufio"
	"context"
	"encoding/binary"
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
				w := &xdrWriter{}
				w.u32(xid)
				w.u32(1) // reply
				w.u32(0) // accepted
				w.u32(0) // verifier flavor
				w.u32(0)
				w.u32(0) // success
				w.b = append(w.b, handler(proc)...)
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
		w.u32(1)
		w.str("docs")
		w.u64(1)
		w.u32(1)
		writeFattr(w, typeDir, 4096)
		w.u32(1)
		w.opaque([]byte("FH-DOCS"))
		// readme.txt (file)
		w.u32(1)
		w.u32(2)
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
