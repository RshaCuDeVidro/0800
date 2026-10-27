// Package nfs implements a minimal ONC RPC / NFSv3 client: portmap, MOUNT and
// just enough NFS procedures to list directories and stream files.
package nfs

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Program numbers and versions.
const (
	progPortmap = 100000
	progMount   = 100005
	progNFS     = 100003

	versPortmap = 2
	versMount   = 3
	versNFS     = 3

	protTCP = 6
)

// proc numbers
const (
	mountProcNull   = 0
	mountProcMnt    = 1
	mountProcExport = 5

	nfsProcNull      = 0
	nfsProcGetattr   = 1
	nfsProcLookup    = 3
	nfsProcAccess    = 4
	nfsProcRead      = 6
	nfsProcReaddir   = 16
	nfsProcReaddirPl = 17
)

// Client is a single ONC RPC connection.
type Client struct {
	// mu serialises calls: xid, the deadline and the reply stream are shared,
	// and a download runs concurrently with browsing on one connection.
	mu      sync.Mutex
	conn    net.Conn
	r       *bufio.Reader
	xid     uint32
	timeout time.Duration
	uid     uint32
	gid     uint32
}

// Dial connects to an RPC endpoint.
func Dial(ctx context.Context, addr string, timeout time.Duration, uid uint32) (*Client, error) {
	d := net.Dialer{Timeout: timeout}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Client{conn: nc, r: bufio.NewReaderSize(nc, 64*1024), timeout: timeout, uid: uid, gid: uid}, nil
}

// Close closes the socket.
func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) deadline(ctx context.Context) time.Time {
	d := time.Now().Add(c.timeout)
	if t, ok := ctx.Deadline(); ok && t.Before(d) {
		return t
	}
	return d
}

// authUnix builds AUTH_UNIX credentials.
func authUnix(uid, gid uint32) []byte {
	w := &xdrWriter{}
	w.u32(0) // stamp
	w.str("0800")
	w.u32(uid)
	w.u32(gid)
	w.u32(0) // no supplementary groups
	return w.b
}

// call performs one RPC request and returns the result body.
func (c *Client) call(ctx context.Context, prog, vers, proc uint32, args []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.conn.SetDeadline(c.deadline(ctx)); err != nil {
		return nil, err
	}
	c.xid++
	xid := c.xid

	cred := authUnix(c.uid, c.gid)

	w := &xdrWriter{}
	w.u32(xid)
	w.u32(0) // CALL
	w.u32(2) // RPC version
	w.u32(prog)
	w.u32(vers)
	w.u32(proc)
	w.u32(1) // AUTH_UNIX
	w.u32(uint32(len(cred)))
	w.fixed(cred)
	w.u32(0) // verifier flavor AUTH_NULL
	w.u32(0)
	w.b = append(w.b, args...)

	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, 0x80000000|uint32(len(w.b)))
	if _, err := c.conn.Write(append(hdr, w.b...)); err != nil {
		return nil, err
	}

	body, err := c.readRecord()
	if err != nil {
		return nil, err
	}
	r := &xdrReader{b: body}
	if r.u32() != xid {
		return nil, errors.New("rpc: xid mismatch")
	}
	if r.u32() != 1 {
		return nil, errors.New("rpc: not a reply")
	}
	switch r.u32() {
	case 0: // MSG_ACCEPTED
		r.u32() // verifier flavor
		n := r.u32()
		r.skip(int(n))
		stat := r.u32()
		if stat != 0 {
			return nil, fmt.Errorf("rpc: accepted with status %d", stat)
		}
	case 1: // MSG_DENIED
		return nil, errors.New("rpc: call denied")
	default:
		return nil, errors.New("rpc: invalid reply")
	}
	if r.err != nil {
		return nil, r.err
	}
	return body[r.pos:], nil
}

func (c *Client) readRecord() ([]byte, error) {
	var out []byte
	for i := 0; i < 32; i++ {
		var hdr [4]byte
		if _, err := io.ReadFull(c.r, hdr[:]); err != nil {
			return nil, err
		}
		v := binary.BigEndian.Uint32(hdr[:])
		n := int(v & 0x7FFFFFFF)
		if n < 0 || n > 8<<20 {
			return nil, fmt.Errorf("rpc: bad fragment length %d", n)
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(c.r, buf); err != nil {
			return nil, err
		}
		out = append(out, buf...)
		if v&0x80000000 != 0 {
			return out, nil
		}
	}
	return nil, errors.New("rpc: too many fragments")
}

// Portmap looks up a program's TCP port using rpcbind v2.
func Portmap(ctx context.Context, host string, prog, vers uint32, timeout time.Duration) (uint16, error) {
	c, err := Dial(ctx, net.JoinHostPort(host, "111"), timeout, 0)
	if err != nil {
		return 0, err
	}
	defer c.Close()

	w := &xdrWriter{}
	w.u32(prog)
	w.u32(vers)
	w.u32(protTCP)
	w.u32(0)
	body, err := c.call(ctx, progPortmap, versPortmap, 3, w.b)
	if err != nil {
		return 0, err
	}
	r := &xdrReader{b: body}
	port := r.u32()
	if r.err != nil {
		return 0, r.err
	}
	if port == 0 || port > 65535 {
		return 0, fmt.Errorf("rpc: program %d not registered", prog)
	}
	return uint16(port), nil
}

// MountExport lists exports via MOUNTPROC_EXPORT.
func MountExport(ctx context.Context, host string, port uint16, timeout time.Duration) ([]Export, error) {
	c, err := Dial(ctx, net.JoinHostPort(host, fmt.Sprint(port)), timeout, 0)
	if err != nil {
		return nil, err
	}
	defer c.Close()

	w := &xdrWriter{}
	w.str("")
	body, err := c.call(ctx, progMount, versMount, mountProcExport, w.b)
	if err != nil {
		return nil, err
	}
	r := &xdrReader{b: body}
	var out []Export
	for r.u32() == 1 {
		ex := Export{Path: r.str()}
		for r.u32() == 1 {
			ex.Groups = append(ex.Groups, r.str())
		}
		out = append(out, ex)
		if r.err != nil {
			break
		}
	}
	return out, r.err
}

// Mount requests a file handle for an export path.
func Mount(ctx context.Context, host string, port uint16, timeout time.Duration, path string, uid uint32) ([]byte, []uint32, error) {
	c, err := Dial(ctx, net.JoinHostPort(host, fmt.Sprint(port)), timeout, uid)
	if err != nil {
		return nil, nil, err
	}
	defer c.Close()

	w := &xdrWriter{}
	w.str(path)
	body, err := c.call(ctx, progMount, versMount, mountProcMnt, w.b)
	if err != nil {
		return nil, nil, err
	}
	r := &xdrReader{b: body}
	status := r.u32()
	if status != 0 {
		return nil, nil, fmt.Errorf("mount: status %d", status)
	}
	fh := r.opaque()
	var flavors []uint32
	n := r.u32()
	for i := uint32(0); i < n && i < 16; i++ {
		flavors = append(flavors, r.u32())
	}
	if r.err != nil {
		return nil, nil, r.err
	}
	if len(fh) == 0 || len(fh) > 128 {
		return nil, nil, errors.New("mount: invalid file handle")
	}
	return fh, flavors, nil
}

// --- XDR ------------------------------------------------------------------

type xdrWriter struct{ b []byte }

func (w *xdrWriter) u32(v uint32) {
	var t [4]byte
	binary.BigEndian.PutUint32(t[:], v)
	w.b = append(w.b, t[:]...)
}

func (w *xdrWriter) u64(v uint64) {
	w.u32(uint32(v >> 32))
	w.u32(uint32(v))
}

func (w *xdrWriter) fixed(b []byte) {
	w.b = append(w.b, b...)
	for len(w.b)%4 != 0 {
		w.b = append(w.b, 0)
	}
}

func (w *xdrWriter) str(s string) {
	w.u32(uint32(len(s)))
	w.fixed([]byte(s))
}

func (w *xdrWriter) opaque(b []byte) {
	w.u32(uint32(len(b)))
	w.fixed(b)
}

type xdrReader struct {
	b   []byte
	pos int
	err error
}

func (r *xdrReader) u32() uint32 {
	if r.pos+4 > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		return 0
	}
	v := binary.BigEndian.Uint32(r.b[r.pos:])
	r.pos += 4
	return v
}

func (r *xdrReader) u64() uint64 {
	hi := r.u32()
	lo := r.u32()
	return uint64(hi)<<32 | uint64(lo)
}

// bytes reads n bytes of fixed-length opaque data (e.g. a cookieverf3),
// consuming the XDR padding.
func (r *xdrReader) bytes(n int) []byte {
	if n < 0 || r.pos+((n+3)&^3) > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		r.pos = len(r.b)
		return make([]byte, max(n, 0))
	}
	out := append([]byte(nil), r.b[r.pos:r.pos+n]...)
	r.skip(n)
	return out
}

func (r *xdrReader) skip(n int) {
	if n < 0 {
		r.err = errors.New("xdr: negative skip")
		return
	}
	n = (n + 3) &^ 3
	if r.pos+n > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		r.pos = len(r.b)
		return
	}
	r.pos += n
}

func (r *xdrReader) str() string {
	n := r.u32()
	if n > 1<<20 {
		r.err = errors.New("xdr: implausible string")
		return ""
	}
	if r.pos+int(n) > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		return ""
	}
	s := string(r.b[r.pos : r.pos+int(n)])
	r.skip(int(n))
	return s
}

func (r *xdrReader) opaque() []byte {
	n := r.u32()
	if n > 1<<20 {
		r.err = errors.New("xdr: implausible opaque")
		return nil
	}
	if r.pos+int(n) > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		return nil
	}
	out := append([]byte(nil), r.b[r.pos:r.pos+int(n)]...)
	r.skip(int(n))
	return out
}

// --- attributes -----------------------------------------------------------

// FileAttr is the subset of fattr3 the UI needs.
type FileAttr struct {
	Type  uint32
	Mode  uint32
	Size  uint64
	Mtime time.Time
}

// NFS file types.
const (
	typeReg  = 1
	typeDir  = 2
	typeLnk  = 5
	typeFifo = 7
)

func (r *xdrReader) fattr3() FileAttr {
	var a FileAttr
	a.Type = r.u32()
	a.Mode = r.u32()
	r.u32() // nlink
	r.u32() // uid
	r.u32() // gid
	a.Size = r.u64()
	r.u64() // used
	r.u32() // rdev major
	r.u32() // rdev minor
	r.u64() // fsid
	r.u64() // fileid
	r.u32() // atime.sec
	r.u32() // atime.nsec
	sec, nsec := r.u32(), r.u32()
	a.Mtime = time.Unix(int64(sec), int64(nsec))
	r.u32() // ctime.sec
	r.u32() // ctime.nsec
	return a
}

// postOpAttr decodes a post_op_attr (optional attributes).
func (r *xdrReader) postOpAttr() (FileAttr, bool) {
	if r.u32() == 0 {
		return FileAttr{}, false
	}
	return r.fattr3(), true
}
