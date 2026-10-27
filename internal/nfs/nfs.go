package nfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"
)

// Config controls the NFS prober.
type Config struct {
	Timeout time.Duration
	// MaxExports caps how many exports are mounted during a probe.
	MaxExports int
	// Port overrides the NFS port (default 2049).
	Port uint16
	// MountPort skips portmap discovery when set.
	MountPort uint16
}

// Export is one NFS export.
type Export struct {
	Path    string
	Groups  []string
	Handle  []byte
	Mounted bool
	UID     uint32
	Entries int
	Err     string
}

// Result is the NFS fingerprint of a host.
type Result struct {
	Port      uint16
	MountPort uint16
	Exports   []Export
	Version   string
	Note      string
}

// Probe enumerates exports and proves access by mounting them with AUTH_UNIX.
func Probe(ctx context.Context, host string, cfg Config) (*Result, error) {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 4 * time.Second
	}
	if cfg.MaxExports <= 0 {
		cfg.MaxExports = 6
	}
	port := cfg.Port
	if port == 0 {
		port = 2049
	}
	res := &Result{Port: port, Version: "3"}

	// Confirm the port really speaks NFS before trusting the export list.
	if err := nfsNull(ctx, host, port, cfg.Timeout); err != nil {
		if err4 := nfsNull4(ctx, host, port, cfg.Timeout); err4 != nil {
			return nil, fmt.Errorf("nfs: port %d did not answer: %w", port, err)
		}
		res.Version = "4"
	}

	mountPort := cfg.MountPort
	if mountPort == 0 {
		p, err := Portmap(ctx, host, progMount, versMount, cfg.Timeout)
		if err != nil || p == 0 {
			p = 20048 // the de-facto fixed port
		}
		mountPort = p
	}
	res.MountPort = mountPort

	exports, err := MountExport(ctx, host, mountPort, cfg.Timeout)
	if err != nil {
		res.Note = "export list unavailable: " + err.Error()
	}
	if len(exports) == 0 && res.Note == "" {
		res.Note = "no exports advertised"
	}

	for i := range exports {
		if i >= cfg.MaxExports {
			res.Note = fmt.Sprintf("listing first %d exports", cfg.MaxExports)
			break
		}
		ex := &exports[i]
		fh, _, err := Mount(ctx, host, mountPort, cfg.Timeout, ex.Path, 0)
		if err != nil {
			// root_squash: retry as nobody before calling it closed.
			fh, _, err = Mount(ctx, host, mountPort, cfg.Timeout, ex.Path, 65534)
			if err != nil {
				ex.Err = err.Error()
				continue
			}
			ex.UID = 65534
		}
		ex.Handle = fh
		ex.Mounted = true
		ex.Entries = countEntries(ctx, host, port, ex.Handle, cfg.Timeout)
	}
	res.Exports = exports
	return res, nil
}

func nfsNull(ctx context.Context, host string, port uint16, timeout time.Duration) error {
	c, err := Dial(ctx, net.JoinHostPort(host, fmt.Sprint(port)), timeout, 0)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.call(ctx, progNFS, versNFS, nfsProcNull, nil)
	return err
}

func nfsNull4(ctx context.Context, host string, port uint16, timeout time.Duration) error {
	c, err := Dial(ctx, net.JoinHostPort(host, fmt.Sprint(port)), timeout, 0)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.call(ctx, progNFS, 4, 0, nil)
	return err
}

// countEntries performs one bounded READDIR to prove the export is readable.
func countEntries(ctx context.Context, host string, port uint16, fh []byte, timeout time.Duration) int {
	c, err := Dial(ctx, net.JoinHostPort(host, fmt.Sprint(port)), timeout, 0)
	if err != nil {
		return 0
	}
	defer c.Close()

	w := &xdrWriter{}
	w.opaque(fh)
	w.u64(0)
	w.fixed(make([]byte, 8))
	w.u32(4096)
	body, err := c.call(ctx, progNFS, versNFS, nfsProcReaddir, w.b)
	if err != nil {
		return 0
	}
	r := &xdrReader{b: body}
	if r.u32() != 0 {
		return 0
	}
	r.postOpAttr()
	r.skip(8) // cookieverf
	n := 0
	for r.u32() == 1 {
		r.u64() // fileid (fileid3 is a uint64, RFC 1813 3.3.16)
		name := r.str()
		r.u64() // cookie
		if name != "." && name != ".." {
			n++
		}
		if n > 500 {
			break
		}
	}
	if r.err != nil {
		return 0
	}
	return n
}

// FS is a browseable NFSv3 filesystem rooted at one export.
type FS struct {
	c      *Client
	port   uint16
	export string
	root   []byte
	uid    uint32
	cache  map[string][]byte
	attrs  map[string]FileAttr
}

// NewFS connects to the NFS service for browsing.
func NewFS(ctx context.Context, host string, port uint16, export string, fh []byte, uid uint32, timeout time.Duration) (*FS, error) {
	if port == 0 {
		port = 2049
	}
	if timeout <= 0 {
		timeout = 6 * time.Second
	}
	c, err := Dial(ctx, net.JoinHostPort(host, fmt.Sprint(port)), timeout, uid)
	if err != nil {
		return nil, err
	}
	return &FS{
		c:      c,
		port:   port,
		export: export,
		root:   fh,
		uid:    uid,
		cache:  map[string][]byte{"": fh},
		attrs:  map[string]FileAttr{},
	}, nil
}

// Close closes the underlying RPC connection.
func (f *FS) Close() error { return f.c.Close() }

// Export returns the mount path this filesystem is rooted at.
func (f *FS) Export() string { return f.export }

// Entry is one directory element.
type Entry struct {
	Name    string
	Dir     bool
	Size    int64
	ModTime time.Time
}

// List returns the contents of a directory (paths are relative to the export).
func (f *FS) List(ctx context.Context, dir string) ([]Entry, error) {
	dir = cleanPath(dir)
	fh, err := f.resolve(ctx, dir)
	if err != nil {
		return nil, err
	}
	entries, err := f.readdirPlus(ctx, fh)
	if err != nil {
		entries, err = f.readdir(ctx, dir, fh)
		if err != nil {
			return nil, err
		}
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Dir != entries[j].Dir {
			return entries[i].Dir
		}
		return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
	})
	return entries, nil
}

func (f *FS) resolve(ctx context.Context, path string) ([]byte, error) {
	path = cleanPath(path)
	if fh, ok := f.cache[path]; ok {
		return fh, nil
	}
	parent, name := splitPath(path)
	pfh, err := f.resolve(ctx, parent)
	if err != nil {
		return nil, err
	}

	w := &xdrWriter{}
	w.opaque(pfh)
	w.str(name)

	body, err := f.c.call(ctx, progNFS, versNFS, nfsProcLookup, w.b)
	if err != nil {
		return nil, err
	}
	r := &xdrReader{b: body}
	if st := r.u32(); st != 0 {
		return nil, fmt.Errorf("nfs: lookup %q: status %d", name, st)
	}
	fh := r.opaque()
	if a, ok := r.postOpAttr(); ok {
		f.attrs[path] = a
	}
	if r.err != nil {
		return nil, r.err
	}
	if len(fh) == 0 {
		return nil, errors.New("nfs: empty file handle")
	}
	f.cache[path] = fh
	return fh, nil
}

// Directory paging limits. A hostile or enormous directory must not be able
// to exhaust memory, and a server that ignores cookies must not loop us.
const (
	maxDirPages   = 4096
	maxDirEntries = 100000
	// readdirNameCap bounds the plain-READDIR fallback, which needs two extra
	// round trips (LOOKUP + GETATTR) per name.
	readdirNameCap = 1000
)

// readdirPlus lists a directory with READDIRPLUS, following the cookie and
// cookieverf across as many replies as the server needs (RFC 1813 3.3.17).
// If a later page fails, the entries gathered so far are returned: a partial
// listing is more useful to a human than none.
func (f *FS) readdirPlus(ctx context.Context, fh []byte) ([]Entry, error) {
	var (
		out    []Entry
		cookie uint64
		verf   = make([]byte, 8)
	)
	for page := 0; page < maxDirPages; page++ {
		w := &xdrWriter{}
		w.opaque(fh)
		w.u64(cookie)
		w.fixed(verf)
		w.u32(8192)  // dircount
		w.u32(65536) // maxcount

		body, err := f.c.call(ctx, progNFS, versNFS, nfsProcReaddirPl, w.b)
		if err != nil {
			if page > 0 {
				return out, nil
			}
			return nil, err
		}
		r := &xdrReader{b: body}
		if st := r.u32(); st != 0 {
			if page > 0 {
				return out, nil
			}
			return nil, fmt.Errorf("nfs: readdirplus: status %d", st)
		}
		r.postOpAttr()
		verf = r.bytes(8)

		last, got := cookie, 0
		for r.u32() == 1 {
			r.u64() // fileid (fileid3 is a uint64)
			name := r.str()
			ck := r.u64()
			a, ok := r.postOpAttr()
			if r.u32() == 1 { // post_op_fh3
				r.opaque()
			}
			if r.err != nil {
				if page > 0 || len(out) > 0 {
					return out, nil
				}
				return out, r.err
			}
			last = ck
			got++
			if name == "." || name == ".." || name == "" {
				continue
			}
			e := Entry{Name: name}
			if ok {
				e.Dir = a.Type == typeDir
				e.Size = int64(a.Size)
				e.ModTime = a.Mtime
			}
			out = append(out, e)
			if len(out) >= maxDirEntries {
				return out, nil
			}
		}
		eof := r.u32() == 1
		if r.err != nil && len(out) == 0 {
			return out, r.err
		}
		if eof || got == 0 || last == cookie {
			break
		}
		cookie = last
	}
	return out, nil
}

// readdir is the fallback for servers that do not implement READDIRPLUS. It
// pages with READDIR and then resolves each name with LOOKUP + GETATTR.
func (f *FS) readdir(ctx context.Context, dir string, fh []byte) ([]Entry, error) {
	names, err := f.readdirNames(ctx, fh)
	if err != nil {
		return nil, err
	}
	out := make([]Entry, 0, len(names))
	for _, n := range names {
		sub := n
		if dir != "" {
			sub = dir + "/" + n
		}
		fh, err := f.resolve(ctx, sub)
		if err != nil {
			out = append(out, Entry{Name: n})
			continue
		}
		a, err := f.getattr(ctx, fh)
		if err != nil {
			out = append(out, Entry{Name: n})
			continue
		}
		out = append(out, Entry{Name: n, Dir: a.Type == typeDir, Size: int64(a.Size), ModTime: a.Mtime})
	}
	return out, nil
}

// readdirNames lists the bare names in a directory with READDIR, following
// the cookie and cookieverf across replies (RFC 1813 3.3.16).
func (f *FS) readdirNames(ctx context.Context, fh []byte) ([]string, error) {
	var (
		names  []string
		cookie uint64
		verf   = make([]byte, 8)
	)
	for page := 0; page < maxDirPages && len(names) < readdirNameCap; page++ {
		w := &xdrWriter{}
		w.opaque(fh)
		w.u64(cookie)
		w.fixed(verf)
		w.u32(32768)

		body, err := f.c.call(ctx, progNFS, versNFS, nfsProcReaddir, w.b)
		if err != nil {
			if page > 0 {
				break
			}
			return nil, err
		}
		r := &xdrReader{b: body}
		if st := r.u32(); st != 0 {
			if page > 0 {
				break
			}
			return nil, fmt.Errorf("nfs: readdir: status %d", st)
		}
		r.postOpAttr()
		verf = r.bytes(8)

		last, got := cookie, 0
		for r.u32() == 1 {
			r.u64() // fileid (fileid3 is a uint64)
			name := r.str()
			ck := r.u64()
			if r.err != nil {
				break
			}
			last = ck
			got++
			if name != "." && name != ".." && name != "" {
				names = append(names, name)
			}
			if len(names) >= readdirNameCap {
				break
			}
		}
		eof := r.u32() == 1
		if r.err != nil && len(names) == 0 {
			return nil, r.err
		}
		if eof || got == 0 || last == cookie {
			break
		}
		cookie = last
	}
	return names, nil
}

func (f *FS) getattr(ctx context.Context, fh []byte) (FileAttr, error) {
	w := &xdrWriter{}
	w.opaque(fh)
	body, err := f.c.call(ctx, progNFS, versNFS, nfsProcGetattr, w.b)
	if err != nil {
		return FileAttr{}, err
	}
	r := &xdrReader{b: body}
	if st := r.u32(); st != 0 {
		return FileAttr{}, fmt.Errorf("nfs: getattr: status %d", st)
	}
	a := r.fattr3()
	return a, r.err
}

// Open starts streaming a file relative to the export root.
func (f *FS) Open(ctx context.Context, path string) (io.ReadCloser, int64, error) {
	path = cleanPath(path)
	fh, err := f.resolve(ctx, path)
	if err != nil {
		return nil, 0, err
	}
	a, ok := f.attrs[path]
	if !ok {
		if a, err = f.getattr(ctx, fh); err != nil {
			return nil, 0, err
		}
	}
	if a.Type == typeDir {
		return nil, 0, errors.New("nfs: is a directory")
	}
	ctx = context.WithoutCancel(ctx)
	return &fileReader{fs: f, ctx: ctx, fh: fh, size: int64(a.Size)}, int64(a.Size), nil
}

// Peek reads at most n bytes from the start of a file in one READ and returns
// the file size, so a preview costs a single round trip.
func (f *FS) Peek(ctx context.Context, path string, n int) ([]byte, int64, error) {
	path = cleanPath(path)
	fh, err := f.resolve(ctx, path)
	if err != nil {
		return nil, 0, err
	}
	a, ok := f.attrs[path]
	if !ok {
		if a, err = f.getattr(ctx, fh); err != nil {
			return nil, 0, err
		}
	}
	if a.Type == typeDir {
		return nil, 0, errors.New("nfs: is a directory")
	}
	if n <= 0 || a.Size == 0 {
		return nil, int64(a.Size), nil
	}
	data, _, err := f.readAt(ctx, fh, 0, uint32(n))
	return data, int64(a.Size), err
}

type fileReader struct {
	fs   *FS
	ctx  context.Context
	fh   []byte
	off  uint64
	size int64
	buf  []byte
	eof  bool
}

func (r *fileReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		if r.eof {
			return 0, io.EOF
		}
		chunk, eof, err := r.fs.readAt(r.ctx, r.fh, r.off, 1<<20)
		if err != nil {
			return 0, err
		}
		if len(chunk) == 0 {
			return 0, io.EOF
		}
		r.off += uint64(len(chunk))
		r.buf = chunk
		r.eof = eof
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

func (r *fileReader) Close() error { return nil }

func (f *FS) readAt(ctx context.Context, fh []byte, off uint64, count uint32) ([]byte, bool, error) {
	w := &xdrWriter{}
	w.opaque(fh)
	w.u64(off)
	w.u32(count)

	body, err := f.c.call(ctx, progNFS, versNFS, nfsProcRead, w.b)
	if err != nil {
		return nil, false, err
	}
	rd := &xdrReader{b: body}
	if st := rd.u32(); st != 0 {
		return nil, false, fmt.Errorf("nfs: read: status %d", st)
	}
	rd.postOpAttr()
	n := rd.u32()
	eof := rd.u32() == 1
	data := rd.opaque()
	if rd.err != nil {
		return nil, false, rd.err
	}
	if int(n) < len(data) {
		data = data[:n]
	}
	return data, eof, nil
}

// MountFS mounts an export and returns a browseable filesystem, retrying as
// nobody when root is squashed.
func MountFS(ctx context.Context, host string, cfg Config, export string) (*FS, error) {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 6 * time.Second
	}
	mountPort := cfg.MountPort
	if mountPort == 0 {
		if p, err := Portmap(ctx, host, progMount, versMount, timeout); err == nil {
			mountPort = p
		} else {
			mountPort = 20048
		}
	}
	port := cfg.Port
	if port == 0 {
		port = 2049
	}
	fh, _, err := Mount(ctx, host, mountPort, timeout, export, 0)
	uid := uint32(0)
	if err != nil {
		fh, _, err = Mount(ctx, host, mountPort, timeout, export, 65534)
		uid = 65534
	}
	if err != nil {
		return nil, err
	}
	return NewFS(ctx, host, port, export, fh, uid, timeout)
}

func cleanPath(p string) string {
	p = strings.TrimSpace(strings.ReplaceAll(p, "\\", "/"))
	p = strings.Trim(p, "/")
	if p == "." {
		return ""
	}
	return p
}

func splitPath(p string) (string, string) {
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return "", p
	}
	return p[:i], p[i+1:]
}
