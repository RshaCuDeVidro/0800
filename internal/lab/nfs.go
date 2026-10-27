package lab

import (
	"bufio"
	"encoding/binary"
	"io"
	"net"
)

// StartNFS serves MOUNT and NFSv3 with world-readable exports.
func StartNFS(nfsPort, mountPort int) ([]Service, error) {
	nfsLn, err := listen(nfsPort)
	if err != nil {
		return nil, err
	}
	mountLn, err := listen(mountPort)
	if err != nil {
		_ = nfsLn.Close()
		return nil, err
	}
	go lbServeRPC(mountLn, lbMountHandler)
	go lbServeRPC(nfsLn, lbNFSHandler)

	return []Service{
		{Name: "nfs", Port: nfsLn.Addr().(*net.TCPAddr).Port, Listener: nfsLn},
		{Name: "mountd", Port: mountLn.Addr().(*net.TCPAddr).Port, Listener: mountLn},
	}, nil
}

func lbServeRPC(ln net.Listener, handler func(proc uint32) []byte) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			br := bufio.NewReader(c)
			for {
				body, err := lbRecord(br)
				if err != nil {
					return
				}
				r := &lbXDR{b: body}
				xid := r.getU32()
				r.getU32()
				r.getU32()
				r.getU32()
				r.getU32()
				proc := r.getU32()

				w := &lbXDR{}
				w.u32(xid)
				w.u32(1)
				w.u32(0)
				w.u32(0)
				w.u32(0)
				w.u32(0)
				w.b = append(w.b, handler(proc)...)
				hdr := make([]byte, 4)
				binary.BigEndian.PutUint32(hdr, 0x80000000|uint32(len(w.b)))
				_, _ = c.Write(append(hdr, w.b...))
			}
		}(c)
	}
}

func lbRecord(br *bufio.Reader) ([]byte, error) {
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

func lbMountHandler(proc uint32) []byte {
	w := &lbXDR{}
	switch proc {
	case 5: // EXPORT
		for _, p := range []string{"/srv/backup", "/srv/public"} {
			w.u32(1)
			w.str(p)
			w.u32(1)
			w.str("*")
			w.u32(0)
		}
		w.u32(0)
	case 1: // MNT
		w.u32(0)
		w.opaque([]byte("LABHANDLE"))
		w.u32(1)
		w.u32(1)
	}
	return w.b
}

func lbNFSHandler(proc uint32) []byte {
	w := &lbXDR{}
	switch proc {
	case 1: // GETATTR
		w.u32(0)
		lbFattr(w, 1, 4096)
	case 3: // LOOKUP
		w.u32(0)
		w.opaque([]byte("LABFILE"))
		w.u32(1)
		lbFattr(w, 1, 20)
		w.u32(0)
	case 6: // READ
		w.u32(0)
		w.u32(0)
		w.u32(20)
		w.u32(1)
		w.opaque([]byte("0800 lab nfs file\r\n"))
	case 16: // READDIR
		w.u32(0)
		w.u32(0)
		w.fixed(make([]byte, 8))
		w.u32(1)
		w.str("dump.sql")
		w.u64(1)
		w.u32(1)
		w.str("notes.txt")
		w.u64(2)
		w.u32(0)
		w.u32(1)
	case 17: // READDIRPLUS
		w.u32(0)
		w.u32(0)
		w.fixed(make([]byte, 8))
		w.u32(1)
		w.u32(1)
		w.str("dump.sql")
		w.u64(1)
		w.u32(1)
		lbFattr(w, 1, 2048)
		w.u32(1)
		w.opaque([]byte("LABDUMP"))
		w.u32(1)
		w.u32(2)
		w.str("notes.txt")
		w.u64(2)
		w.u32(1)
		lbFattr(w, 1, 20)
		w.u32(1)
		w.opaque([]byte("LABNOTES"))
		w.u32(0)
		w.u32(1)
	}
	return w.b
}

func lbFattr(w *lbXDR, typ uint32, size uint64) {
	w.u32(typ)
	w.u32(0o777)
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

type lbXDR struct {
	b   []byte
	pos int
}

func (x *lbXDR) u32(v uint32) {
	var t [4]byte
	binary.BigEndian.PutUint32(t[:], v)
	x.b = append(x.b, t[:]...)
}

func (x *lbXDR) u64(v uint64) {
	x.u32(uint32(v >> 32))
	x.u32(uint32(v))
}

func (x *lbXDR) fixed(b []byte) {
	x.b = append(x.b, b...)
	for len(x.b)%4 != 0 {
		x.b = append(x.b, 0)
	}
}

func (x *lbXDR) str(s string) {
	x.u32(uint32(len(s)))
	x.fixed([]byte(s))
}

func (x *lbXDR) opaque(b []byte) {
	x.u32(uint32(len(b)))
	x.fixed(b)
}

func (x *lbXDR) getU32() uint32 {
	if x.pos+4 > len(x.b) {
		return 0
	}
	v := binary.BigEndian.Uint32(x.b[x.pos:])
	x.pos += 4
	return v
}

func (x *lbXDR) skip(n int) {
	n = (n + 3) &^ 3
	if x.pos+n <= len(x.b) {
		x.pos += n
	}
}
