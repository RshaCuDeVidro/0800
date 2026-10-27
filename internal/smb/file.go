package smb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// Access masks and create options (MS-SMB2 2.2.13 / 2.2.14).
const (
	fileReadData        = 0x00000001
	fileListDirectory   = 0x00000001
	fileReadAttributes  = 0x00000080
	fileWriteAttributes = 0x00000100
	deleteAccess        = 0x00010000
	readControl         = 0x00020000
	synchronize         = 0x00100000
	genericRead         = 0x80000000

	fileDirectoryFile         = 0x00000001
	fileNonDirectoryFile      = 0x00000040
	fileSynchronousIoNonAlert = 0x00000020

	fileOpen = 1
)

// Entry is one directory listing element.
type Entry struct {
	Name    string
	Size    int64
	Dir     bool
	Mode    uint32
	ModTime time.Time
}

func (c *conn) create(ctx context.Context, treeID uint32, name string, access, attrs, share, disposition, options uint32) (fileID [16]byte, size int64, isDir bool, err error) {
	nameB := utf16le(name)
	const fixed = 56
	b := make([]byte, fixed+len(nameB))
	putU16(b, 0, 57)
	b[2] = 0        // security flags
	b[3] = 0        // oplock
	putU32(b, 4, 2) // impersonation
	putU32(b, 24, access)
	putU32(b, 28, attrs)
	putU32(b, 32, share)
	putU32(b, 36, disposition)
	putU32(b, 40, options)
	putU16(b, 44, uint16(smb2HeaderSize+fixed))
	putU16(b, 46, uint16(len(nameB)))
	copy(b[fixed:], nameB)

	h, resp, err := c.call(ctx, cmdCreate, treeID, c.sessionID, b)
	if err != nil {
		return fileID, 0, false, err
	}
	if !h.Status.OK() {
		return fileID, 0, false, h.Status
	}
	if len(resp) < 80 {
		return fileID, 0, false, fmt.Errorf("smb: short create response")
	}
	copy(fileID[:], resp[64:80])
	size = int64(u64(resp, 48))
	isDir = u32(resp, 56)&0x10 != 0
	return fileID, size, isDir, nil
}

func (c *conn) closeFile(ctx context.Context, treeID uint32, id [16]byte) {
	b := make([]byte, 24)
	putU16(b, 0, 24)
	copy(b[8:24], id[:])
	_, _, _ = c.call(ctx, cmdClose, treeID, c.sessionID, b)
}

// queryDirectory lists a directory handle. It transparently pages through
// results until the server reports STATUS_NO_MORE_FILES.
func (c *conn) queryDirectory(ctx context.Context, treeID uint32, id [16]byte) ([]Entry, error) {
	var out []Entry
	pattern := "*"
	restart := true

	for page := 0; page < 512; page++ {
		pat := utf16le(pattern)
		const fixed = 32
		b := make([]byte, fixed+len(pat))
		putU16(b, 0, 33)
		b[2] = 0x25 // FileIdBothDirectoryInformation
		flags := byte(0)
		if restart {
			flags |= 0x01
		}
		b[3] = flags
		copy(b[8:24], id[:])
		putU16(b, 24, uint16(smb2HeaderSize+fixed))
		putU16(b, 26, uint16(len(pat)))
		putU32(b, 28, 1<<20)
		copy(b[fixed:], pat)

		h, resp, err := c.call(ctx, cmdQueryDirectory, treeID, c.sessionID, b)
		if err != nil {
			return out, err
		}
		if h.Status == StatusNoMoreFiles {
			return out, nil
		}
		if !h.Status.OK() {
			return out, h.Status
		}
		entries, err := parseDirEntries(resp)
		if err != nil {
			return out, err
		}
		out = append(out, entries...)
		if len(entries) == 0 {
			return out, nil
		}
		pattern, restart = "", false
	}
	return out, nil
}

// parseDirEntries decodes a FileIdBothDirectoryInformation buffer.
func parseDirEntries(resp []byte) ([]Entry, error) {
	if len(resp) < 8 {
		return nil, fmt.Errorf("smb: short query directory response")
	}
	off := int(u16(resp, 2)) - smb2HeaderSize
	n := int(u32(resp, 4))
	if off < 0 || n < 0 || off+n > len(resp) {
		return nil, fmt.Errorf("smb: bad query directory buffer")
	}
	buf := resp[off : off+n]

	var out []Entry
	for pos := 0; pos+104 <= len(buf); {
		next := int(u32(buf, pos))
		nameLen := int(u32(buf, pos+60))
		if nameLen < 0 || pos+104+nameLen > len(buf) {
			return out, fmt.Errorf("smb: truncated directory entry")
		}
		name := fromUTF16LE(buf[pos+104 : pos+104+nameLen])
		attrs := u32(buf, pos+56)
		size := int64(u64(buf, pos+40))
		mtime := filetime(u64(buf, pos+24))

		if name != "." && name != ".." && name != "" {
			out = append(out, Entry{
				Name:    name,
				Size:    size,
				Dir:     attrs&0x10 != 0,
				Mode:    attrs,
				ModTime: mtime,
			})
		}
		if next <= 0 {
			break
		}
		pos += next
	}
	return out, nil
}

func filetime(v uint64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	// FILETIME counts 100ns ticks since 1601-01-01.
	sec := int64(v/10_000_000) - 11644473600
	nsec := int64(v%10_000_000) * 100
	return time.Unix(sec, nsec)
}

const readChunk = 1 << 20

type fileReader struct {
	c      *conn
	treeID uint32
	id     [16]byte
	ctx    context.Context
	off    uint64
	size   int64
	buf    []byte
	done   bool
}

// Read implements io.Reader.
func (r *fileReader) Read(p []byte) (int, error) {
	if r.done {
		return 0, io.EOF
	}
	if len(r.buf) == 0 {
		want := uint32(readChunk)
		if r.size > 0 {
			remaining := r.size - int64(r.off)
			if remaining <= 0 {
				r.done = true
				return 0, io.EOF
			}
			if remaining < int64(want) {
				want = uint32(remaining)
			}
		}
		if max := r.c.maxRead; want > max {
			want = max
		}
		data, err := r.c.readAt(r.ctx, r.treeID, r.id, r.off, want)
		if err != nil {
			if errors.Is(err, io.EOF) {
				r.done = true
				return 0, io.EOF
			}
			return 0, err
		}
		if len(data) == 0 {
			r.done = true
			return 0, io.EOF
		}
		r.buf = data
		r.off += uint64(len(data))
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// Close releases the remote handle.
func (r *fileReader) Close() error {
	r.c.closeFile(context.Background(), r.treeID, r.id)
	return nil
}

func (c *conn) readAt(ctx context.Context, treeID uint32, id [16]byte, offset uint64, length uint32) ([]byte, error) {
	const fixed = 48
	b := make([]byte, fixed+1)
	putU16(b, 0, 49)
	putU32(b, 4, length)
	putU64(b, 8, offset)
	copy(b[16:32], id[:])
	putU32(b, 32, 0)

	h, resp, err := c.call(ctx, cmdRead, treeID, c.sessionID, b)
	if err != nil {
		return nil, err
	}
	if h.Status == StatusEndOfFile {
		return nil, io.EOF
	}
	if !h.Status.OK() {
		return nil, h.Status
	}
	if len(resp) < 16 {
		return nil, fmt.Errorf("smb: short read response")
	}
	dataOff := int(resp[2]) - smb2HeaderSize
	dataLen := int(u32(resp, 4))
	if dataOff < 0 || dataLen < 0 || dataOff+dataLen > len(resp) {
		return nil, fmt.Errorf("smb: bad read buffer")
	}
	return resp[dataOff : dataOff+dataLen], nil
}

// writeAt sends data on a named pipe handle.
func (c *conn) writeAt(ctx context.Context, treeID uint32, id [16]byte, data []byte) error {
	const fixed = 48
	b := make([]byte, fixed+len(data))
	putU16(b, 0, 49)
	putU16(b, 2, uint16(smb2HeaderSize+fixed))
	putU32(b, 4, uint32(len(data)))
	putU64(b, 8, 0)
	copy(b[16:32], id[:])
	copy(b[fixed:], data)

	h, _, err := c.call(ctx, cmdWrite, treeID, c.sessionID, b)
	if err != nil {
		return err
	}
	if !h.Status.OK() {
		return h.Status
	}
	return nil
}

// normaliseSharePath converts a user supplied path into the SMB wire format.
func normaliseSharePath(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	p = strings.TrimPrefix(p, `\`)
	if p == "" {
		return ""
	}
	return p
}
