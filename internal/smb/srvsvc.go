package smb

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Minimal DCE/RPC 1.1 client over an SMB2 named pipe, just enough for
// srvsvc!NetrShareEnum. Kept in-tree so the binary has no RPC dependency.

const (
	rpcRequest  = 0
	rpcResponse = 2
	rpcFault    = 3
	rpcBind     = 11
	rpcBindAck  = 12

	pipeAccess = 0x0012019F
)

var (
	uuidSRVSVC = [16]byte{0xC8, 0x4F, 0x32, 0x4B, 0x70, 0x16, 0xD3, 0x01, 0x12, 0x78, 0x5A, 0x47, 0xBF, 0x6E, 0xE1, 0x88}
	uuidNDR32  = [16]byte{0x04, 0x5D, 0x88, 0x8A, 0xEB, 0x1C, 0xC9, 0x11, 0x9F, 0xE8, 0x08, 0x00, 0x2B, 0x10, 0x48, 0x60}
)

type pipe struct {
	ctx    context.Context
	c      *Client
	treeID uint32
	id     [16]byte
	callID uint32
}

func (c *Client) openPipe(ctx context.Context, name string) (*pipe, error) {
	treeID, _, _, err := c.c.treeConnect(ctx, c.host, "IPC$")
	if err != nil {
		return nil, err
	}
	id, _, _, err := c.c.create(ctx, treeID, name, pipeAccess, 0, 7, fileOpen, 0)
	if err != nil {
		c.c.treeDisconnect(ctx, treeID)
		return nil, err
	}
	return &pipe{ctx: ctx, c: c, treeID: treeID, id: id, callID: 1}, nil
}

func (p *pipe) Close() {
	p.c.c.closeFile(context.Background(), p.treeID, p.id)
	p.c.c.treeDisconnect(context.Background(), p.treeID)
}

func (p *pipe) write(b []byte) error {
	err := p.c.c.writeAt(p.ctx, p.treeID, p.id, b)
	if os.Getenv("SMB_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "pipe write %d bytes err=%v\n", len(b), err)
	}
	return err
}

// readPDU reads one complete PDU, stitching fragments using frag_length.
func (p *pipe) readPDU() ([]byte, error) {
	var out []byte
	want := -1
	for i := 0; i < 64; i++ {
		chunk, err := p.c.c.readAt(p.ctx, p.treeID, p.id, 0, 65536)
		if os.Getenv("SMB_DEBUG") != "" {
			fmt.Fprintf(os.Stderr, "pipe read %d bytes err=%v\n", len(chunk), err)
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(out) > 0 {
				break
			}
			return nil, err
		}
		if len(chunk) == 0 {
			break
		}
		out = append(out, chunk...)
		if len(out) >= 10 && want < 0 {
			want = int(binary.LittleEndian.Uint16(out[8:]))
		}
		if want > 0 && len(out) >= want {
			return out[:want], nil
		}
	}
	if len(out) == 0 {
		return nil, errors.New("rpc: empty response")
	}
	return out, nil
}

func rpcHeader(ptype byte, flags byte, callID uint32, body []byte) []byte {
	b := make([]byte, 16+len(body))
	b[0] = 5 // version
	b[1] = 0
	b[2] = ptype
	b[3] = flags
	b[4] = 0x10 // little endian
	b[8], b[9] = byte(len(b)), byte(len(b)>>8)
	binary.LittleEndian.PutUint32(b[12:], callID)
	copy(b[16:], body)
	return b
}

// bindBody builds a DCERPC bind PDU body for srvsvc over NDR32.
func bindBody() []byte {
	body := make([]byte, 56)
	binary.LittleEndian.PutUint16(body[0:], 5840) // max xmit
	binary.LittleEndian.PutUint16(body[2:], 5840) // max recv
	binary.LittleEndian.PutUint32(body[4:], 0)    // assoc group
	body[8] = 1                                   // num contexts
	body[12] = 0                                  // context id (u16, 12..13)
	body[13] = 0
	body[14] = 1 // num transfer syntaxes
	copy(body[16:32], uuidSRVSVC[:])
	binary.LittleEndian.PutUint32(body[32:], 3) // interface version
	copy(body[36:52], uuidNDR32[:])
	binary.LittleEndian.PutUint32(body[52:], 2)
	return body
}

func (p *pipe) bind() error {
	pdu := rpcHeader(rpcBind, 0x03, p.callID, bindBody())
	if err := p.write(pdu); err != nil {
		return err
	}
	resp, err := p.readPDU()
	if err != nil {
		return err
	}
	if len(resp) < 26 || resp[2] != rpcBindAck {
		return fmt.Errorf("rpc: unexpected bind response")
	}
	secLen := int(binary.LittleEndian.Uint16(resp[24:]))
	off := align4(26 + secLen)
	if off+4 > len(resp) {
		return fmt.Errorf("rpc: truncated bind ack")
	}
	n := int(resp[off])
	if n < 1 || off+4+24 > len(resp) {
		return fmt.Errorf("rpc: bind ack without results")
	}
	result := binary.LittleEndian.Uint16(resp[off+4:])
	if result != 0 {
		return fmt.Errorf("rpc: bind rejected (result %d)", result)
	}
	return nil
}

func (p *pipe) call(opnum uint16, stub []byte) ([]byte, error) {
	p.callID++
	body := make([]byte, 8+len(stub))
	binary.LittleEndian.PutUint32(body[0:], uint32(len(stub)))
	binary.LittleEndian.PutUint16(body[6:], opnum)
	copy(body[8:], stub)

	if err := p.write(rpcHeader(rpcRequest, 0x03, p.callID, body)); err != nil {
		return nil, err
	}
	resp, err := p.readPDU()
	if err != nil {
		return nil, err
	}
	if len(resp) < 24 {
		return nil, fmt.Errorf("rpc: short response")
	}
	switch resp[2] {
	case rpcResponse:
		return resp[24:], nil
	case rpcFault:
		if len(resp) >= 32 {
			return nil, fmt.Errorf("rpc: fault 0x%08x", binary.LittleEndian.Uint32(resp[24:]))
		}
		return nil, errors.New("rpc: fault")
	default:
		return nil, fmt.Errorf("rpc: unexpected pdu type %d", resp[2])
	}
}

// srvsvcListShares asks the server for its share table.
func (c *Client) srvsvcListShares(ctx context.Context) ([]Share, error) {
	p, err := c.openPipe(ctx, "srvsvc")
	if err != nil {
		return nil, err
	}
	defer p.Close()
	if err := p.bind(); err != nil {
		return nil, err
	}
	stub, err := p.call(15, ndrShareEnumRequest(`\\`+c.host))
	if err != nil {
		return nil, err
	}
	if os.Getenv("SMB_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "srvsvc stub: %x\n", stub)
	}
	return ndrParseShareEnum(stub)
}

// --- NDR ------------------------------------------------------------------

type ndrWriter struct{ b []byte }

func (w *ndrWriter) u32(v uint32) {
	var t [4]byte
	binary.LittleEndian.PutUint32(t[:], v)
	w.b = append(w.b, t[:]...)
}

func (w *ndrWriter) str(s string) {
	u := utf16le(s)
	n := uint32(len(u)/2 + 1)
	w.u32(n) // max count
	w.u32(0) // offset
	w.u32(n) // actual count
	w.b = append(w.b, u...)
	w.b = append(w.b, 0, 0) // NUL terminator
	w.align()
}

func (w *ndrWriter) align() {
	for len(w.b)%4 != 0 {
		w.b = append(w.b, 0)
	}
}

// ndrShareEnumRequest marshals NetrShareEnum(level 1) with an empty container.
//
// The wire layout was validated against a real implementation:
//
//	ServerName ref, ServerName string (inline pointee),
//	Level, union tag, container ref, EntriesRead, Buffer ref,
//	PreferedMaximumLength, ResumeHandle ref, ResumeHandle value
//
// TotalEntries is [out] only and is not part of the request stub.
func ndrShareEnumRequest(server string) []byte {
	w := &ndrWriter{}
	w.u32(0x00020000) // [in] ServerName
	w.str(server)     // its pointee, immediately after the pointer
	w.u32(1)          // Level
	w.u32(1)          // SHARE_ENUM_UNION tag
	w.u32(0x00020004) // container pointer
	w.u32(0)          // EntriesRead
	w.u32(0)          // Buffer (null)
	w.u32(0xFFFFFFFF) // PreferedMaximumLength
	w.u32(0x00020008) // ResumeHandle pointer
	w.u32(0)          // ResumeHandle value
	return w.b
}

type ndrReader struct {
	b   []byte
	pos int
	err error
}

func (r *ndrReader) u32() uint32 {
	if r.pos+4 > len(r.b) {
		r.err = io.ErrUnexpectedEOF
		return 0
	}
	v := binary.LittleEndian.Uint32(r.b[r.pos:])
	r.pos += 4
	return v
}

func (r *ndrReader) str() string {
	max := r.u32()
	_ = r.u32() // offset
	actual := r.u32()
	if r.err != nil {
		return ""
	}
	if max > 4096 || actual > max {
		r.err = errors.New("ndr: implausible string length")
		return ""
	}
	n := int(actual) * 2
	if r.pos+n > len(r.b) {
		r.err = errors.New("ndr: string out of bounds")
		return ""
	}
	s := strings.TrimRight(fromUTF16LE(r.b[r.pos:r.pos+n]), "\x00")
	r.pos += n
	for r.pos%4 != 0 && r.pos < len(r.b) {
		r.pos++
	}
	return s
}

type rawShare struct {
	nameRef, typ, remarkRef uint32
	name, remark            string
}

func ndrParseShareEnum(stub []byte) ([]Share, error) {
	r := &ndrReader{b: stub}
	level := r.u32()
	_ = r.u32() // union tag (duplicates Level on the wire)
	container := r.u32()
	if r.err != nil {
		return nil, r.err
	}
	if level != 1 {
		return nil, fmt.Errorf("rpc: unexpected share level %d", level)
	}

	var out []Share
	if container != 0 {
		entries := r.u32()
		bufRef := r.u32()
		if r.err != nil {
			return nil, r.err
		}
		if entries > 65535 {
			return nil, errors.New("ndr: implausible share count")
		}
		if bufRef != 0 {
			_ = r.u32() // array max_count
			raws := make([]rawShare, entries)
			for i := range raws {
				raws[i].nameRef = r.u32()
				raws[i].typ = r.u32()
				raws[i].remarkRef = r.u32()
			}
			if r.err != nil {
				return nil, r.err
			}
			// Strings follow the fixed array, in pointer order per element.
			for i := range raws {
				if raws[i].nameRef != 0 {
					raws[i].name = r.str()
				}
				if raws[i].remarkRef != 0 {
					raws[i].remark = r.str()
				}
			}
			for _, rs := range raws {
				if rs.name == "" {
					continue
				}
				out = append(out, Share{
					Name:    rs.name,
					Type:    srvShareType(rs.typ),
					Comment: strings.TrimSpace(rs.remark),
				})
			}
		}
	}
	return out, r.err
}

func srvShareType(t uint32) string {
	switch t & 0xFFFF {
	case 0:
		return "disk"
	case 1:
		return "print"
	case 2:
		return "device"
	case 3:
		return "pipe"
	default:
		return "other"
	}
}

// rpcTimeout is the deadline applied to a whole RPC exchange.
const rpcTimeout = 15 * time.Second
