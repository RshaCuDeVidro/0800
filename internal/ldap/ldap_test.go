package ldap

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// fakeLDAP answers anonymous binds and two searches.
func fakeLDAP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveLDAP(c)
		}
	}()
	return ln.Addr().String()
}

func serveLDAP(c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	for {
		msg, err := readMsg(br)
		if err != nil {
			return
		}
		id, rest, err := readTLV(msg)
		if err != nil || id.Tag != 0x02 {
			return
		}
		op, _, err := readTLV(rest)
		if err != nil {
			return
		}
		switch op.Tag {
		case 0x60: // bind
			writeMsg(c, berSeq(msgID(id), ber(0x61, berInt(0x0A, 0), berString(0x04, ""), berString(0x04, ""))))
		case 0x63: // search
			base := searchBase(op.Val)
			if base == "" {
				attrs := map[string]string{
					"defaultNamingContext": "DC=corp,DC=local",
					"dnsHostName":          "dc01.corp.local",
					"vendorName":           "Fake Directory",
					"supportedLDAPVersion": "3",
				}
				writeMsg(c, berSeq(msgID(id), entry("", attrs)))
				writeMsg(c, berSeq(msgID(id), ber(0x65, berInt(0x0A, 0), berString(0x04, ""), berString(0x04, ""))))
			} else {
				writeMsg(c, berSeq(msgID(id), entry("CN=svc_backup,DC=corp,DC=local", map[string]string{"sAMAccountName": "svc_backup"})))
				writeMsg(c, berSeq(msgID(id), entry("CN=helpdesk,DC=corp,DC=local", map[string]string{"sAMAccountName": "helpdesk"})))
				writeMsg(c, berSeq(msgID(id), ber(0x65, berInt(0x0A, 0), berString(0x04, ""), berString(0x04, ""))))
			}
		default:
			writeMsg(c, berSeq(msgID(id), ber(0x65, berInt(0x0A, 2), berString(0x04, ""), berString(0x04, "unsupported"))))
		}
	}
}

func msgID(id tlv) []byte { return berInt(0x02, int64FromBytes(id.Val)) }

func entry(dn string, attrs map[string]string) []byte {
	var list [][]byte
	for k, v := range attrs {
		list = append(list, berSeq(berString(0x04, k), ber(0x31, berString(0x04, v))))
	}
	return ber(0x64, berString(0x04, dn), berSeq(list...))
}

func searchBase(op []byte) string {
	base, _, err := readTLV(op)
	if err != nil {
		return ""
	}
	return string(base.Val)
}

func writeMsg(w io.Writer, b []byte) { _, _ = w.Write(b) }

func readMsg(r *bufio.Reader) ([]byte, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if tag != 0x30 {
		return nil, io.ErrUnexpectedEOF
	}
	n, err := readLength(r)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func TestProbe(t *testing.T) {
	addr := fakeLDAP(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := Probe(ctx, addr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Bound || res.BindCode != 0 {
		t.Fatalf("bind = %d %q", res.BindCode, res.BindMessage)
	}
	if res.DefaultDN != "DC=corp,DC=local" {
		t.Errorf("defaultNamingContext = %q", res.DefaultDN)
	}
	if res.Host != "dc01.corp.local" {
		t.Errorf("dnsHostName = %q", res.Host)
	}
	if !res.IsDC {
		t.Error("expected DC markers")
	}
	if res.Entries != 2 {
		t.Errorf("entries = %d, want 2", res.Entries)
	}
	if len(res.Sample) == 0 || res.Sample[0] != "svc_backup" {
		t.Errorf("sample = %v", res.Sample)
	}
}

func TestTLVLongForm(t *testing.T) {
	payload := make([]byte, 300)
	for i := range payload {
		payload[i] = byte(i)
	}
	enc := ber(0x04, payload)
	got, rest, err := readTLV(enc)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Errorf("trailing bytes: %d", len(rest))
	}
	if len(got.Val) != 300 {
		t.Fatalf("len = %d", len(got.Val))
	}
	if got.Val[299] != byte(299&0xff) {
		t.Error("payload mismatch")
	}
}

func TestTLVRejectsTruncated(t *testing.T) {
	if _, _, err := readTLV([]byte{0x04, 0x10, 0x00}); err == nil {
		t.Fatal("expected error")
	}
	if _, _, err := readTLV([]byte{0x04}); err == nil {
		t.Fatal("expected error")
	}
}

func FuzzReadTLV(f *testing.F) {
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x00})
	f.Add([]byte{0x04, 0x81, 0x02, 0x00, 0x00})
	f.Fuzz(func(t *testing.T, data []byte) {
		if tl, _, err := readTLV(data); err == nil {
			_ = tl.Val
		}
	})
}

func TestResultCode(t *testing.T) {
	code, msg := resultCode(ber(0x30, berInt(0x0A, 49), berString(0x04, ""), berString(0x04, "invalid credentials")))
	if code != 49 || msg != "invalid credentials" {
		t.Fatalf("code=%d msg=%q", code, msg)
	}
}

func TestIntFromBytes(t *testing.T) {
	// sanity check the helper used by the BER reader
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], 1234)
	if got := int64FromBytes(b[:]); got != 1234 {
		t.Fatalf("got %d", got)
	}
}
