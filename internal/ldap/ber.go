// Package ldap implements the tiny subset of LDAP needed to test anonymous
// binds and read the root DSE. It speaks BER directly; no external codec.
package ldap

import (
	"errors"
	"fmt"
)

// tlv is a decoded BER element.
type tlv struct {
	Tag byte
	Val []byte
}

// readTLV decodes one element. It rejects indefinite lengths (not used by LDAP).
func readTLV(b []byte) (tlv, []byte, error) {
	if len(b) < 2 {
		return tlv{}, nil, errors.New("ber: short element")
	}
	tag := b[0]
	if tag&0x1F == 0x1F {
		return tlv{}, nil, errors.New("ber: high tag numbers unsupported")
	}
	i := 1
	n := int(b[i])
	i++
	if n&0x80 != 0 {
		k := n & 0x7F
		if k == 0 || k > 4 || i+k > len(b) {
			return tlv{}, nil, errors.New("ber: bad length")
		}
		n = 0
		for j := 0; j < k; j++ {
			n = n<<8 | int(b[i+j])
		}
		i += k
	}
	if n < 0 || i+n > len(b) {
		return tlv{}, nil, errors.New("ber: truncated element")
	}
	return tlv{Tag: tag, Val: b[i : i+n]}, b[i+n:], nil
}

func encodeLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var tmp []byte
	for n > 0 {
		tmp = append([]byte{byte(n)}, tmp...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(tmp))}, tmp...)
}

func ber(tag byte, parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	out := []byte{tag}
	out = append(out, encodeLen(len(body))...)
	return append(out, body...)
}

func berInt(tag byte, v int64) []byte {
	if v == 0 {
		return []byte{tag, 1, 0}
	}
	var b []byte
	for v > 0 {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return ber(tag, b)
}

func berString(tag byte, s string) []byte { return ber(tag, []byte(s)) }
func berSeq(parts ...[]byte) []byte       { return ber(0x30, parts...) }

// message wraps a protocol op in an LDAPMessage with the given message id.
func message(id int, op []byte) []byte {
	return berSeq(berInt(0x02, int64(id)), op)
}

// attributes walks a SearchResultEntry and returns its attribute map.
func attributes(entry []byte) (map[string][]string, error) {
	seq, _, err := readTLV(entry)
	if err != nil || seq.Tag != 0x30 {
		return nil, fmt.Errorf("ldap: malformed entry")
	}
	_, rest, err := readTLV(seq.Val) // objectName
	if err != nil {
		return nil, err
	}
	attrs, _, err := readTLV(rest)
	if err != nil || attrs.Tag != 0x30 {
		return nil, fmt.Errorf("ldap: malformed attribute list")
	}
	out := map[string][]string{}
	for len(attrs.Val) > 0 {
		var at tlv
		at, attrs.Val, err = readTLV(attrs.Val)
		if err != nil {
			return out, err
		}
		if at.Tag != 0x30 {
			continue
		}
		name, r, err := readTLV(at.Val)
		if err != nil {
			return out, err
		}
		vals, _, err := readTLV(r)
		if err != nil || vals.Tag != 0x31 {
			continue
		}
		key := string(name.Val)
		for len(vals.Val) > 0 {
			var v tlv
			v, vals.Val, err = readTLV(vals.Val)
			if err != nil {
				break
			}
			out[key] = append(out[key], string(v.Val))
		}
	}
	return out, nil
}

// resultCode extracts the LDAPResult fields from a response op.
func resultCode(op []byte) (int, string) {
	seq, _, err := readTLV(op)
	if err != nil || seq.Tag != 0x30 {
		return -1, ""
	}
	code, rest, err := readTLV(seq.Val)
	if err != nil {
		return -1, ""
	}
	_, rest, err = readTLV(rest) // matchedDN
	if err != nil {
		return -1, ""
	}
	diag, _, _ := readTLV(rest)
	return int(int64FromBytes(code.Val)), string(diag.Val)
}

func int64FromBytes(b []byte) int64 {
	var v int64
	for _, c := range b {
		v = v<<8 | int64(c)
	}
	return v
}
