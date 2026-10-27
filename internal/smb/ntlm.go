package smb

import (
	"bytes"
	"crypto/des"
	"encoding/binary"
	"encoding/hex"
	"time"
)

// emptyNTHash is MD4(UTF-16LE("")) — the NT hash of an empty password. It is a
// well known constant, so computing MD4 at runtime would only add code.
const emptyNTHash = "31d6cfe0d16ae931b73c59d7e0c089c0"

var ntlmSignature = []byte("NTLMSSP\x00")

// Challenge is the parsed NTLMSSP Type 2 message.
type Challenge struct {
	Flags      uint32
	Server     [8]byte
	Target     string
	Identity   ServerIdentity
	TargetInfo map[uint16][]byte
}

// negoType1 builds the NTLMSSP NEGOTIATE message. Signing and sealing are
// deliberately not requested: this client never signs.
func negoType1() []byte {
	const flags = 0xA0080207 // unicode|oem|request-target|ntlm|target-info|128|56
	b := make([]byte, 32)
	copy(b, ntlmSignature)
	putU32(b, 8, 1)
	putU32(b, 12, flags)
	putU16(b, 16, 0)  // domain len
	putU16(b, 18, 0)  // domain max len
	putU32(b, 20, 32) // domain offset
	putU16(b, 24, 0)  // workstation len
	putU16(b, 26, 0)  // workstation max len
	putU32(b, 28, 32) // workstation offset
	return b
}

// parseType2 decodes an NTLMSSP CHALLENGE message.
func parseType2(blob []byte) (*Challenge, bool) {
	if len(blob) < 48 || !bytes.HasPrefix(blob, ntlmSignature) {
		return nil, false
	}
	if binary.LittleEndian.Uint32(blob[8:]) != 2 {
		return nil, false
	}
	ch := &Challenge{
		Flags:      binary.LittleEndian.Uint32(blob[20:]),
		TargetInfo: map[uint16][]byte{},
	}
	copy(ch.Server[:], blob[24:32])

	if n, off := int(u16(blob, 12)), int(u32(blob, 16)); n > 0 && off+n <= len(blob) {
		ch.Target = fromUTF16LE(blob[off : off+n])
	}

	if n, off := int(u16(blob, 40)), int(u32(blob, 44)); n > 0 && off+n <= len(blob) {
		parseAVPairs(blob[off:off+n], ch)
	}
	return ch, true
}

func parseAVPairs(b []byte, ch *Challenge) {
	for len(b) >= 4 {
		id := binary.LittleEndian.Uint16(b)
		n := int(binary.LittleEndian.Uint16(b[2:]))
		b = b[4:]
		if id == 0 {
			return
		}
		if n > len(b) {
			return
		}
		val := b[:n]
		b = b[n:]
		ch.TargetInfo[id] = append([]byte(nil), val...)
		switch id {
		case 1:
			ch.Identity.NetBIOSName = fromUTF16LE(val)
		case 2:
			ch.Identity.NetBIOSDom = fromUTF16LE(val)
		case 3:
			ch.Identity.DNSName = fromUTF16LE(val)
		case 4:
			ch.Identity.DNSDomain = fromUTF16LE(val)
		case 5:
			ch.Identity.Forest = fromUTF16LE(val)
		case 7:
			if len(val) == 8 {
				ft := binary.LittleEndian.Uint64(val)
				ch.Identity.Time = time.Unix(int64(ft)/1e7-11644473600, 0)
			}
		}
	}
}

// type3 builds an NTLMSSP AUTHENTICATE message for an empty password.
// anonymous=true sends empty LM/NT responses (a null session).
func type3(user, domain string, ch *Challenge, anonymous bool) []byte {
	domainB := utf16le(domain)
	userB := utf16le(user)
	wsB := utf16le("0800")

	var ntB []byte
	if !anonymous {
		ntB = ntResponseEmptyPassword(ch.Server)
	}

	off := 64
	lmOff := off
	ntOff := lmOff + 0
	domOff := ntOff + len(ntB)
	usrOff := domOff + len(domainB)
	wsOff := usrOff + len(userB)
	keyOff := wsOff + len(wsB)

	b := make([]byte, keyOff)
	copy(b, ntlmSignature)
	putU32(b, 8, 3)

	putU16(b, 12, 0) // LM len
	putU16(b, 14, 0)
	putU32(b, 16, uint32(lmOff))

	putU16(b, 20, uint16(len(ntB)))
	putU16(b, 22, uint16(len(ntB)))
	putU32(b, 24, uint32(ntOff))

	putU16(b, 28, uint16(len(domainB)))
	putU16(b, 30, uint16(len(domainB)))
	putU32(b, 32, uint32(domOff))

	putU16(b, 36, uint16(len(userB)))
	putU16(b, 38, uint16(len(userB)))
	putU32(b, 40, uint32(usrOff))

	putU16(b, 44, uint16(len(wsB)))
	putU16(b, 46, uint16(len(wsB)))
	putU32(b, 48, uint32(wsOff))

	putU16(b, 52, 0) // session key
	putU16(b, 54, 0)
	putU32(b, 56, uint32(keyOff))

	const flags = 0x00000201 // unicode | ntlm
	putU32(b, 60, flags)

	copy(b[ntOff:], ntB)
	copy(b[domOff:], domainB)
	copy(b[usrOff:], userB)
	copy(b[wsOff:], wsB)
	return b
}

// ntResponseEmptyPassword computes the NTLMv1 response for an empty password.
func ntResponseEmptyPassword(server [8]byte) []byte {
	hash, _ := hex.DecodeString(emptyNTHash)
	keys := [][]byte{
		hash[0:7],
		hash[7:14],
		append(append([]byte(nil), hash[14:16]...), 0, 0, 0, 0, 0),
	}
	out := make([]byte, 0, 24)
	for _, k := range keys {
		block, err := des.NewCipher(desExpand(k))
		if err != nil {
			return nil
		}
		var enc [8]byte
		block.Encrypt(enc[:], server[:])
		out = append(out, enc[:]...)
	}
	return out
}

// desExpand turns a 7 byte key into the 8 byte DES key used by NTLM.
func desExpand(k []byte) []byte {
	if len(k) < 7 {
		return nil
	}
	return []byte{
		k[0] >> 1,
		(k[0]&0x01)<<6 | k[1]>>2,
		(k[1]&0x03)<<5 | k[2]>>3,
		(k[2]&0x07)<<4 | k[3]>>4,
		(k[3]&0x0F)<<3 | k[4]>>5,
		(k[4]&0x1F)<<2 | k[5]>>6,
		(k[5]&0x3F)<<1 | k[6]>>7,
		k[6] & 0x7F,
	}
}

// --- SPNEGO ---------------------------------------------------------------

var (
	oidSPNEGO = []byte{0x06, 0x06, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x02}
	oidNTLM   = []byte{0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A}
)

func derLen(n int) []byte {
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

func der(tag byte, parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	out := []byte{tag}
	out = append(out, derLen(len(body))...)
	return append(out, body...)
}

// spnegoInit wraps an NTLMSSP Type 1 in a GSS-API NegTokenInit.
func spnegoInit(tok []byte) []byte {
	mechTypes := der(0xA0, der(0x30, oidNTLM))
	mechToken := der(0xA2, der(0x04, tok))
	init := der(0x30, mechTypes, mechToken)
	return der(0x60, oidSPNEGO, der(0xA0, init))
}

// spnegoResp wraps an NTLMSSP Type 3 in a NegTokenResp.
func spnegoResp(tok []byte) []byte {
	return der(0xA1, der(0x30, der(0xA2, der(0x04, tok))))
}

// extractNTLM finds the NTLMSSP message inside a SPNEGO blob.
func extractNTLM(blob []byte) []byte {
	i := bytes.Index(blob, ntlmSignature)
	if i < 0 {
		return nil
	}
	return blob[i:]
}
