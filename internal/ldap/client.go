package ldap

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// Result is the outcome of an anonymous LDAP probe.
type Result struct {
	BindCode      int
	BindMessage   string
	Bound         bool
	RootDSE       map[string][]string
	DefaultDN     string
	NamingContext []string
	Host          string
	Domain        string
	Vendor        string
	Version       string
	SearchCode    int
	SearchMessage string
	Entries       int
	Sample        []string
	IsDC          bool
}

// Probe performs an anonymous bind and a bounded search.
func Probe(ctx context.Context, addr string, timeout time.Duration) (*Result, error) {
	d := net.Dialer{Timeout: timeout}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer nc.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = nc.SetDeadline(dl)
	} else {
		_ = nc.SetDeadline(time.Now().Add(timeout * 2))
	}

	c := &conn{r: bufio.NewReaderSize(nc, 64*1024), w: nc, id: 1}
	res := &Result{}

	code, msg, err := c.bind("", "")
	res.BindCode, res.BindMessage = code, msg
	if err == nil && code == 0 {
		res.Bound = true
	}

	attrs := []string{
		"namingContexts", "defaultNamingContext", "rootDomainNamingContext",
		"configurationNamingContext", "dnsHostName", "ldapServiceName",
		"supportedLDAPVersion", "supportedSASLMechanisms", "domainFunctionality",
		"forestFunctionality", "domainControllerFunctionality", "vendorName",
		"vendorVersion", "isGlobalCatalogReady", "serverName",
	}
	dseList, _, err := c.search("", 0, 1, 0, "objectClass", attrs, 64)
	if err == nil && len(dseList) > 0 {
		dse := dseList[0]
		res.RootDSE = dse
		res.DefaultDN = first(dse["defaultNamingContext"])
		res.NamingContext = dse["namingContexts"]
		res.Host = first(dse["dnsHostName"])
		res.Vendor = first(dse["vendorName"])
		res.Version = first(dse["vendorVersion"])
		res.IsDC = res.DefaultDN != "" || len(res.NamingContext) > 0
	}

	// A bounded anonymous search is the actual proof of information disclosure.
	// A root DSE read alone is not: it is exposed by design.
	if res.Bound && res.DefaultDN != "" {
		entries, code, err := c.search(res.DefaultDN, 1, 5, 5, "objectClass",
			[]string{"sAMAccountName", "cn", "objectClass"}, 5)
		if err == nil {
			res.SearchCode = code
			res.SearchMessage = ""
			if code == 0 {
				res.Entries = len(entries)
				for _, e := range entries {
					if v := first(e["sAMAccountName"]); v != "" {
						res.Sample = append(res.Sample, v)
					} else if v := first(e["cn"]); v != "" {
						res.Sample = append(res.Sample, v)
					}
				}
			}
		}
	}
	return res, nil
}

// SearchSample performs one bounded anonymous search and returns what leaked.
// Kept separate so callers can decide whether the extra request is acceptable.
func SearchSample(ctx context.Context, addr, base string, timeout time.Duration) (int, []string, error) {
	d := net.Dialer{Timeout: timeout}
	nc, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, nil, err
	}
	defer nc.Close()
	_ = nc.SetDeadline(time.Now().Add(timeout * 2))
	c := &conn{r: bufio.NewReaderSize(nc, 64*1024), w: nc, id: 1}
	if _, _, err := c.bind("", ""); err != nil {
		return 0, nil, err
	}
	entries, code, err := c.search(base, 1, 5, 5, "objectClass",
		[]string{"sAMAccountName", "cn"}, 32)
	if err != nil {
		return 0, nil, err
	}
	if code != 0 {
		return 0, nil, fmt.Errorf("ldap: search result %d", code)
	}
	var names []string
	for _, e := range entries {
		if v := first(e["sAMAccountName"]); v != "" {
			names = append(names, v)
		} else if v := first(e["cn"]); v != "" {
			names = append(names, v)
		}
	}
	return len(entries), names, nil
}

type conn struct {
	r  *bufio.Reader
	w  io.Writer
	id int
}

func (c *conn) nextID() int { c.id++; return c.id }

func (c *conn) bind(dn, password string) (int, string, error) {
	op := ber(0x60,
		berInt(0x02, 3),
		berString(0x04, dn),
		berString(0x80, password),
	)
	msg := message(c.nextID(), op)
	if _, err := c.w.Write(msg); err != nil {
		return -1, "", err
	}
	resp, err := c.readMessage()
	if err != nil {
		return -1, "", err
	}
	_, respOp, err := parseMessage(resp.Val)
	if err != nil {
		return -1, "", err
	}
	if respOp.Tag != 0x61 {
		return -1, "", fmt.Errorf("ldap: unexpected bind response tag 0x%02x", respOp.Tag)
	}
	code, diag := resultCode(ber(0x30, respOp.Val))
	return code, diag, nil
}

// search sends a search request and returns all entries plus the final result
// code. scope: 0=base, 1=one, 2=subtree.
func (c *conn) search(base string, scope, deref, sizeLimit int, filterAttr string,
	attrs []string, maxEntries int) ([]map[string][]string, int, error) {

	var attrList [][]byte
	for _, a := range attrs {
		attrList = append(attrList, berString(0x04, a))
	}

	op := ber(0x63,
		berString(0x04, base),
		berInt(0x0A, int64(scope)),
		berInt(0x0A, int64(deref)),
		berInt(0x02, int64(sizeLimit)),
		berInt(0x02, 10), // time limit seconds
		ber(0x01, []byte{0}),
		ber(0x87, []byte(filterAttr)), // present filter
		berSeq(attrList...),
	)
	msg := message(c.nextID(), op)
	if _, err := c.w.Write(msg); err != nil {
		return nil, -1, err
	}

	var entries []map[string][]string
	for i := 0; i < maxEntries+8; i++ {
		resp, err := c.readMessage()
		if err != nil {
			return entries, -1, err
		}
		_, respOp, err := parseMessage(resp.Val)
		if err != nil {
			return entries, -1, err
		}
		switch respOp.Tag {
		case 0x64: // SearchResultEntry
			at, err := attributes(ber(0x30, respOp.Val))
			if err == nil {
				entries = append(entries, at)
			}
			if len(entries) >= maxEntries {
				return entries, 0, nil
			}
		case 0x65: // SearchResultDone
			code, _ := resultCode(ber(0x30, respOp.Val))
			return entries, code, nil
		case 0x73: // SearchResultReference — ignore
			continue
		default:
			continue
		}
	}
	return entries, 0, nil
}

// parseMessage splits an LDAPMessage into its id and protocol op.
func parseMessage(content []byte) (tlv, tlv, error) {
	id, rest, err := readTLV(content)
	if err != nil {
		return tlv{}, tlv{}, err
	}
	op, _, err := readTLV(rest)
	if err != nil {
		return tlv{}, tlv{}, err
	}
	return id, op, nil
}

// readMessage reads one complete LDAPMessage envelope.
func (c *conn) readMessage() (tlv, error) {
	tag, err := c.r.ReadByte()
	if err != nil {
		return tlv{}, err
	}
	n, err := readLength(c.r)
	if err != nil {
		return tlv{}, err
	}
	if n < 0 || n > 8<<20 {
		return tlv{}, errors.New("ldap: message too large")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.r, buf); err != nil {
		return tlv{}, err
	}
	return tlv{Tag: tag, Val: buf}, nil
}

func readLength(r *bufio.Reader) (int, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	n := int(b)
	if n&0x80 == 0 {
		return n, nil
	}
	k := n & 0x7F
	if k == 0 || k > 4 {
		return 0, errors.New("ldap: bad length")
	}
	n = 0
	for i := 0; i < k; i++ {
		c, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		n = n<<8 | int(c)
	}
	return n, nil
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// Describe renders the probe as a short key/value list for the details pane.
func (r *Result) Describe() [][2]string {
	out := [][2]string{
		{"bind", strconv.Itoa(r.BindCode) + " " + r.BindMessage},
	}
	if r.Bound {
		out = append(out, [2]string{"anonymous", "accepted"})
	}
	if r.DefaultDN != "" {
		out = append(out, [2]string{"domain DN", r.DefaultDN})
	}
	if r.Host != "" {
		out = append(out, [2]string{"dns host", r.Host})
	}
	if r.Vendor != "" {
		out = append(out, [2]string{"vendor", strings.TrimSpace(r.Vendor + " " + r.Version)})
	}
	if r.SearchCode != 0 {
		out = append(out, [2]string{"search", strconv.Itoa(r.SearchCode)})
	}
	return out
}
