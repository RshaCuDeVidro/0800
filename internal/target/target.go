// Package target expands user supplied target specifications into a sorted,
// de-duplicated list of IP addresses.
//
// Accepted forms (comma separated or repeated):
//
//	10.0.0.5              single address
//	10.0.0.0/24           CIDR range
//	host.example.com      resolved with the system resolver
//	./targets.txt         file with one entry per line ("#" comments allowed)
//	@targets.txt          same, explicit form
package target

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

// ErrTooMany is returned when the expansion exceeds the configured limit.
var ErrTooMany = errors.New("target limit exceeded")

// Options controls expansion behaviour.
type Options struct {
	// Max is the maximum number of hosts allowed (0 means no limit).
	Max int
	// Exclude holds CIDRs / single IPs that must be removed from the result.
	Exclude []string
	// Resolve enables DNS resolution of hostnames.
	Resolve bool
}

// Parse expands every specification and returns a sorted list of unique IPs.
func Parse(specs []string, opts Options) ([]string, error) {
	seen := map[string]struct{}{}
	var out []string

	add := func(ip string) error {
		if _, ok := seen[ip]; ok {
			return nil
		}
		if opts.Max > 0 && len(out) >= opts.Max {
			return fmt.Errorf("%w: more than %d hosts (raise --max-hosts)", ErrTooMany, opts.Max)
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
		return nil
	}

	for _, raw := range specs {
		for _, spec := range splitSpecs(raw) {
			ips, err := expandOne(spec, opts)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if err := add(ip); err != nil {
					return nil, err
				}
			}
		}
	}

	excluded, err := parseExcludes(opts.Exclude)
	if err != nil {
		return nil, err
	}
	if len(excluded) > 0 {
		filtered := out[:0]
		for _, ip := range out {
			if !containsIP(excluded, net.ParseIP(ip)) {
				filtered = append(filtered, ip)
			}
		}
		out = filtered
	}

	sort.Slice(out, func(i, j int) bool { return lessIP(out[i], out[j]) })
	return out, nil
}

func splitSpecs(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	// A file path must not be split on commas.
	if strings.HasPrefix(raw, "@") || isFile(raw) ||
		strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "./") ||
		strings.HasPrefix(raw, "~/") || strings.Contains(raw, `\`) {
		return []string{raw}
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func expandOne(spec string, opts Options) ([]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil
	}
	if strings.HasPrefix(spec, "@") {
		return readFile(strings.TrimPrefix(spec, "@"), opts)
	}
	if isFile(spec) {
		return readFile(spec, opts)
	}
	if _, network, err := net.ParseCIDR(spec); err == nil {
		return expandCIDR(network, opts)
	}
	if ip := net.ParseIP(spec); ip != nil {
		return []string{normalize(ip)}, nil
	}
	if opts.Resolve {
		addrs, err := net.LookupHost(spec)
		if err != nil {
			return nil, fmt.Errorf("resolve %q: %w", spec, err)
		}
		var out []string
		for _, a := range addrs {
			if ip := net.ParseIP(a); ip != nil {
				out = append(out, normalize(ip))
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("resolve %q: no addresses", spec)
		}
		return out, nil
	}
	return nil, fmt.Errorf("invalid target %q (want IP, CIDR, hostname or file)", spec)
}

func expandCIDR(n *net.IPNet, opts Options) ([]string, error) {
	ones, bits := n.Mask.Size()
	hostBits := bits - ones
	if hostBits > 24 { // bigger than a /8 for IPv4, /104 for IPv6
		return nil, fmt.Errorf("refusing to expand %s: too large", n)
	}
	count := 1 << hostBits
	if opts.Max > 0 && count > opts.Max {
		return nil, fmt.Errorf("%w: %s expands to %d hosts", ErrTooMany, n, count)
	}
	out := make([]string, 0, count)
	for ip := n.IP.Mask(n.Mask); n.Contains(ip); ip = inc(ip) {
		out = append(out, normalize(ip))
	}
	return out, nil
}

func inc(ip net.IP) net.IP {
	next := make(net.IP, len(ip))
	copy(next, ip)
	for i := len(next) - 1; i >= 0; i-- {
		next[i]++
		if next[i] != 0 {
			break
		}
	}
	return next
}

func normalize(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func readFile(path string, opts Options) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open target file: %w", err)
	}
	defer f.Close()

	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "#"); i > 0 {
			line = strings.TrimSpace(line[:i])
		}
		ips, err := expandOne(line, opts)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, ips...)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read target file: %w", err)
	}
	return out, nil
}

func parseExcludes(specs []string) ([]*net.IPNet, error) {
	var out []*net.IPNet
	for _, s := range specs {
		for _, p := range strings.Split(s, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if _, n, err := net.ParseCIDR(p); err == nil {
				out = append(out, n)
				continue
			}
			if ip := net.ParseIP(p); ip != nil {
				bits := 32
				if ip.To4() == nil {
					bits = 128
				}
				out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
				continue
			}
			return nil, fmt.Errorf("invalid --exclude %q", p)
		}
	}
	return out, nil
}

func containsIP(nets []*net.IPNet, ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func lessIP(a, b string) bool {
	ia, ib := net.ParseIP(a), net.ParseIP(b)
	if ia == nil || ib == nil {
		return a < b
	}
	va, vb := ia.To16(), ib.To16()
	for i := 0; i < len(va) && i < len(vb); i++ {
		if va[i] != vb[i] {
			return va[i] < vb[i]
		}
	}
	return false
}

func isFile(path string) bool {
	if path == "" {
		return false
	}
	// Addresses are not paths, even when they contain a separator or a colon.
	if net.ParseIP(path) != nil {
		return false
	}
	if _, _, err := net.ParseCIDR(path); err == nil {
		return false
	}
	if strings.Contains(path, ":") && !strings.ContainsAny(path, `\/`) {
		return false // host:port
	}
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}
