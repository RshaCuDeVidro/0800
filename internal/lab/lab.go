// Package lab provides deliberately vulnerable servers for local testing.
//
// It exists so 0800 can be exercised end to end without touching a third-party
// system: run `go run ./tools/lab`, then scan 127.0.0.1.
package lab

import (
	"fmt"
	"net"
	"sort"
	"sync"
)

// Service is one running fake service.
type Service struct {
	Name     string
	Port     int
	Listener net.Listener
}

// Lab is a collection of running services.
type Lab struct {
	mu    sync.Mutex
	procs []Service
}

// Add registers a listener under a friendly name.
func (l *Lab) Add(name string, ln net.Listener) Service {
	s := Service{Name: name, Port: ln.Addr().(*net.TCPAddr).Port, Listener: ln}
	l.mu.Lock()
	l.procs = append(l.procs, s)
	l.mu.Unlock()
	return s
}

// Close stops every listener.
func (l *Lab) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, s := range l.procs {
		_ = s.Listener.Close()
	}
	l.procs = nil
}

// Services returns the running services sorted by port.
func (l *Lab) Services() []Service {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := append([]Service(nil), l.procs...)
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

// String renders a printable table of the lab.
func (l *Lab) String() string {
	var out string
	for _, s := range l.Services() {
		out += fmt.Sprintf("  %-10s 127.0.0.1:%d\n", s.Name, s.Port)
	}
	return out
}

func listen(port int) (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
}
