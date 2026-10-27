package scan

import (
	"context"
	"fmt"
	"net"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Config configures an Engine.
type Config struct {
	Targets      []string
	Ports        []int
	DialTimeout  time.Duration
	IOTimeout    time.Duration
	Concurrency  int
	ProbeWorkers int
	Rate         int // dials per second, 0 = unlimited
	HostBudget   time.Duration
	// Retries is the number of extra TCP dial attempts after the first one,
	// with a small linear backoff between them. 0 (the default) keeps the
	// original fail-fast behaviour; raise it on flaky networks where a dial
	// timeout doesn't necessarily mean the port is closed.
	Retries int
	// Skip lists hosts a previous run already finished (--resume): they are
	// counted as done but not probed again.
	Skip map[string]bool
	// EnumShares runs share enumeration (srvsvc) during the scan. The browser
	// can always enumerate on demand.
	EnumShares bool
	// ServicePorts maps a non-standard port to a protocol name ("smb", "ldap",
	// "nfs", "mysql", "postgres", "redis", "kerberos"). Useful for labs and NAT.
	ServicePorts map[int]string
	OnFinish     func(*HostView)
	// Probe overrides the protocol dispatcher (tests).
	Probe func(ctx context.Context, e *Engine, ip string, port int)
}

// DefaultPorts is the default scan set.
var DefaultPorts = []int{21, 445, 88, 389, 2049, 3306, 5432, 6379}

// Engine runs the two-stage scan: a fast TCP sweep followed by protocol probes
// only on ports that answered.
type Engine struct {
	cfg   Config
	store *Store

	probeCh chan probeJob

	gate *gate
}

type hostTask struct {
	ip      string
	pending atomic.Int32
	done    sync.Once
	started time.Time
}

type portJob struct {
	host *hostTask
	port int
}

type probeJob struct {
	host *hostTask
	port int
}

// New creates an engine. Targets must already be expanded and sorted.
func New(cfg Config) *Engine {
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 500 * time.Millisecond
	}
	if cfg.IOTimeout <= 0 {
		cfg.IOTimeout = 4 * time.Second
	}
	if cfg.HostBudget <= 0 {
		cfg.HostBudget = 15 * time.Second
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 1024
	}
	if cfg.ProbeWorkers <= 0 {
		cfg.ProbeWorkers = 64
	}
	if len(cfg.Ports) == 0 {
		cfg.Ports = DefaultPorts
	}
	e := &Engine{cfg: cfg}
	if cfg.Rate > 0 {
		e.gate = newGate(cfg.Rate)
	}
	e.store = NewStore(cfg.Targets, cfg.OnFinish)
	return e
}

// Store exposes the live scan state.
func (e *Engine) Store() *Store { return e.store }

// Run blocks until the scan completes or ctx is cancelled.
func (e *Engine) Run(ctx context.Context) error {
	total := len(e.cfg.Targets)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if e.gate != nil {
		defer e.gate.close()
	}

	var storeWG sync.WaitGroup
	storeWG.Add(1)
	go func() {
		defer storeWG.Done()
		e.store.Run(runCtx)
	}()

	tasks := make([]*hostTask, 0, total)
	for _, ip := range e.cfg.Targets {
		if e.cfg.Skip[ip] {
			e.store.Finish(ip, 0)
			continue
		}
		t := &hostTask{ip: ip, started: time.Now()}
		t.pending.Store(int32(len(e.cfg.Ports)))
		tasks = append(tasks, t)
	}

	e.probeCh = make(chan probeJob, 4096)

	var probeWG sync.WaitGroup
	for i := 0; i < e.cfg.ProbeWorkers; i++ {
		probeWG.Add(1)
		go func() {
			defer probeWG.Done()
			for pj := range e.probeCh {
				e.runProbe(runCtx, pj)
				if runCtx.Err() != nil {
					// Cancelled mid-probe: the host is not finished. Counting
					// it done would report unscanned hosts as scanned.
					continue
				}
				e.unitDone(pj.host)
			}
		}()
	}

	jobs := make(chan portJob, 4096)
	var workers sync.WaitGroup
	for i := 0; i < e.cfg.Concurrency; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := range jobs {
				if runCtx.Err() != nil {
					return
				}
				e.checkPort(runCtx, j.host, j.port)
				if runCtx.Err() != nil {
					// Cancelled while waiting on the rate gate or dialing: this
					// port was never really checked, so the host stays pending
					// (and --resume will scan it) instead of "done".
					return
				}
				e.unitDone(j.host)
			}
		}()
	}

feed:
	for _, t := range tasks {
		for _, p := range e.cfg.Ports {
			select {
			case <-runCtx.Done():
				break feed
			case jobs <- portJob{host: t, port: p}:
			}
		}
	}
	close(jobs)
	workers.Wait()
	close(e.probeCh)
	probeWG.Wait()

	e.store.Complete()
	cancel()
	storeWG.Wait()
	return ctx.Err()
}

func (e *Engine) unitDone(h *hostTask) {
	if h.pending.Add(-1) != 0 {
		return
	}
	h.done.Do(func() {
		e.store.Finish(h.ip, time.Since(h.started))
	})
}

func (e *Engine) checkPort(ctx context.Context, h *hostTask, port int) {
	if e.gate != nil {
		if err := e.gate.wait(ctx); err != nil {
			return
		}
	}

	conn, err := e.dialWithRetry(ctx, h.ip, port)
	if err != nil {
		return
	}
	_ = conn.Close()

	e.store.PortOpen(h.ip, port)
	e.store.SetState(h.ip, StateScanning)

	h.pending.Add(1)
	select {
	case e.probeCh <- probeJob{host: h, port: port}:
	case <-ctx.Done():
		h.pending.Add(-1)
	}
}

// dialWithRetry dials once, then retries up to e.cfg.Retries more times with
// a linear backoff (150ms, 300ms, 450ms, ...) on failure. A context
// cancellation during the backoff wait aborts immediately.
func (e *Engine) dialWithRetry(ctx context.Context, ip string, port int) (net.Conn, error) {
	d := net.Dialer{Timeout: e.cfg.DialTimeout}
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	var lastErr error
	for attempt := 0; ; attempt++ {
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if attempt >= e.cfg.Retries {
			return nil, lastErr
		}
		backoff := time.Duration(attempt+1) * 150 * time.Millisecond
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (e *Engine) runProbe(ctx context.Context, pj probeJob) {
	defer func() {
		if r := recover(); r != nil {
			e.store.SetError(pj.host.ip, fmt.Sprintf("probe panic on %d: %v\n%s", pj.port, r, debug.Stack()))
		}
	}()

	budget := e.cfg.IOTimeout * 3
	if e.cfg.HostBudget > 0 && e.cfg.HostBudget < budget {
		budget = e.cfg.HostBudget
	}
	pctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	if e.cfg.Probe != nil {
		e.cfg.Probe(pctx, e, pj.host.ip, pj.port)
		return
	}
	e.dispatch(pctx, pj.host.ip, pj.port)
}

// gate is a simple token bucket used to keep the TCP sweep polite.
type gate struct {
	ch     chan struct{}
	ticker *time.Ticker
	done   chan struct{}
	once   sync.Once
}

func newGate(perSec int) *gate {
	if perSec < 1 {
		perSec = 1
	}
	g := &gate{
		ch:     make(chan struct{}, perSec),
		ticker: time.NewTicker(time.Second / time.Duration(perSec)),
		done:   make(chan struct{}),
	}
	for i := 0; i < perSec && i < 64; i++ {
		g.ch <- struct{}{}
	}
	go func() {
		for {
			select {
			case <-g.ticker.C:
				select {
				case g.ch <- struct{}{}:
				default:
				}
			case <-g.done:
				return
			}
		}
	}()
	return g
}

func (g *gate) close() {
	g.once.Do(func() {
		g.ticker.Stop()
		close(g.done)
	})
}

func (g *gate) wait(ctx context.Context) error {
	select {
	case <-g.ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
