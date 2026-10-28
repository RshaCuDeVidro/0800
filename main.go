// Command 0800 is a fast terminal recon tool for services that answer without
// credentials: SMB null/guest sessions, anonymous LDAP, open NFS exports and
// passwordless databases.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/RshaCuDeVidro/0800/internal/preset"
	"github.com/RshaCuDeVidro/0800/internal/report"
	"github.com/RshaCuDeVidro/0800/internal/scan"
	"github.com/RshaCuDeVidro/0800/internal/smb"
	"github.com/RshaCuDeVidro/0800/internal/target"
	"github.com/RshaCuDeVidro/0800/internal/ui"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"golang.org/x/term"
)

var version = "0.5.1"

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

// errNewExposure makes --diff exit with status 3 when the new report holds a
// finding the old one did not (medium or above), so a cron job or CI step can
// alert on it. The diff itself has already been printed.
var errNewExposure = errors.New("new exposure")

func main() {
	if err := run(); err != nil {
		if errors.Is(err, errNewExposure) {
			os.Exit(3)
		}
		fmt.Fprintln(os.Stderr, "0800:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		targets     stringList
		exclude     stringList
		portsFlag   = flag.String("p", "21,445,88,389,2049,3306,5432,6379", "comma separated ports to test")
		timeout     = flag.Duration("timeout", 500*time.Millisecond, "TCP dial timeout")
		ioTimeout   = flag.Duration("io-timeout", 4*time.Second, "per protocol I/O timeout")
		concurrency = flag.Int("c", 1024, "parallel TCP workers")
		probes      = flag.Int("probe-workers", 64, "parallel protocol workers")
		rate        = flag.Int("rate", 0, "max dials per second (0 = unlimited)")
		remap       = flag.String("remap", "", "probe a non-standard port, e.g. smb=1445,ldap=1389")
		maxHosts    = flag.Int("max-hosts", 65536, "refuse to expand more than this many targets")
		loot        = flag.String("loot", "0800-loot", "directory for downloaded files")
		flat        = flag.Bool("flat", false, "download straight into the loot root")
		jsonPath    = flag.String("json", "", "write a JSON report to this path")
		mdPath      = flag.String("markdown", "", "write a Markdown report to this path")
		htmlPath    = flag.String("html", "", "write a self-contained HTML report to this path")
		checkpoint  = flag.Duration("checkpoint", 20*time.Second, "autosave the partial report(s) at this interval while scanning (0 disables)")
		retries     = flag.Int("retries", 0, "extra TCP dial attempts on a failed connection, with backoff")
		plain       = flag.Bool("plain", false, "headless output, no TUI")
		profile     = flag.String("profile", "", "port preset: full, quick, ad, smb, db")
		enumShares  = flag.Bool("enum-shares", true, "enumerate shares during the scan (short list)")
		menu        = flag.Bool("menu", false, "always show the interactive setup screen")
		noMenu      = flag.Bool("no-menu", false, "skip the interactive setup screen")
		noColor     = flag.Bool("no-color", false, "disable ANSI colours")
		diffMode    = flag.Bool("diff", false, "compare two JSON reports: 0800 --diff old.json new.json (exit 3 on new exposure)")
		resumePath  = flag.String("resume", "", "continue an interrupted scan from its (partial) JSON report")
		noMouse     = flag.Bool("no-mouse", false, "do not capture the mouse (keeps terminal text selection)")
		demo        = flag.Bool("demo", false, "run the TUI with built-in example data")
		width       = flag.Int("width", 0, "override terminal width (demo/screenshots)")
		height      = flag.Int("height", 0, "override terminal height (demo/screenshots)")
		showVersion = flag.Bool("version", false, "print version and exit")
	)

	flag.Var(&targets, "t", "target: IP, CIDR, hostname, file or @file (repeatable)")
	flag.Var(&targets, "target", "alias for -t")
	flag.Var(&exclude, "exclude", "CIDR or IP to skip (repeatable)")
	flag.Usage = usage
	flag.Parse()
	targets = append(targets, flag.Args()...)

	if *showVersion {
		fmt.Printf("0800 %s\n", version)
		return nil
	}
	if *noColor {
		lipgloss.SetColorProfile(termenv.Ascii)
	}
	if *demo {
		return runDemo(*width, *height)
	}
	if *diffMode {
		return runDiff(flag.Args())
	}

	var rs *report.Resume
	if *resumePath != "" {
		r, err := report.LoadResume(*resumePath)
		if err != nil {
			return err
		}
		rs = &r
		if len(targets) > 0 {
			fmt.Fprintln(os.Stderr, "0800: --resume continues the report's own target list; ignoring -t")
		}
		targets = stringList{"(resume)"}
	}

	setFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) { setFlags[f.Name] = true })

	// Resolve the port list from -p / --profile when given; the wizard may
	// override it later.
	var flagPorts []int
	if setFlags["p"] || *profile != "" {
		if *profile != "" && !setFlags["p"] {
			pre, ok := preset.Find(*profile)
			if !ok {
				return fmt.Errorf("unknown profile %q (want %s)", *profile, strings.Join(preset.Names(), ", "))
			}
			*portsFlag = pre.Format()
		}
		p, err := preset.ParsePorts(*portsFlag)
		if err != nil {
			return err
		}
		flagPorts = p
	}

	// The setup screen is the default when a terminal is attached, even if -t
	// was given (it is prefilled). Scripts use --no-menu or a pipe.
	interactive := term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	showMenu := (*menu || (interactive && !*noMenu && !*plain)) && rs == nil
	if showMenu {
		if !interactive {
			return errors.New("interactive setup needs a terminal (use --no-menu for scripts)")
		}
		setup, err := ui.RunWizard(version, ui.Setup{
			TargetSpec: strings.Join(targets, ","),
			Ports:      flagPorts,
			PortsSet:   setFlags["p"] || *profile != "",
			Workers:    *concurrency,
			WorkersSet: setFlags["c"],
			Rate:       *rate,
			RateSet:    setFlags["rate"],
			EnumShares: *enumShares,
			EnumSet:    setFlags["enum-shares"],
		})
		if err != nil {
			return err
		}
		if setup == nil {
			return nil
		}
		targets = stringList(setup.Targets)
		flagPorts = setup.Ports
		*portsFlag = joinInts(setup.Ports)
		*concurrency = setup.Workers
		*rate = setup.Rate
		*enumShares = setup.EnumShares
	}
	if len(targets) == 0 {
		flag.Usage()
		return errors.New("no targets given")
	}

	portList := flagPorts
	if portList == nil {
		pre, _ := preset.Find(preset.Default)
		portList = pre.Ports
	}

	servicePorts, extraPorts, err := parseRemap(*remap)
	if err != nil {
		return err
	}
	for _, p := range extraPorts {
		if !containsPort(portList, p) {
			portList = append(portList, p)
		}
	}
	if len(targets) == 0 {
		flag.Usage()
		return errors.New("no targets given (use -t or positional arguments)")
	}

	var (
		ips  []string
		skip map[string]bool
	)
	if rs != nil {
		ips, skip = resumeTargets(rs)
		fmt.Fprintf(os.Stderr, "resuming %s: %d target(s) left, %d host(s) with results restored\n",
			*resumePath, len(rs.Targets), len(rs.Done))
	} else {
		ips, err = target.Parse(targets, target.Options{
			Max:     *maxHosts,
			Exclude: exclude,
			Resolve: true,
		})
		if errors.Is(err, target.ErrTooMany) {
			return fmt.Errorf("%w — lower the scope or raise --max-hosts", err)
		}
		if err != nil {
			return err
		}
		if len(ips) == 0 {
			return errors.New("every target was excluded")
		}
	}

	smbCfg := smb.DefaultConfig()
	smbCfg.DialTimeout = *timeout
	smbCfg.IOTimeout = *ioTimeout

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stderr, "%s %s\n", uiWordmark(), version)
	fmt.Fprintf(os.Stderr, "  %d target(s) · ports %s · %d workers · %d probes\n\n",
		len(ips), *portsFlag, *concurrency, *probes)

	cfg := scan.Config{
		Targets:      ips,
		Ports:        portList,
		DialTimeout:  *timeout,
		IOTimeout:    *ioTimeout,
		Concurrency:  *concurrency,
		ProbeWorkers: *probes,
		Rate:         *rate,
		Retries:      *retries,
		Skip:         skip,
		ServicePorts: servicePorts,
		EnumShares:   *enumShares,
	}

	if *plain {
		cfg.OnFinish = func(h *scan.HostView) {
			fmt.Printf("%s %s\n", severityPrefix(h), report.PlainLine(h))
		}
		eng := scan.New(cfg)
		if rs != nil {
			eng.Store().Restore(rs.Done)
		}
		scanCtx, cancelScan := context.WithCancel(ctx)
		stopCheckpoint := startCheckpointer(scanCtx, eng, version, *checkpoint, *jsonPath, *mdPath, *htmlPath)
		err := eng.Run(scanCtx)
		cancelScan()
		stopCheckpoint()
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		snap := eng.Store().Snapshot()
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "  "+report.Summary(snap))
		return writeReports(snap, version, *jsonPath, *mdPath, *htmlPath)
	}

	scanCtx, cancelScan := context.WithCancel(ctx)
	eng := scan.New(cfg)
	if rs != nil {
		eng.Store().Restore(rs.Done)
	}
	stopCheckpoint := startCheckpointer(scanCtx, eng, version, *checkpoint, *jsonPath, *mdPath, *htmlPath)
	// A single defer, in this order: cancelScan must run before stopCheckpoint
	// blocks on it, on every exit path (including an early return from
	// p.Run()'s error case below, not just the normal fallthrough).
	defer func() {
		cancelScan()
		stopCheckpoint()
	}()
	model := ui.New(ui.Config{
		Store:      eng.Store(),
		LootDir:    *loot,
		Flat:       *flat,
		Version:    version,
		SMB:        smbCfg,
		NFSTimeout: *ioTimeout,
		Workers:    *concurrency,
		Cancel:     cancelScan,
	})

	go func() {
		if err := eng.Run(scanCtx); err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "0800:", err)
		}
	}()

	progOpts := []tea.ProgramOption{tea.WithAltScreen()}
	if !*noMouse {
		progOpts = append(progOpts, tea.WithMouseCellMotion())
	}
	p := tea.NewProgram(model, progOpts...)
	go func() {
		<-ctx.Done()
		p.Quit()
	}()
	if _, err := p.Run(); err != nil {
		return err
	}

	// Give the engine a moment to publish its final state before reporting.
	stop()
	if st := eng.Store(); st != nil {
		st.Complete()
		if err := writeReports(st.Snapshot(), version, *jsonPath, *mdPath, *htmlPath); err != nil {
			return err
		}
	}
	return nil
}

// runDiff prints what changed between two saved reports.
func runDiff(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: 0800 --diff <old.json> <new.json>")
	}
	oldDoc, err := report.LoadDocument(args[0])
	if err != nil {
		return err
	}
	newDoc, err := report.LoadDocument(args[1])
	if err != nil {
		return err
	}
	d := report.Diff(oldDoc, newDoc)
	fmt.Print(report.FormatDiff(d, args[0], args[1]))
	if d.NewExposure() {
		return errNewExposure
	}
	return nil
}

// resumeTargets merges the pending targets with the hosts whose results are
// restored (they must be in the store to appear in the final report), sorted,
// and returns the set of hosts the engine must not probe again.
func resumeTargets(rs *report.Resume) ([]string, map[string]bool) {
	skip := make(map[string]bool, len(rs.Done))
	all := append([]string(nil), rs.Targets...)
	for _, h := range rs.Done {
		skip[h.IP] = true
		all = append(all, h.IP)
	}
	sort.Slice(all, func(i, j int) bool {
		a, errA := netip.ParseAddr(all[i])
		b, errB := netip.ParseAddr(all[j])
		if errA != nil || errB != nil {
			return all[i] < all[j]
		}
		return a.Less(b)
	})
	return all, skip
}

// writeReports writes every report format the caller asked for (an empty
// path skips that format) and prints where each one landed.
func writeReports(snap *scan.Snapshot, version, jsonPath, mdPath, htmlPath string) error {
	return writeReportsAnnounce(snap, version, jsonPath, mdPath, htmlPath, true)
}

func writeReportsAnnounce(snap *scan.Snapshot, version, jsonPath, mdPath, htmlPath string, announce bool) error {
	doc := report.Build(snap, version)
	type target struct {
		path  string
		write func(string, report.Document) error
	}
	for _, t := range []target{
		{jsonPath, report.WriteJSON},
		{mdPath, report.WriteMarkdown},
		{htmlPath, report.WriteHTML},
	} {
		if t.path == "" {
			continue
		}
		if err := t.write(t.path, doc); err != nil {
			return err
		}
		if announce {
			fmt.Fprintln(os.Stderr, "  report: "+t.path)
		}
	}
	return nil
}

// startCheckpointer periodically writes the report format(s) the user asked
// for while a long scan is still running, so killing the process (or it
// crashing) loses at most one interval's worth of findings instead of the
// whole scan. It writes quietly — no per-tick "report: ..." line — and the
// final writeReports call after the scan finishes overwrites it with the
// complete result. The returned func stops the ticker and must be called
// exactly once.
func startCheckpointer(ctx context.Context, eng *scan.Engine, version string, interval time.Duration, jsonPath, mdPath, htmlPath string) func() {
	if interval <= 0 || (jsonPath == "" && mdPath == "" && htmlPath == "") {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				_ = writeReportsAnnounce(eng.Store().Snapshot(), version, jsonPath, mdPath, htmlPath, false)
			}
		}
	}()
	return func() { <-done }
}

func runDemo(w, h int) error {
	if w <= 0 {
		w = 120
	}
	if h <= 0 {
		h = 38
	}
	m := ui.NewDemo(w, h, "main")
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return err
	}
	return nil
}

// parseRemap turns "smb=1445,ldap=1389" into a port->service map.
func parseRemap(s string) (map[int]string, []int, error) {
	out := map[int]string{}
	var ports []int
	if strings.TrimSpace(s) == "" {
		return nil, nil, nil
	}
	valid := map[string]bool{
		"smb": true, "ldap": true, "nfs": true, "kerberos": true,
		"mysql": true, "postgres": true, "redis": true, "ftp": true,
	}
	for _, pair := range strings.Split(s, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		svc, raw, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, nil, fmt.Errorf("invalid --remap %q (want service=port)", pair)
		}
		svc = strings.ToLower(strings.TrimSpace(svc))
		if !valid[svc] {
			return nil, nil, fmt.Errorf("invalid --remap service %q", svc)
		}
		port, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || port < 1 || port > 65535 {
			return nil, nil, fmt.Errorf("invalid --remap port %q", raw)
		}
		out[port] = svc
		ports = append(ports, port)
	}
	return out, ports, nil
}

func containsPort(list []int, p int) bool {
	for _, v := range list {
		if v == p {
			return true
		}
	}
	return false
}

func joinInts(v []int) string {
	parts := make([]string, 0, len(v))
	for _, n := range v {
		parts = append(parts, strconv.Itoa(n))
	}
	return strings.Join(parts, ",")
}

func severityPrefix(h *scan.HostView) string {
	switch {
	case h.Discovered() > 0:
		return "[+]"
	case len(h.Ports) > 0:
		return "[·]"
	default:
		return "[-]"
	}
}

func uiWordmark() string {
	return lipgloss.NewStyle().Foreground(lipgloss.Color("#7EE7D0")).Bold(true).Render("0800") + " · null-auth recon"
}

func usage() {
	fmt.Fprintf(os.Stderr, `0800 %s — null authentication recon

usage:
  0800                       interactive setup
  0800 -t <target>... [flags]

targets:
  -t, --target     IP, CIDR, hostname, file or @file (repeatable)
      --exclude    CIDR or IP to skip (repeatable)

examples:
  0800                                # setup menu (default on a terminal)
  0800 -t 10.0.0.0/24 --profile quick
  0800 -t hosts.txt --plain
  0800 -t 192.0.2.10 -p 445,389 --json out.json
  0800 -t 10.0.0.0/24 --plain | tee scan.log

flags:
`, version)
	flag.PrintDefaults()
	fmt.Fprint(os.Stderr, `
keys (TUI):
  j/k move · enter open · h back · g get · tab details · / filter · q quit

Only use 0800 against systems you own or have written permission to test.
`)
}
