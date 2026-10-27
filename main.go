// Command 0800 is a fast terminal recon tool for services that answer without
// credentials: SMB null/guest sessions, anonymous LDAP, open NFS exports and
// passwordless databases.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
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

var version = "0.4.3"

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "0800:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		targets     stringList
		exclude     stringList
		portsFlag   = flag.String("p", "445,88,389,2049,3306,5432,6379", "comma separated ports to test")
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
		plain       = flag.Bool("plain", false, "headless output, no TUI")
		profile     = flag.String("profile", "", "port preset: full, quick, ad, smb, db")
		enumShares  = flag.Bool("enum-shares", true, "enumerate shares during the scan (short list)")
		menu        = flag.Bool("menu", false, "always show the interactive setup screen")
		noMenu      = flag.Bool("no-menu", false, "skip the interactive setup screen")
		noColor     = flag.Bool("no-color", false, "disable ANSI colours")
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
	showMenu := *menu || (interactive && !*noMenu && !*plain)
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

	ips, err := target.Parse(targets, target.Options{
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
		ServicePorts: servicePorts,
		EnumShares:   *enumShares,
	}

	if *plain {
		cfg.OnFinish = func(h *scan.HostView) {
			fmt.Printf("%s %s\n", severityPrefix(h), report.PlainLine(h))
		}
		eng := scan.New(cfg)
		if err := eng.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		snap := eng.Store().Snapshot()
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "  "+report.Summary(snap))
		if *jsonPath != "" {
			if err := report.WriteJSON(*jsonPath, report.Build(snap, version)); err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "  report: "+*jsonPath)
		}
		return nil
	}

	scanCtx, cancelScan := context.WithCancel(ctx)
	defer cancelScan()

	eng := scan.New(cfg)
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

	p := tea.NewProgram(model, tea.WithAltScreen())
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
		if *jsonPath != "" {
			if err := report.WriteJSON(*jsonPath, report.Build(st.Snapshot(), version)); err != nil {
				return err
			}
		}
	}
	return nil
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
		"mysql": true, "postgres": true, "redis": true,
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
