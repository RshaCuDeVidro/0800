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

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"github.com/rsha/0800/internal/report"
	"github.com/rsha/0800/internal/scan"
	"github.com/rsha/0800/internal/smb"
	"github.com/rsha/0800/internal/target"
	"github.com/rsha/0800/internal/ui"
)

var version = "0.1.0"

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
		timeout     = flag.Duration("timeout", 700*time.Millisecond, "TCP dial timeout")
		ioTimeout   = flag.Duration("io-timeout", 6*time.Second, "per protocol I/O timeout")
		concurrency = flag.Int("c", 512, "parallel TCP workers")
		probes      = flag.Int("probe-workers", 24, "parallel protocol workers")
		rate        = flag.Int("rate", 0, "max dials per second (0 = unlimited)")
		maxHosts    = flag.Int("max-hosts", 65536, "refuse to expand more than this many targets")
		loot        = flag.String("loot", "0800-loot", "directory for downloaded files")
		flat        = flag.Bool("flat", false, "download straight into the loot root")
		jsonPath    = flag.String("json", "", "write a JSON report to this path")
		plain       = flag.Bool("plain", false, "headless output, no TUI")
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

	portList, err := parsePorts(*portsFlag)
	if err != nil {
		return err
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
	fmt.Fprintf(os.Stderr, "  %d target(s) · ports %s · %d workers\n\n",
		len(ips), *portsFlag, *concurrency)

	cfg := scan.Config{
		Targets:      ips,
		Ports:        portList,
		DialTimeout:  *timeout,
		IOTimeout:    *ioTimeout,
		Concurrency:  *concurrency,
		ProbeWorkers: *probes,
		Rate:         *rate,
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

	eng := scan.New(cfg)
	model := ui.New(ui.Config{
		Store:      eng.Store(),
		LootDir:    *loot,
		Flat:       *flat,
		Version:    version,
		SMB:        smbCfg,
		NFSTimeout: *ioTimeout,
	})

	go func() {
		if err := eng.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "0800:", err)
		}
	}()

	p := tea.NewProgram(model, tea.WithAltScreen(), tea.WithContext(ctx))
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

func parsePorts(s string) ([]int, error) {
	var out []int
	seen := map[int]bool{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port %q", p)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no ports to scan")
	}
	return out, nil
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
  0800 -t <target>... [flags]

targets:
  -t, --target     IP, CIDR, hostname, file or @file (repeatable)
      --exclude    CIDR or IP to skip (repeatable)

examples:
  0800 -t 10.0.0.0/24
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
