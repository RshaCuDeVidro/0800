package ui

import (
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/RshaCuDeVidro/0800/internal/preset"
	"github.com/RshaCuDeVidro/0800/internal/target"
)

// Setup is the result of the interactive wizard.
type Setup struct {
	Targets    []string
	TargetSpec string
	Ports      []int
	Workers    int
	Rate       int
	EnumShares bool

	// Set marks values that came from an explicit command line flag and must
	// not be overridden by the saved preferences.
	PortsSet   bool
	WorkersSet bool
	RateSet    bool
	EnumSet    bool
}

type wizardModel struct {
	version string
	w, h    int
	focus   int

	target  textinput.Model
	ports   textinput.Model
	workers textinput.Model
	rate    textinput.Model

	profile int
	enum    bool

	err   string
	done  bool
	quit  bool
	setup *Setup
}

const wizardFields = 6

func newWizard(version string, d Setup) *wizardModel {
	p := loadPrefs()
	if d.TargetSpec == "" {
		d.TargetSpec = p.Target
	}
	if !d.WorkersSet && p.Workers > 0 {
		d.Workers = p.Workers
	}
	if !d.RateSet {
		d.Rate = p.Rate
	}
	if !d.EnumSet {
		d.EnumShares = p.EnumShares
	}

	// Ports: explicit flag > saved ports > saved profile > full preset.
	ports := d.Ports
	if !d.PortsSet {
		switch {
		case len(p.Ports) > 0:
			ports = p.Ports
		case p.Profile != "":
			if i := profileByName(p.Profile); i >= 0 {
				ports = preset.All[i].Ports
			}
		}
	}
	if len(ports) == 0 {
		ports = preset.All[0].Ports
	}

	mk := func(placeholder, value string) textinput.Model {
		t := textinput.New()
		t.Prompt = ""
		t.Placeholder = placeholder
		t.SetValue(value)
		t.CharLimit = 512
		t.Width = 40
		t.PromptStyle = lipgloss.NewStyle().Foreground(colAccent)
		t.TextStyle = lipgloss.NewStyle().Foreground(colText)
		t.Cursor.Style = lipgloss.NewStyle().Foreground(colAccent)
		return t
	}

	m := &wizardModel{version: version, profile: profileIndex(ports)}
	m.target = mk("10.0.0.0/24, 192.0.2.10 or hosts.txt", d.TargetSpec)
	m.ports = mk("445,389,…", csvPorts(ports))
	m.workers = mk("1024", "1024")
	m.rate = mk("0", "0")
	if d.Workers > 0 {
		m.workers.SetValue(strconv.Itoa(d.Workers))
	}
	if d.Rate > 0 {
		m.rate.SetValue(strconv.Itoa(d.Rate))
	}
	m.enum = d.EnumShares
	m.focus = 0
	m.target.Focus()
	return m
}

// RunWizard shows the setup screen and returns the chosen configuration, or nil
// when the user quits.
func RunWizard(version string, defaults Setup) (*Setup, error) {
	m := newWizard(version, defaults)
	p := tea.NewProgram(m, tea.WithAltScreen())
	res, err := p.Run()
	if err != nil {
		return nil, err
	}
	wm, ok := res.(*wizardModel)
	if !ok || wm.quit || !wm.done {
		return nil, nil
	}
	return wm.setup, nil
}

func (m *wizardModel) Init() tea.Cmd {
	return tea.Batch(tea.SetWindowTitle("0800 · setup"), textinput.Blink)
}

func (m *wizardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.w, m.h = msg.Width, msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "esc", "ctrl+c":
			m.quit = true
			return m, tea.Quit
		case "tab", "down":
			m.setFocus(m.focus + 1)
			return m, nil
		case "shift+tab", "up":
			m.setFocus(m.focus - 1)
			return m, nil
		case "enter":
			m.start()
			if m.done {
				return m, tea.Quit
			}
			return m, nil
		case "left":
			switch m.focus {
			case 1:
				m.setProfile(m.profile - 1)
				return m, nil
			case 5:
				m.enum = !m.enum
				return m, nil
			}
		case "right":
			if m.focus == 1 {
				m.setProfile(m.profile + 1)
				return m, nil
			}
		case " ":
			switch m.focus {
			case 1:
				m.setProfile(m.profile + 1)
				return m, nil
			case 5:
				m.enum = !m.enum
				return m, nil
			}
		}

		var cmd tea.Cmd
		switch m.focus {
		case 0:
			m.target, cmd = m.target.Update(msg)
		case 2:
			m.ports, cmd = m.ports.Update(msg)
		case 3:
			m.workers, cmd = m.workers.Update(msg)
		case 4:
			m.rate, cmd = m.rate.Update(msg)
		}
		return m, cmd
	}
	return m, nil
}

func (m *wizardModel) setFocus(i int) {
	if i < 0 {
		i = wizardFields - 1
	}
	m.focus = i % wizardFields
	m.target.Blur()
	m.ports.Blur()
	m.workers.Blur()
	m.rate.Blur()
	switch m.focus {
	case 0:
		m.target.Focus()
	case 2:
		m.ports.Focus()
	case 3:
		m.workers.Focus()
	case 4:
		m.rate.Focus()
	}
}

func (m *wizardModel) setProfile(i int) {
	n := len(preset.All)
	m.profile = ((i % n) + n) % n
	m.ports.SetValue(preset.All[m.profile].Format())
}

func (m *wizardModel) start() {
	spec := strings.TrimSpace(m.target.Value())
	if spec == "" {
		m.err = "give me at least one target (ip, cidr or file)"
		return
	}
	ips, err := target.Parse([]string{spec}, target.Options{Max: 65536, Resolve: true})
	if err != nil {
		m.err = err.Error()
		return
	}
	ports, err := preset.ParsePorts(m.ports.Value())
	if err != nil {
		m.err = err.Error()
		return
	}
	workers, err := strconv.Atoi(strings.TrimSpace(m.workers.Value()))
	if err != nil || workers < 1 || workers > 8192 {
		m.err = "workers must be between 1 and 8192"
		return
	}
	rate, err := strconv.Atoi(strings.TrimSpace(m.rate.Value()))
	if err != nil || rate < 0 {
		m.err = "rate must be 0 (unlimited) or a positive number"
		return
	}
	m.err = ""
	m.setup = &Setup{
		Targets: ips, TargetSpec: spec, Ports: ports,
		Workers: workers, Rate: rate, EnumShares: m.enum,
	}
	savePrefs(prefs{
		Target: spec, Profile: preset.All[m.profile].Name, Ports: ports,
		Workers: workers, Rate: rate, EnumShares: m.enum,
	})
	m.done = true
}

func (m *wizardModel) View() string {
	if m.w == 0 || m.h == 0 {
		m.w, m.h = 96, 30
	}

	w := min(84, m.w-4)
	if w < 54 {
		w = max(40, m.w-2)
	}
	m.target.Width = max(18, w-40)
	m.ports.Width = max(18, w-26)

	label := func(i int, name string) string {
		if m.focus == i {
			return styleAccent.Bold(true).Render(pad(name, 10)) + styleAccent.Render("▸ ")
		}
		return styleDim.Render(pad(name, 10)) + "  "
	}
	value := func(i int, in textinput.Model) string {
		if m.focus == i {
			return in.View()
		}
		v := in.Value()
		if v == "" {
			return styleFaint.Render(in.Placeholder)
		}
		return styleText.Render(v)
	}
	hint := func(text string) string { return styleFaint.Render("  " + text) }

	p := preset.All[m.profile]
	profileLine := styleText.Render("‹ " + p.Name + " ›")
	if m.focus != 1 {
		profileLine = styleDim.Render("‹ ") + styleText.Render(p.Name) + styleDim.Render(" ›")
	}

	enumBox := styleDim.Render("[ ]")
	if m.enum {
		enumBox = styleAccent.Render("[x]")
	}

	targetLine := label(0, "target") + value(0, m.target)
	if est := estimateHosts(m.target.Value()); est != "" {
		targetLine = spread(targetLine, styleFaint.Render(est), w-6)
	}

	lines := []string{
		"",
		styleAccent.Bold(true).Render("0800") + styleSubtitle.Render("  null-auth recon"),
		styleFaint.Render("interactive setup · " + versionTag(m.version)),
		"",
		targetLine,
		hint("ip, cidr, hostname, file or @file"),
		"",
		label(1, "profile") + profileLine + styleDim.Render("   "+p.Desc),
		"",
		label(2, "ports") + value(2, m.ports),
		"",
		label(3, "workers") + value(3, m.workers) + styleFaint.Render("   parallel tcp workers"),
		label(4, "rate") + value(4, m.rate) + styleFaint.Render("   dials per second, 0 = unlimited"),
		label(5, "shares") + enumBox + styleFaint.Render("   enumerate shares during the scan"),
		"",
	}
	if m.err != "" {
		lines = append(lines, styleErr.Render("  ! "+m.err))
	} else {
		lines = append(lines, styleFaint.Render("  read-only probes · at most two auth attempts per host"))
	}
	lines = append(lines, "")
	lines = append(lines, spread(
		styleKey.Render("tab")+" "+styleKeyDesc.Render("next")+
			"   "+styleKey.Render("←/→")+" "+styleKeyDesc.Render("profile")+
			"   "+styleKey.Render("enter")+" "+styleKeyDesc.Render("start")+
			"   "+styleKey.Render("esc")+" "+styleKeyDesc.Render("quit"),
		styleFaint.Render("remembered in ~/.config/0800"),
		w-6))

	box := panel("setup", "read-only recon", strings.Join(lines, "\n"), w, len(lines)+4, true)
	return lipgloss.Place(max(m.w, w), max(m.h, len(lines)+6), lipgloss.Center, lipgloss.Center, box)
}

func csvPorts(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, strconv.Itoa(p))
	}
	return strings.Join(parts, ",")
}

func profileIndex(ports []int) int {
	for i, p := range preset.All {
		if len(p.Ports) == len(ports) {
			same := true
			for j := range ports {
				if p.Ports[j] != ports[j] {
					same = false
					break
				}
			}
			if same {
				return i
			}
		}
	}
	return 0
}

func profileByName(name string) int {
	for i, p := range preset.All {
		if strings.EqualFold(p.Name, name) {
			return i
		}
	}
	return -1
}

// estimateHosts gives a cheap, non-blocking size hint for the target field.
func estimateHosts(spec string) string {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return ""
	}
	if _, n, err := net.ParseCIDR(spec); err == nil {
		ones, bits := n.Mask.Size()
		count := 1 << (bits - ones)
		if bits == 32 && count > 65536 {
			return "too large"
		}
		return "≈ " + itoa(count) + " hosts"
	}
	if net.ParseIP(spec) != nil {
		return "1 host"
	}
	if st, err := os.Stat(spec); err == nil && !st.IsDir() {
		return "file"
	}
	return ""
}

func itoa(n int) string { return strconv.Itoa(n) }

// NewWizardPreview builds a wizard for screenshots and docs.
func NewWizardPreview(w, h int) tea.Model {
	m := newWizard("0.4.3", Setup{TargetSpec: "10.10.0.0/24", Workers: 1024, WorkersSet: true})
	m.w, m.h = w, h
	m.target.SetValue("10.10.0.0/24")
	m.setFocus(0)
	return m
}
