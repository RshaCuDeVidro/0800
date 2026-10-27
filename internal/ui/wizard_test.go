package ui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestWizardDefaults(t *testing.T) {
	m := newWizard("test", Setup{Workers: 2048})
	if m.workers.Value() != "2048" {
		t.Errorf("workers = %q", m.workers.Value())
	}
	if !strings.Contains(m.ports.Value(), "445") {
		t.Errorf("ports = %q", m.ports.Value())
	}
	if m.focus != 0 {
		t.Errorf("focus = %d", m.focus)
	}
}

func TestWizardStart(t *testing.T) {
	m := newWizard("test", Setup{})
	m.target.SetValue("192.0.2.0/30")
	m.start()
	if m.err != "" {
		t.Fatalf("err = %q", m.err)
	}
	if m.setup == nil || len(m.setup.Targets) != 4 {
		t.Fatalf("setup = %+v", m.setup)
	}
	if len(m.setup.Ports) != 7 || m.setup.Workers != 1024 {
		t.Errorf("setup = %+v", m.setup)
	}
	if m.setup.Targets[0] != "192.0.2.0" || m.setup.Targets[3] != "192.0.2.3" {
		t.Errorf("targets = %v", m.setup.Targets)
	}
}

func TestWizardRejectsBadInput(t *testing.T) {
	m := newWizard("test", Setup{})
	m.target.SetValue("")
	m.start()
	if m.err == "" || m.done {
		t.Fatal("empty target should fail")
	}

	m.target.SetValue("192.0.2.1")
	m.ports.SetValue("99999")
	m.start()
	if m.err == "" || m.done {
		t.Fatal("invalid port should fail")
	}

	m.ports.SetValue("445")
	m.workers.SetValue("0")
	m.start()
	if m.err == "" || m.done {
		t.Fatal("invalid workers should fail")
	}
}

func TestWizardProfileCycling(t *testing.T) {
	m := newWizard("test", Setup{})
	m.setProfile(1) // quick
	if !strings.Contains(m.ports.Value(), "389") || strings.Contains(m.ports.Value(), "3306") {
		t.Errorf("quick ports = %q", m.ports.Value())
	}
	m.setProfile(0)
	if !strings.Contains(m.ports.Value(), "3306") {
		t.Errorf("full ports = %q", m.ports.Value())
	}
}

func TestWizardKeys(t *testing.T) {
	m := newWizard("test", Setup{})
	m.Update(tea.KeyMsg{Type: tea.KeyTab})
	if m.focus != 1 {
		t.Fatalf("focus = %d", m.focus)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyRight})
	if m.profile != 1 {
		t.Errorf("profile = %d", m.profile)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{' '}})
	// space on the profile field cycles too
	if m.profile != 2 {
		t.Errorf("profile after space = %d", m.profile)
	}
	m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if !m.quit {
		t.Error("esc should quit")
	}
}

func TestWizardView(t *testing.T) {
	m := NewWizardPreview(100, 30)
	out := m.View()
	for _, want := range []string{"setup", "target", "profile", "workers", "enter", "10.10.0.0/24"} {
		if !strings.Contains(out, want) {
			t.Errorf("view missing %q", want)
		}
	}
}
