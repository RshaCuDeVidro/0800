package ui

import (
	"github.com/charmbracelet/bubbles/key"
)

// KeyMap holds every binding so the footer and the help overlay cannot drift
// away from the actual behaviour.
type KeyMap struct {
	Up       key.Binding
	Down     key.Binding
	Top      key.Binding
	Bottom   key.Binding
	HalfUp   key.Binding
	HalfDown key.Binding
	Open     key.Binding
	Back     key.Binding
	Get      key.Binding
	Details  key.Binding
	Filter   key.Binding
	Reload   key.Binding
	Help     key.Binding
	Quit     key.Binding
}

var keys = KeyMap{
	Up:       key.NewBinding(key.WithKeys("k", "up"), key.WithHelp("↑/k", "up")),
	Down:     key.NewBinding(key.WithKeys("j", "down"), key.WithHelp("↓/j", "down")),
	Top:      key.NewBinding(key.WithKeys("home"), key.WithHelp("home", "top")),
	Bottom:   key.NewBinding(key.WithKeys("G", "end"), key.WithHelp("G", "bottom")),
	HalfUp:   key.NewBinding(key.WithKeys("ctrl+u", "pgup"), key.WithHelp("^u", "page up")),
	HalfDown: key.NewBinding(key.WithKeys("ctrl+d", "pgdown"), key.WithHelp("^d", "page down")),
	Open:     key.NewBinding(key.WithKeys("enter", "l"), key.WithHelp("↵/l", "open")),
	Back:     key.NewBinding(key.WithKeys("esc", "h"), key.WithHelp("esc/h", "back")),
	Get:      key.NewBinding(key.WithKeys("g"), key.WithHelp("g", "get")),
	Details:  key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "details")),
	Filter:   key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter")),
	Reload:   key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "reload")),
	Help:     key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
	Quit:     key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
}
