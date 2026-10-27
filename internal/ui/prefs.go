package ui

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// prefs is the small amount of state remembered between runs.
type prefs struct {
	Target     string `json:"target,omitempty"`
	Profile    string `json:"profile,omitempty"`
	Ports      []int  `json:"ports,omitempty"`
	Workers    int    `json:"workers,omitempty"`
	Rate       int    `json:"rate,omitempty"`
	EnumShares bool   `json:"enumShares,omitempty"`
}

// prefsDirOverride lets tests keep the user's config untouched.
var prefsDirOverride string

func prefsPath() string {
	if prefsDirOverride != "" {
		return filepath.Join(prefsDirOverride, "config.json")
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "0800", "config.json")
}

func loadPrefs() prefs {
	var p prefs
	path := prefsPath()
	if path == "" {
		return p
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return p
	}
	_ = json.Unmarshal(data, &p)
	return p
}

func savePrefs(p prefs) {
	path := prefsPath()
	if path == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o600)
}
