package report

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/RshaCuDeVidro/0800/internal/scan"
)

// LoadDocument reads a JSON report written by WriteJSON.
func LoadDocument(path string) (Document, error) {
	var doc Document
	data, err := os.ReadFile(path)
	if err != nil {
		return doc, err
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return doc, fmt.Errorf("%s is not a 0800 report: %w", path, err)
	}
	if doc.Tool != "0800" {
		return doc, fmt.Errorf("%s is not a 0800 report (tool %q)", path, doc.Tool)
	}
	return doc, nil
}

// Resume is what --resume continues from.
type Resume struct {
	// Targets are the hosts that still have to be scanned.
	Targets []string
	// Done are the finished hosts with results, to be restored into the store.
	Done []*scan.HostView
	// Finished counts hosts the previous run completed (with or without
	// results); it is only used to tell the operator where they are.
	Finished int
}

// LoadResume reads a partial report and works out what is left to do. It
// refuses a report that already covers every target.
func LoadResume(path string) (Resume, error) {
	doc, err := LoadDocument(path)
	if err != nil {
		return Resume{}, err
	}
	if !doc.Partial || len(doc.Pending) == 0 {
		return Resume{}, fmt.Errorf("%s is a complete report: there is nothing to resume", path)
	}

	pending := make(map[string]bool, len(doc.Pending))
	for _, ip := range doc.Pending {
		pending[ip] = true
	}
	r := Resume{Targets: append([]string(nil), doc.Pending...)}
	for _, h := range doc.Hosts {
		if pending[h.IP] {
			continue // probed again, so its partial results are dropped
		}
		r.Done = append(r.Done, h)
	}
	r.Finished = doc.Stats.Scanned
	return r, nil
}
