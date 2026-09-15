package engine

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Evidence is one rule that fired, with enough context that a block page or
// a log line says exactly why.
type Evidence struct {
	RuleID     int      `json:"rule"`
	Name       string   `json:"name"`
	Category   string   `json:"category"`
	Severity   string   `json:"severity"`
	Score      int      `json:"score"`
	Target     string   `json:"target"`
	Op         string   `json:"op"`
	Match      string   `json:"match"`
	Window     string   `json:"window,omitempty"`
	Transforms string   `json:"transforms,omitempty"`
	Tags       []string `json:"tags,omitempty"`
	Mode       string   `json:"mode,omitempty"`
}

// Verdict is the engine's answer for a request or response.
type Verdict struct {
	Action    Action        `json:"action"`    // what the rules asked for
	Effective Action        `json:"effective"` // after mode: detect turns block into allow
	Score     int           `json:"score"`
	Threshold int           `json:"threshold"`
	Paranoia  int           `json:"paranoia"`
	Mode      string        `json:"mode"`
	TopLabel  string        `json:"top_label,omitempty"`
	Evidence  []Evidence    `json:"evidence,omitempty"`
	BodySkip  string        `json:"body_skipped,omitempty"`
	Phase     Phase         `json:"-"`
	Duration  time.Duration `json:"-"`
	Ruleset   string        `json:"ruleset"`
	Aborted   bool          `json:"-"`
}

// Blocked reports whether the request should be stopped.
func (v *Verdict) Blocked() bool { return v.Effective == ActBlock }

// RuleIDs is the compact list for a log line.
func (v *Verdict) RuleIDs() string {
	if len(v.Evidence) == 0 {
		return ""
	}
	ids := make([]string, 0, len(v.Evidence))
	for _, e := range v.Evidence {
		ids = append(ids, fmt.Sprintf("%d", e.RuleID))
	}
	return strings.Join(ids, ",")
}

// Summary is the one-line human reason.
func (v *Verdict) Summary() string {
	if len(v.Evidence) == 0 {
		return "no match"
	}
	cats := map[string]bool{}
	for _, e := range v.Evidence {
		cats[e.Category] = true
	}
	list := make([]string, 0, len(cats))
	for c := range cats {
		list = append(list, c)
	}
	sort.Strings(list)
	return fmt.Sprintf("%s (score %d/%d)", strings.Join(list, ", "), v.Score, v.Threshold)
}

func (v *Verdict) sortEvidence() {
	sort.SliceStable(v.Evidence, func(a, b int) bool {
		if v.Evidence[a].Target != v.Evidence[b].Target {
			return v.Evidence[a].Target < v.Evidence[b].Target
		}
		return v.Evidence[a].RuleID < v.Evidence[b].RuleID
	})
}
